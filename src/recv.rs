//! Receiver: print cert fingerprint, accept one control connection (TLS by
//! default), collect sealed symbols off UDP, decode blocks as enough
//! symbols arrive, ack each block, verify sha256, report.

use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use raptorq::{Decoder, EncodingPacket};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::blocks::Layout;
use crate::datagram::RxPlane;
use crate::error::{Error, Result};
use crate::sealed::SymbolOpener;
use crate::tls;
use crate::udp::UdpRx;
use crate::wire::{self, Frame};

#[derive(Debug, clap::Args)]
pub struct RecvArgs {
    /// Where to write the received file.
    pub output: PathBuf,
    /// TCP control listen address.
    #[arg(long, default_value = "0.0.0.0:9440")]
    pub listen: String,
    /// UDP port for the symbol plane (0 = ephemeral, reported to sender).
    #[arg(long, default_value_t = 0)]
    pub udp_port: u16,
    /// Plaintext mode: no TLS, no sealed datagrams (for demo comparison).
    #[arg(long)]
    pub nocrypto: bool,
}

pub async fn run(args: &RecvArgs) -> Result<()> {
    let listener = TcpListener::bind(&args.listen).await?;
    let addr = listener.local_addr()?;
    eprintln!("recv: control listening on {addr}");
    let identity = if args.nocrypto {
        eprintln!("recv: PLAINTEXT mode (--nocrypto)");
        None
    } else {
        let id = tls::Identity::generate()?;
        eprintln!("recv: cert sha256 fingerprint (give to sender as --pin):");
        eprintln!("recv:   {}", id.fingerprint());
        eprintln!("recv: sender runs: atp-experiment send <file> <this-host>:{} --pin {}", addr.port(), id.fingerprint());
        Some(id)
    };
    serve(listener, identity, args).await
}

/// Accept a single transfer on an already-bound listener (separated from
/// [`run`] so tests can bind port 0 and supply their own identity).
pub async fn serve(
    listener: TcpListener,
    identity: Option<tls::Identity>,
    args: &RecvArgs,
) -> Result<()> {
    let (tcp, peer) = listener.accept().await?;
    eprintln!("recv: control connection from {peer}");
    tcp.set_nodelay(true)?;

    match identity {
        None => handle_transfer(tcp, RxPlane::Plain, args).await,
        Some(id) => {
            let acceptor = TlsAcceptor::from(id.server_config()?);
            let stream = acceptor
                .accept(tcp)
                .await
                .map_err(|e| Error::Transfer(format!("TLS handshake failed: {e}")))?;
            // Same exporter, same label, same key as the sender derives.
            let (_, conn) = stream.get_ref();
            let key = tls::export_symbol_key(conn)?;
            eprintln!("recv: sealed session established (TLS 1.3, exporter key derived)");
            handle_transfer(stream, RxPlane::Sealed(Box::new(SymbolOpener::new(&key))), args).await
        }
    }
}

enum Block {
    Pending(Option<Decoder>),
    Done,
}

async fn handle_transfer<S>(mut tcp: S, plane: RxPlane, args: &RecvArgs) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- handshake --------------------------------------------------------
    let transfer_tag = match wire::read_frame(&mut tcp).await? {
        Frame::Hello { version, transfer_tag } => {
            if version != wire::VERSION {
                let err = format!("version mismatch: peer {version}, ours {}", wire::VERSION);
                let _ = wire::write_frame(
                    &mut tcp,
                    &Frame::Done { ok: false, error: Some(err.clone()) },
                )
                .await;
                return Err(Error::protocol(err));
            }
            transfer_tag
        }
        f => return Err(Error::protocol(format!("expected Hello, got {f:?}"))),
    };

    let mut rx = UdpRx::bind(args.udp_port)?;
    let udp_port = rx.local_port()?;
    wire::write_frame(&mut tcp, &Frame::HelloAck { udp_port }).await?;

    let (file_name, sha256, layout) = match wire::read_frame(&mut tcp).await? {
        Frame::Manifest { file_name, file_size, sha256, block_size, symbol_size, num_blocks } => {
            if file_size == 0 || block_size == 0 || symbol_size == 0 {
                return Err(Error::protocol("degenerate manifest"));
            }
            let layout = Layout::new(file_size, block_size, symbol_size);
            if layout.num_blocks != num_blocks {
                return Err(Error::protocol(format!(
                    "block count mismatch: manifest {num_blocks}, computed {}",
                    layout.num_blocks
                )));
            }
            (file_name, sha256, layout)
        }
        f => return Err(Error::protocol(format!("expected Manifest, got {f:?}"))),
    };
    eprintln!(
        "recv: manifest {file_name}: {} bytes, {} blocks, symbol {} B, udp :{udp_port}, gro {}",
        layout.file_size,
        layout.num_blocks,
        layout.symbol_size,
        if rx.gro() { "on" } else { "off" },
    );

    let file = std::fs::File::create(&args.output)?;
    file.set_len(layout.file_size)?;

    wire::write_frame(&mut tcp, &Frame::ManifestAck).await?;

    // --- symbol collection --------------------------------------------
    let start = Instant::now();
    let mut blocks: Vec<Block> =
        (0..layout.num_blocks).map(|_| Block::Pending(None)).collect();
    let mut decoded: u32 = 0;
    let mut pkts: u64 = 0;
    let mut late_pkts: u64 = 0;
    let mut pending_acks: Vec<u32> = Vec::new();
    let mut io_err: Option<std::io::Error> = None;
    // 100 ms Progress cadence: this is the sender's adaptive rate-control
    // signal, so it needs ~10 Hz resolution. Status prints every 5th tick.
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ticks: u32 = 0;

    while decoded < layout.num_blocks {
        tokio::select! {
            // recvmmsg batch: the closure runs synchronously per datagram
            // (open in place, feed decoder); acks are flushed after the
            // batch so the hot loop never awaits.
            r = rx.recv_batch(|dgram| {
                // Sealed mode: verify + decrypt + replay-check; silent drop
                // on any failure, before touching decoder state.
                let Some((b, payload)) = plane.open(transfer_tag, dgram) else { return };
                if payload.len() < 4 {
                    return;
                }
                pkts += 1;
                if b >= layout.num_blocks {
                    return;
                }
                match &mut blocks[b as usize] {
                    Block::Done => late_pkts += 1,
                    Block::Pending(slot) => {
                        let dec = slot.get_or_insert_with(|| Decoder::new(layout.oti(b)));
                        let packet = EncodingPacket::deserialize(payload);
                        if let Some(data) = dec.decode(packet) {
                            debug_assert_eq!(data.len() as u64, layout.block_len(b));
                            if let Err(e) = file.write_all_at(&data, layout.range(b).start) {
                                io_err = Some(e);
                                return;
                            }
                            blocks[b as usize] = Block::Done;
                            decoded += 1;
                            pending_acks.push(b);
                        }
                    }
                }
            }) => {
                r?;
                if let Some(e) = io_err.take() {
                    return Err(e.into());
                }
                for b in pending_acks.drain(..) {
                    wire::write_frame(&mut tcp, &Frame::BlockDecoded { index: b }).await?;
                }
            }
            _ = ticker.tick() => {
                ticks += 1;
                if ticks.is_multiple_of(5) {
                    eprintln!(
                        "recv: {decoded}/{} blocks, {pkts} pkts ({late_pkts} late)",
                        layout.num_blocks
                    );
                }
                // Loss + delivery feedback for the sender's adaptive repair
                // sizing and rate control: authenticated count + seq span =
                // exact wire loss. Nothing useful to report before the
                // first authenticated datagram.
                if pkts > 0 {
                    wire::write_frame(
                        &mut tcp,
                        &Frame::Progress {
                            pkts,
                            span: plane.seq_span(),
                            t_ms: start.elapsed().as_millis() as u64,
                        },
                    )
                    .await?;
                }
            }
        }
    }
    drop(blocks);
    file.sync_all()?;
    drop(file);

    // --- verify ---------------------------------------------------------
    let actual = sha256_file(&args.output)?;
    let ok = actual == sha256;
    let error = (!ok).then(|| format!("sha256 mismatch: expected {sha256}, got {actual}"));
    wire::write_frame(&mut tcp, &Frame::Done { ok, error: error.clone() }).await?;

    let elapsed = start.elapsed().as_secs_f64();
    eprintln!(
        "recv: {} — {} bytes in {elapsed:.2}s ({:.1} Mbit/s), {pkts} pkts, {late_pkts} late",
        if ok { "complete, sha256 verified" } else { "HASH MISMATCH" },
        layout.file_size,
        layout.file_size as f64 * 8.0 / 1e6 / elapsed,
    );
    match error {
        None => Ok(()),
        Some(e) => Err(Error::Transfer(e)),
    }
}

fn sha256_file(path: &std::path::Path) -> Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
