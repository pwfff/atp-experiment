//! Sender: TLS handshake for keys/identity, then spray sealed RaptorQ
//! symbols over kernel UDP, generating repair for unacked blocks until the
//! receiver says Done.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use raptorq::Encoder;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

use crate::blocks::Layout;
use crate::datagram::TxPlane;
use crate::error::{Error, Result};
use crate::rate::{self, Pacer, RateController};
use crate::sealed::SymbolSealer;
use crate::tls;
use crate::udp::{self, UdpFlowAcceptor, UdpTx};
use crate::wire::{self, Frame};

#[derive(Debug, clap::Args)]
pub struct SendArgs {
    /// File to send.
    pub file: PathBuf,
    /// Receiver control address, host:port (push mode: the sender dials the
    /// receiver). Omit and pass --listen for pull mode.
    #[arg(required_unless_present = "listen", conflicts_with = "listen")]
    pub dest: Option<String>,
    /// Pull mode (client-initiated download): listen on this control
    /// address for the receiver to connect and open the data flow, then
    /// stream the file back — the browser/download model. The receiver
    /// initiates, so it works even when the receiver is behind NAT and the
    /// sender is publicly reachable. Data still flows sender→receiver.
    #[arg(long)]
    pub listen: Option<String>,
    /// Pull-mode UDP data port the receiver opens the flow toward (must be
    /// reachable from the receiver). 0 = ephemeral.
    #[arg(long, default_value_t = 9441)]
    pub udp_port: u16,
    /// Fixed pacing rate for the UDP spray, in Mbit/s (0 = unpaced).
    /// Default: adaptive rate control from receiver feedback.
    #[arg(long)]
    pub rate_mbps: Option<f64>,
    /// Adaptive pacing ceiling, in Mbit/s.
    #[arg(long, default_value_t = 5000.0)]
    pub max_rate_mbps: f64,
    /// Initial repair overhead, percent of source symbols per block.
    #[arg(long, default_value_t = 5.0)]
    pub overhead: f64,
    /// RaptorQ symbol size in bytes.
    #[arg(long, default_value_t = 1200)]
    pub symbol_size: u16,
    /// Block size in bytes (each block is an independent RaptorQ object).
    #[arg(long, default_value_t = 1 << 20)]
    pub block_size: u32,
    /// SHA-256 pin of the receiver's certificate (printed by `atp-experiment recv`).
    #[arg(long, conflicts_with = "nocrypto")]
    pub pin: Option<String>,
    /// Plaintext mode: no TLS, no sealed datagrams (for demo comparison).
    #[arg(long)]
    pub nocrypto: bool,
    /// Testing: simulate this datagram loss fraction on the send path
    /// (0.0–1.0). Exercises repair rounds without netem.
    #[arg(long, default_value_t = 0.0, hide = true)]
    pub test_drop: f64,
}

/// Feedback routed from the TCP reader task to the spray loop.
enum Feedback {
    Decoded(u32),
    /// Receiver's authenticated-datagram count + observed seq span +
    /// receiver-clock timestamp (ms since transfer start).
    Progress {
        pkts: u64,
        span: Option<u64>,
        t_ms: u64,
    },
    Done {
        ok: bool,
        error: Option<String>,
    },
    /// Control connection ended without Done.
    Closed(String),
}

/// How the sender reaches the receiver's UDP symbol plane.
enum Rendezvous {
    /// Push: the sender dialed the receiver; spray to the receiver's
    /// advertised UDP port at the TCP peer IP.
    Push { peer_ip: IpAddr },
    /// Pull (client-initiated download): the sender listened; the receiver
    /// connects and opens the data flow to this pre-bound UDP socket, which
    /// then connects back to the receiver's address.
    Pull { acceptor: UdpFlowAcceptor },
}

/// EWMA loss estimate from receiver Progress reports, over report
/// *intervals* (a lifetime-cumulative ratio would stay polluted by the
/// startup overshoot for the whole transfer and oversize every repair
/// round). Slightly overestimates in plaintext mode while datagrams are
/// in flight; the smoothing keeps that acceptable for sizing repair.
struct LossEstimator {
    ewma: f64,
    primed: bool,
    last: Option<(u64, u64)>,
}

impl LossEstimator {
    fn new() -> Self {
        LossEstimator {
            ewma: 0.0,
            primed: false,
            last: None,
        }
    }

    fn update(&mut self, received: u64, sent: u64) {
        let Some((lr, ls)) = self.last else {
            self.last = Some((received, sent));
            if sent > 0 {
                self.ewma = (1.0 - received as f64 / sent as f64).clamp(0.0, 0.9);
                self.primed = true;
            }
            return;
        };
        let dr = received.saturating_sub(lr);
        let ds = sent.saturating_sub(ls);
        if ds < 50 {
            return; // merge tiny intervals into the next report
        }
        self.last = Some((received, sent));
        let sample = (1.0 - dr as f64 / ds as f64).clamp(0.0, 0.9);
        if self.primed {
            self.ewma = 0.7 * self.ewma + 0.3 * sample;
        } else {
            self.ewma = sample;
            self.primed = true;
        }
    }

    /// Repair fraction for round-0 blocks: CLI overhead or the adaptive
    /// estimate (1.5× measured loss + margin), whichever is larger.
    fn round0_frac(&self, cli_frac: f64) -> f64 {
        let adaptive = if self.primed {
            self.ewma * 1.5 + 0.02
        } else {
            0.0
        };
        cli_frac.max(adaptive).clamp(0.0, 0.8)
    }

    /// Repair fraction per follow-up round.
    fn repair_frac(&self) -> f64 {
        let base = if self.primed { self.ewma * 1.5 } else { 0.0 };
        base.clamp(0.05, 0.8)
    }
}

pub async fn run(args: &SendArgs) -> Result<()> {
    let data = tokio::fs::read(&args.file).await?;
    if data.is_empty() {
        return Err(Error::Transfer("refusing to send an empty file".into()));
    }
    let sha256 = hex::encode(Sha256::digest(&data));
    let layout = Layout::new(data.len() as u64, args.block_size, args.symbol_size);
    let transfer_tag = fresh_tag();
    let file_name = args
        .file
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());

    eprintln!(
        "send: {} ({} bytes, {} blocks of ≤{} B, symbol {} B, sha256 {})",
        file_name,
        layout.file_size,
        layout.num_blocks,
        layout.block_size,
        layout.symbol_size,
        &sha256[..16],
    );

    // --- establish control connection + rendezvous ---------------------
    // The sender is always the TLS client (it pins the receiver's cert),
    // regardless of which side dials TCP.
    let (tcp, rendezvous) = match (&args.dest, &args.listen) {
        (Some(dest), None) => {
            let tcp = TcpStream::connect(dest).await?;
            tcp.set_nodelay(true)?;
            let peer_ip = tcp.peer_addr()?.ip();
            (tcp, Rendezvous::Push { peer_ip })
        }
        (None, Some(listen)) => {
            // Bind the data port up front so an early flow-open is buffered.
            let acceptor = UdpFlowAcceptor::bind(args.udp_port)?;
            let listener = TcpListener::bind(listen).await?;
            eprintln!(
                "send: pull mode — control listening on {}, data udp :{}",
                listener.local_addr()?,
                acceptor.port()
            );
            let (tcp, peer) = listener.accept().await?;
            tcp.set_nodelay(true)?;
            eprintln!("send: receiver connected from {peer}");
            (tcp, Rendezvous::Pull { acceptor })
        }
        _ => {
            return Err(Error::Transfer(
                "pass exactly one of <dest> (push) or --listen (pull)".into(),
            ))
        }
    };

    if args.nocrypto {
        eprintln!("send: PLAINTEXT mode (--nocrypto)");
        return transfer(
            tcp,
            TxPlane::Plain,
            rendezvous,
            args,
            &data,
            &sha256,
            layout,
            transfer_tag,
            file_name,
        )
        .await;
    }

    let pin_str = args.pin.as_deref().ok_or_else(|| {
        Error::Transfer(
            "--pin <sha256> required (copy it from `atp-experiment recv` output), or --nocrypto"
                .into(),
        )
    })?;
    let pin = tls::parse_pin(pin_str)?;
    let connector = TlsConnector::from(tls::client_config(pin));
    let sni = ServerName::try_from(tls::SNI).expect("static SNI is valid");
    let stream = connector.connect(sni, tcp).await.map_err(|e| {
        Error::Transfer(format!(
            "TLS handshake failed (wrong --pin, or receiver not atp-experiment?): {e}"
        ))
    })?;

    // Both sides derive the symbol-plane key from the TLS session; no key
    // material travels on the wire.
    let (_, conn) = stream.get_ref();
    let key = tls::export_symbol_key(conn)?;
    eprintln!("send: sealed session established (TLS 1.3, cert pinned, exporter key derived)");

    transfer(
        stream,
        TxPlane::Sealed(SymbolSealer::new(&key)),
        rendezvous,
        args,
        &data,
        &sha256,
        layout,
        transfer_tag,
        file_name,
    )
    .await
}

/// Drive one transfer over an established control stream (plain TCP or TLS).
#[allow(clippy::too_many_arguments)]
async fn transfer<S>(
    mut control: S,
    plane: TxPlane,
    rendezvous: Rendezvous,
    args: &SendArgs,
    data: &[u8],
    sha256: &str,
    layout: Layout,
    transfer_tag: u64,
    file_name: String,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // --- control handshake ---------------------------------------------
    let data_port = match &rendezvous {
        Rendezvous::Push { .. } => None,
        Rendezvous::Pull { acceptor } => Some(acceptor.port()),
    };
    wire::write_frame(
        &mut control,
        &Frame::Hello {
            version: wire::VERSION,
            transfer_tag,
            data_port,
        },
    )
    .await?;
    let recv_udp_port = match wire::read_frame(&mut control).await? {
        Frame::HelloAck { udp_port } => udp_port,
        f => return Err(Error::protocol(format!("expected HelloAck, got {f:?}"))),
    };
    wire::write_frame(
        &mut control,
        &Frame::Manifest {
            file_name,
            file_size: layout.file_size,
            sha256: sha256.to_string(),
            block_size: layout.block_size,
            symbol_size: layout.symbol_size,
            num_blocks: layout.num_blocks,
        },
    )
    .await?;
    match wire::read_frame(&mut control).await? {
        Frame::ManifestAck => {}
        f => return Err(Error::protocol(format!("expected ManifestAck, got {f:?}"))),
    }

    // --- feedback reader task -------------------------------------------
    let (mut ctl_rd, _ctl_wr) = tokio::io::split(control);
    let (fb_tx, mut fb_rx) = mpsc::unbounded_channel::<Feedback>();
    tokio::spawn(async move {
        loop {
            match wire::read_frame(&mut ctl_rd).await {
                Ok(Frame::BlockDecoded { index }) => {
                    let _ = fb_tx.send(Feedback::Decoded(index));
                }
                Ok(Frame::Progress { pkts, span, t_ms }) => {
                    let _ = fb_tx.send(Feedback::Progress { pkts, span, t_ms });
                }
                Ok(Frame::Done { ok, error }) => {
                    let _ = fb_tx.send(Feedback::Done { ok, error });
                    return;
                }
                Ok(f) => {
                    let _ = fb_tx.send(Feedback::Closed(format!("unexpected frame {f:?}")));
                    return;
                }
                Err(e) => {
                    let _ = fb_tx.send(Feedback::Closed(e.to_string()));
                    return;
                }
            }
        }
    });

    // --- symbol plane -----------------------------------------------------
    let tx = match rendezvous {
        Rendezvous::Push { peer_ip } => {
            let port = recv_udp_port
                .ok_or_else(|| Error::protocol("push mode: receiver advertised no UDP port"))?;
            UdpTx::connect(SocketAddr::new(peer_ip, port))?
        }
        Rendezvous::Pull { acceptor } => {
            eprintln!(
                "send: awaiting receiver data-flow open on :{}",
                acceptor.port()
            );
            let tx =
                tokio::time::timeout(Duration::from_secs(30), acceptor.accept_flow(transfer_tag))
                    .await
                    .map_err(|_| {
                        Error::Transfer(
                    "timed out waiting for receiver to open the data flow (NAT/firewall blocking?)"
                        .into(),
                )
                    })??;
            eprintln!("send: data flow open; spraying to receiver");
            tx
        }
    };

    // GSO super-buffer geometry: every datagram in a batch has identical
    // wire size (RaptorQ symbols are fixed-size), so one segment size fits.
    let payload_len = 4 + layout.symbol_size as usize; // PayloadId + symbol
    let seg = plane.wire_len(payload_len);
    let max_segs = (udp::MAX_GSO_BYTES / seg).clamp(1, udp::MAX_GSO_SEGMENTS);
    let mut batch: Vec<u8> = Vec::with_capacity(seg * max_segs);
    let mut batch_segs = 0usize;
    let mut payload_buf: Vec<u8> = Vec::with_capacity(payload_len);
    let (mut pacer, mut ctrl) = match args.rate_mbps {
        Some(mbps) => (Pacer::new_mbps(mbps), None),
        None => (
            Pacer::new_bps(rate::START_RATE_BPS),
            Some(RateController::new(seg, args.max_rate_mbps)),
        ),
    };
    eprintln!(
        "send: udp spray: {seg} B datagrams × {max_segs}/batch, gso {}, pacing {}",
        if tx.gso() {
            "on"
        } else {
            "off (sendmmsg fallback)"
        },
        match args.rate_mbps {
            Some(r) if r > 0.0 => format!("static {r} Mbit/s"),
            Some(_) => "off (unpaced)".into(),
            None => format!(
                "adaptive (start {:.0}, cap {:.0} Mbit/s)",
                rate::START_RATE_BPS * 8.0 / 1e6,
                args.max_rate_mbps
            ),
        }
    );

    let mut loss = LossEstimator::new();
    let mut receiver_gone = false;
    // xorshift state for --test-drop.
    let mut drop_rng: u64 = transfer_tag | 1;
    let mut acked = vec![false; layout.num_blocks as usize];
    let mut acked_count: u32 = 0;
    // Next repair symbol id per block, so successive rounds emit fresh symbols.
    let mut next_repair = vec![0u32; layout.num_blocks as usize];
    let mut packets_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let done: (bool, Option<String>);
    let start = Instant::now();

    // Small LRU of live encoders: building one costs the RaptorQ
    // intermediate-symbol solve, so keep the ones we're still repairing.
    let mut encoders: VecDeque<(u32, Encoder)> = VecDeque::new();
    const ENCODER_CACHE: usize = 8;

    // Round 0: source symbols + initial overhead for every block.
    // Later rounds: extra repair symbols for whatever is still unacked.
    let mut round: u32 = 0;
    'transfer: loop {
        if let Some(d) = drain_feedback(
            &mut fb_rx,
            &mut acked,
            &mut acked_count,
            &mut loss,
            &mut ctrl,
            &mut pacer,
            packets_sent,
            bytes_sent,
        )? {
            done = d;
            break 'transfer;
        }

        let pending: Vec<u32> = (0..layout.num_blocks)
            .filter(|&b| !acked[b as usize])
            .collect();
        if pending.is_empty() || receiver_gone {
            // Everything acked; wait for the receiver's Done (hash verify).
            match tokio::time::timeout(Duration::from_secs(10), fb_rx.recv()).await {
                Ok(Some(Feedback::Done { ok, error })) => {
                    done = (ok, error);
                    break 'transfer;
                }
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => return Err(Error::protocol("receiver never sent Done")),
            }
        }

        for &b in &pending {
            if acked[b as usize] {
                continue; // ack arrived mid-round
            }
            let k = layout.source_symbols(b);
            let encoder = get_encoder(&mut encoders, ENCODER_CACHE, b, &layout, data);
            let block_enc = &encoder.get_block_encoders()[0];

            let mut packets = Vec::new();
            if round == 0 {
                packets.extend(block_enc.source_packets());
                let frac = loss.round0_frac(args.overhead / 100.0);
                let overhead = ((k as f64 * frac).ceil() as u32).max(2);
                packets.extend(block_enc.repair_packets(next_repair[b as usize], overhead));
                next_repair[b as usize] += overhead;
            } else {
                // Loss-driven repair sizing, escalating gently per round.
                let frac = loss.repair_frac() * (1.0 + 0.25 * round.min(4) as f64);
                let extra = ((k as f64 * frac).ceil() as u32).max(8);
                packets.extend(block_enc.repair_packets(next_repair[b as usize], extra));
                next_repair[b as usize] += extra;
            }

            for pkt in packets {
                packets_sent += 1;
                if args.test_drop > 0.0 && xorshift_unit(&mut drop_rng) < args.test_drop {
                    // Simulated network loss: never hits the wire, but must
                    // consume seq space like a real drop would.
                    plane.burn_seq();
                    continue;
                }
                payload_buf.clear();
                payload_buf.extend_from_slice(&pkt.payload_id().serialize());
                payload_buf.extend_from_slice(pkt.data());
                plane.encode_into(transfer_tag, b, &payload_buf, &mut batch)?;
                bytes_sent += seg as u64;
                batch_segs += 1;
                if batch_segs == max_segs {
                    receiver_gone = flush_batch(&tx, &mut batch, seg, &mut pacer).await?;
                    batch_segs = 0;
                    if receiver_gone {
                        break;
                    }
                }
            }
            if !receiver_gone && batch_segs > 0 {
                receiver_gone = flush_batch(&tx, &mut batch, seg, &mut pacer).await?;
                batch_segs = 0;
            }
            if receiver_gone {
                break;
            }

            if let Some(d) = drain_feedback(
                &mut fb_rx,
                &mut acked,
                &mut acked_count,
                &mut loss,
                &mut ctrl,
                &mut pacer,
                packets_sent,
                bytes_sent,
            )? {
                done = d;
                break 'transfer;
            }
        }

        round += 1;
        eprintln!(
            "send: round {round} done, {acked_count}/{} blocks acked, {packets_sent} pkts sent, est loss {:.1}%, pacing {:.0} Mbit/s",
            layout.num_blocks,
            loss.ewma * 100.0,
            pacer.rate_mbps(),
        );

        // Ack-settle: symbols still in flight (and blocks mid-decode) look
        // "unacked" but need no repair. Wait while acks keep arriving; only
        // spend repair once the feedback goes quiet.
        loop {
            let before = acked_count;
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Some(d) = drain_feedback(
                &mut fb_rx,
                &mut acked,
                &mut acked_count,
                &mut loss,
                &mut ctrl,
                &mut pacer,
                packets_sent,
                bytes_sent,
            )? {
                done = d;
                break 'transfer;
            }
            if acked_count == before || acked_count == layout.num_blocks {
                break;
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let (ok, error) = done;
    let goodput = layout.file_size as f64 * 8.0 / 1e6 / elapsed;
    let efficiency = layout.file_size as f64 / bytes_sent.max(1) as f64 * 100.0;
    eprintln!(
        "send: {} in {elapsed:.2}s — {goodput:.1} Mbit/s goodput, \
         {packets_sent} pkts / {bytes_sent} B on the wire ({efficiency:.1}% efficient)",
        if ok { "complete" } else { "FAILED" },
    );
    if ok {
        Ok(())
    } else {
        Err(Error::Transfer(
            error.unwrap_or_else(|| "receiver reported failure".into()),
        ))
    }
}

/// Flush one GSO super-buffer. Returns `true` if the receiver's socket is
/// gone (ECONNREFUSED on connected loopback after it finished) — stop
/// spraying and wait for Done on the control stream.
async fn flush_batch(
    tx: &UdpTx,
    batch: &mut Vec<u8>,
    seg: usize,
    pacer: &mut Pacer,
) -> Result<bool> {
    if batch.is_empty() {
        return Ok(false);
    }
    let len = batch.len();
    let res = tx.send_segments(batch, seg).await;
    batch.clear();
    match res {
        Ok(()) => {
            pacer.pace(len).await;
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// Uniform-ish value in [0, 1) from an xorshift64* state (for --test-drop).
fn xorshift_unit(state: &mut u64) -> f64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    (x.wrapping_mul(0x2545f4914f6cdd1d) >> 11) as f64 / (1u64 << 53) as f64
}

/// Drain pending feedback without blocking; returns `Some` when the
/// receiver reported Done. Progress reports update the loss estimator
/// (repair sizing) and, in adaptive mode, the rate controller → pacer.
#[allow(clippy::too_many_arguments)]
fn drain_feedback(
    rx: &mut mpsc::UnboundedReceiver<Feedback>,
    acked: &mut [bool],
    acked_count: &mut u32,
    loss: &mut LossEstimator,
    ctrl: &mut Option<RateController>,
    pacer: &mut Pacer,
    packets_sent: u64,
    bytes_sent: u64,
) -> Result<Option<(bool, Option<String>)>> {
    loop {
        match rx.try_recv() {
            Ok(Feedback::Decoded(i)) => {
                let i = i as usize;
                if i < acked.len() && !acked[i] {
                    acked[i] = true;
                    *acked_count += 1;
                }
            }
            Ok(Feedback::Progress { pkts, span, t_ms }) => {
                if std::env::var_os("ATP2_DEBUG_LOSS").is_some() {
                    eprintln!(
                        "send: progress pkts={pkts} span={span:?} t_ms={t_ms} sent={packets_sent} pacing={:.0}Mbit",
                        pacer.rate_mbps()
                    );
                }
                // No signal until the receiver has authenticated something:
                // a pkts=0 report says nothing about loss (the spray may
                // simply not have reached it yet) and must not prime the
                // estimator with a bogus 100%-loss sample.
                if pkts > 0 {
                    // Prefer the receiver's seq-span measurement (exact wire
                    // loss); fall back to sent-count comparison (plaintext
                    // mode), which overestimates while datagrams are in
                    // flight.
                    loss.update(pkts, span.unwrap_or(packets_sent));
                    if let Some(c) = ctrl.as_mut() {
                        if let Some(new_bps) = c.on_report(pkts, span, bytes_sent, t_ms) {
                            pacer.set_rate_bps(new_bps);
                        }
                    }
                }
            }
            Ok(Feedback::Done { ok, error }) => return Ok(Some((ok, error))),
            Ok(Feedback::Closed(why)) => {
                return Err(Error::protocol(format!("control connection lost: {why}")))
            }
            Err(mpsc::error::TryRecvError::Empty) => return Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Err(Error::protocol("control connection lost"))
            }
        }
    }
}

/// Fetch or build the encoder for block `b`, keeping a small LRU cache.
fn get_encoder<'a>(
    cache: &'a mut VecDeque<(u32, Encoder)>,
    cap: usize,
    b: u32,
    layout: &Layout,
    data: &[u8],
) -> &'a Encoder {
    if let Some(pos) = cache.iter().position(|(i, _)| *i == b) {
        let entry = cache.remove(pos).unwrap();
        cache.push_front(entry);
    } else {
        let r = layout.range(b);
        let block = &data[r.start as usize..r.end as usize];
        let enc = Encoder::with_defaults(block, layout.symbol_size);
        debug_assert_eq!(enc.get_block_encoders().len(), 1);
        cache.push_front((b, enc));
        cache.truncate(cap);
    }
    &cache.front().unwrap().1
}

/// A cheap unique-per-invocation transfer tag (not a secret; phase 2 binds
/// the real session via TLS).
fn fresh_tag() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    nanos ^ (std::process::id() as u64).rotate_left(32)
}
