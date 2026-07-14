//! End-to-end tests: sha256-verified file transfer over loopback, sender
//! and receiver running as tasks in one process — sealed (TLS + AEAD
//! datagrams) and plaintext (--nocrypto) modes, plus pin rejection.

use std::path::PathBuf;

use tokio::net::TcpListener;

use atp_experiment::recv::{self, RecvArgs};
use atp_experiment::send::{self, SendArgs};
use atp_experiment::tls;

/// Deterministic pseudo-random bytes (xorshift64*).
fn test_data(len: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x = seed | 1;
    for chunk in out.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let bytes = x.wrapping_mul(0x2545f4914f6cdd1d).to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("atp-experiment-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TestDir(dir)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn transfer(
    len: usize,
    block_size: u32,
    seed: u64,
    sealed: bool,
    test_drop: f64,
    rate_mbps: Option<f64>,
) {
    let dir = TestDir::new(&format!("{seed}-{sealed}"));
    let src: PathBuf = dir.0.join("src.bin");
    let dst: PathBuf = dir.0.join("dst.bin");
    let data = test_data(len, seed);
    std::fs::write(&src, &data).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (identity, pin) = if sealed {
        let id = tls::Identity::generate().unwrap();
        let pin = id.fingerprint();
        (Some(id), Some(pin))
    } else {
        (None, None)
    };

    let recv_args = RecvArgs {
        output: dst.clone(),
        listen: String::new(),
        udp_port: 0,
        nocrypto: !sealed,
    };
    let recv_task =
        tokio::spawn(async move { recv::serve(listener, identity, &recv_args).await });

    let send_args = SendArgs {
        file: src,
        dest: addr.to_string(),
        rate_mbps,
        max_rate_mbps: 5000.0,
        overhead: 5.0,
        symbol_size: 1200,
        block_size,
        pin,
        nocrypto: !sealed,
        test_drop,
    };
    send::run(&send_args).await.expect("send succeeds");
    recv_task.await.unwrap().expect("recv succeeds");

    let got = std::fs::read(&dst).unwrap();
    assert_eq!(got.len(), data.len());
    assert_eq!(got, data, "received bytes match");
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_multi_block() {
    // 3.5 MiB across 1 MiB blocks: several full blocks + a short tail,
    // through TLS key exchange + AEAD-sealed datagrams.
    transfer(3 * 1024 * 1024 + 512 * 1024, 1 << 20, 0xa1b2, true, 0.0, Some(2000.0)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_tiny_file() {
    transfer(100, 1 << 20, 0xc3d4, true, 0.0, Some(2000.0)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_odd_sizes() {
    transfer(777_777, 256 * 1024, 0xe5f6, true, 0.0, Some(2000.0)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_multi_block() {
    transfer(2 * 1024 * 1024 + 123, 1 << 20, 0x7788, false, 0.0, Some(2000.0)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_survives_ten_percent_loss() {
    // The demo claim: fountain-coded repair absorbs heavy datagram loss
    // (simulated on the send path) with no retransmit protocol.
    transfer(4 * 1024 * 1024, 1 << 20, 0x9dad, true, 0.10, Some(2000.0)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_survives_thirty_percent_loss() {
    transfer(1024 * 1024 + 7, 1 << 20, 0xbeef, true, 0.30, Some(2000.0)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn adaptive_rate_survives_loss() {
    // Default pacing (no --rate-mbps): the adaptive controller must not
    // starve on stochastic loss — excess-loss back-off only.
    transfer(2 * 1024 * 1024, 1 << 20, 0xace0, true, 0.10, None).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_pin_is_rejected() {
    let dir = TestDir::new("wrongpin");
    let src = dir.0.join("src.bin");
    let dst = dir.0.join("dst.bin");
    std::fs::write(&src, test_data(4096, 0x1122)).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_identity = tls::Identity::generate().unwrap();
    // Pin a *different* identity's fingerprint.
    let wrong_pin = tls::Identity::generate().unwrap().fingerprint();
    assert_ne!(wrong_pin, server_identity.fingerprint());

    let recv_args =
        RecvArgs { output: dst.clone(), listen: String::new(), udp_port: 0, nocrypto: false };
    let recv_task =
        tokio::spawn(async move { recv::serve(listener, Some(server_identity), &recv_args).await });

    let send_args = SendArgs {
        file: src,
        dest: addr.to_string(),
        rate_mbps: Some(2000.0),
        max_rate_mbps: 5000.0,
        overhead: 5.0,
        symbol_size: 1200,
        block_size: 1 << 20,
        pin: Some(wrong_pin),
        nocrypto: false,
        test_drop: 0.0,
    };
    let err = send::run(&send_args).await.expect_err("handshake must fail");
    let msg = err.to_string();
    assert!(msg.contains("TLS handshake failed"), "unexpected error: {msg}");

    // Receiver side also errors out (client aborted the handshake).
    assert!(recv_task.await.unwrap().is_err());
    assert!(!dst.exists(), "no output file may be created");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_pin_is_rejected() {
    let send_args = SendArgs {
        file: PathBuf::from("/dev/null"),
        dest: "127.0.0.1:1".into(),
        rate_mbps: Some(1.0),
        max_rate_mbps: 5000.0,
        overhead: 5.0,
        symbol_size: 1200,
        block_size: 1 << 20,
        pin: None,
        nocrypto: false,
        test_drop: 0.0,
    };
    // Fails before any connection: empty file check first, so use a real file.
    let dir = TestDir::new("nopin");
    let src = dir.0.join("src.bin");
    std::fs::write(&src, b"data").unwrap();

    // Sender must refuse to run sealed mode without a pin (no silent
    // trust-anything fallback). Bind a listener so connect succeeds.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let send_args = SendArgs { file: src, dest: addr.to_string(), ..send_args };
    let err = send::run(&send_args).await.expect_err("must refuse without --pin");
    assert!(err.to_string().contains("--pin"), "unexpected error: {err}");
}
