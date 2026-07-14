//! Batched UDP I/O: GSO (`UDP_SEGMENT`) + `sendmmsg` on the way out,
//! GRO (`UDP_GRO`) + `recvmmsg` on the way in, on a nonblocking
//! `socket2::Socket` driven by tokio's `AsyncFd`.
//!
//! This is where "keep the transport in the kernel" becomes literal: one
//! syscall hands the kernel a super-buffer of up to 64 equal-size
//! datagrams and the kernel (or NIC) does segmentation; the receive side
//! gets coalesced super-buffers back. Userspace never runs per-packet
//! transport logic — it only seals/opens AEAD and feeds the decoder.
//!
//! Everything degrades gracefully: no GSO → `sendmmsg` of individual
//! datagrams; no GRO → `recvmmsg` still batches wakeups.
//!
//! The raw-libc cmsg handling (UDP_SEGMENT/UDP_GRO ancillary data) was
//! adapted from the UDP code of Dicklesworthstone/asupersync's atp — see
//! README § Provenance & credit.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::ptr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

/// Kernel limit on segments per GSO super-packet (`UDP_MAX_SEGMENTS`).
pub const MAX_GSO_SEGMENTS: usize = 64;

/// A GSO super-buffer (single sendmsg) must stay under the IP datagram
/// size cap; leave headroom for headers.
pub const MAX_GSO_BYTES: usize = 65000;

/// Messages per `recvmmsg` call.
const RECV_MSGS: usize = 16;

/// Per-message receive buffer: GRO can coalesce up to ~64 KB.
const RECV_BUF_LEN: usize = 1 << 16;

/// Requested socket buffer sizes (clamped by net.core.{r,w}mem_max).
const SND_BUF: usize = 8 << 20;
const RCV_BUF: usize = 16 << 20;

// ─── Sender ──────────────────────────────────────────────────────────────────

/// Connected UDP sender with GSO batching.
pub struct UdpTx {
    fd: AsyncFd<Socket>,
    gso: bool,
}

impl UdpTx {
    pub fn connect(peer: SocketAddr) -> io::Result<Self> {
        let sock = Socket::new(Domain::for_address(peer), Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_nonblocking(true)?;
        let _ = sock.set_send_buffer_size(SND_BUF);
        sock.connect(&peer.into())?;
        let gso = probe_gso(&sock);
        Ok(UdpTx { fd: AsyncFd::new(sock)?, gso })
    }

    /// Whether `UDP_SEGMENT` offload is in use.
    pub fn gso(&self) -> bool {
        self.gso
    }

    /// Send a super-buffer of equal-size datagrams (`seg` bytes each; the
    /// last may be shorter). One `sendmsg` with a `UDP_SEGMENT` cmsg when
    /// GSO is available, `sendmmsg` of individual datagrams otherwise.
    pub async fn send_segments(&self, buf: &[u8], seg: usize) -> io::Result<()> {
        debug_assert!(seg > 0 && buf.len() <= MAX_GSO_BYTES);
        let mut off = 0usize;
        while off < buf.len() {
            let mut guard = self.fd.writable().await?;
            let res = guard.try_io(|afd| {
                let raw = afd.get_ref().as_raw_fd();
                let rest = &buf[off..];
                if self.gso {
                    send_gso(raw, rest, seg as u16)
                } else {
                    send_mmsg_once(raw, rest, seg)
                }
            });
            match res {
                Ok(Ok(sent)) => off += sent,
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }
}

/// Probe `UDP_SEGMENT` support by setting the socket-level default to 0
/// (off); succeeds iff the kernel knows the option.
fn probe_gso(sock: &Socket) -> bool {
    let zero: libc::c_int = 0;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_SEGMENT,
            &zero as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// One `sendmsg` carrying `buf` as a GSO super-packet of `seg`-byte
/// datagrams. Returns bytes accepted (all of `buf` on success).
fn send_gso(fd: libc::c_int, buf: &[u8], seg: u16) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<u16>() as u32) } as usize;
    let mut cmsg_buf = [0u8; 32];
    debug_assert!(cmsg_space <= cmsg_buf.len());

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<u16>() as u32) as usize;
        ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, seg);
    }

    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// One `sendmmsg` of up to [`MAX_GSO_SEGMENTS`] individual datagrams
/// (fallback path). Returns bytes accepted.
fn send_mmsg_once(fd: libc::c_int, buf: &[u8], seg: usize) -> io::Result<usize> {
    let mut iovecs: [libc::iovec; MAX_GSO_SEGMENTS] = unsafe { mem::zeroed() };
    let mut hdrs: [libc::mmsghdr; MAX_GSO_SEGMENTS] = unsafe { mem::zeroed() };
    let mut count = 0usize;
    for chunk in buf.chunks(seg).take(MAX_GSO_SEGMENTS) {
        iovecs[count] = libc::iovec {
            iov_base: chunk.as_ptr() as *mut libc::c_void,
            iov_len: chunk.len(),
        };
        hdrs[count].msg_hdr.msg_iov = &mut iovecs[count];
        hdrs[count].msg_hdr.msg_iovlen = 1;
        count += 1;
    }
    let n = unsafe { libc::sendmmsg(fd, hdrs.as_mut_ptr(), count as libc::c_uint, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = 0usize;
    for h in &hdrs[..n as usize] {
        bytes += h.msg_len as usize;
    }
    Ok(bytes)
}

// ─── Receiver ────────────────────────────────────────────────────────────────

/// Bound UDP receiver with GRO coalescing and `recvmmsg` batching.
pub struct UdpRx {
    fd: AsyncFd<Socket>,
    bufs: Vec<Vec<u8>>,
    gro: bool,
}

impl UdpRx {
    pub fn bind(port: u16) -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_nonblocking(true)?;
        let _ = sock.set_recv_buffer_size(RCV_BUF);
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("static addr");
        sock.bind(&addr.into())?;
        let gro = probe_gro(&sock);
        Ok(UdpRx {
            fd: AsyncFd::new(sock)?,
            bufs: vec![vec![0u8; RECV_BUF_LEN]; RECV_MSGS],
            gro,
        })
    }

    /// Whether `UDP_GRO` coalescing is in use.
    pub fn gro(&self) -> bool {
        self.gro
    }

    pub fn local_port(&self) -> io::Result<u16> {
        let addr = self.fd.get_ref().local_addr()?;
        Ok(addr.as_socket().map(|a| a.port()).unwrap_or(0))
    }

    /// Await one `recvmmsg` batch and invoke `f` for every datagram in it
    /// (mutable slice, so sealed datagrams can be opened in place).
    /// Returns the number of datagrams delivered.
    pub async fn recv_batch(&mut self, mut f: impl FnMut(&mut [u8])) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            let bufs = &mut self.bufs;
            let res = guard.try_io(|afd| {
                let raw = afd.get_ref().as_raw_fd();

                let mut iovecs: [libc::iovec; RECV_MSGS] = unsafe { mem::zeroed() };
                let mut cmsg_bufs = [[0u8; 64]; RECV_MSGS];
                let mut hdrs: [libc::mmsghdr; RECV_MSGS] = unsafe { mem::zeroed() };
                for i in 0..RECV_MSGS {
                    iovecs[i] = libc::iovec {
                        iov_base: bufs[i].as_mut_ptr() as *mut libc::c_void,
                        iov_len: RECV_BUF_LEN,
                    };
                    hdrs[i].msg_hdr.msg_iov = &mut iovecs[i];
                    hdrs[i].msg_hdr.msg_iovlen = 1;
                    hdrs[i].msg_hdr.msg_control = cmsg_bufs[i].as_mut_ptr() as *mut libc::c_void;
                    hdrs[i].msg_hdr.msg_controllen = cmsg_bufs[i].len();
                }

                let n = unsafe {
                    libc::recvmmsg(
                        raw,
                        hdrs.as_mut_ptr(),
                        RECV_MSGS as libc::c_uint,
                        0,
                        ptr::null_mut(),
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }

                let mut datagrams = 0usize;
                for i in 0..n as usize {
                    let len = hdrs[i].msg_len as usize;
                    if len == 0 {
                        continue;
                    }
                    // GRO: the kernel hands us a coalesced buffer plus the
                    // segment size it was built from.
                    let seg = gro_segment_size(&hdrs[i].msg_hdr).unwrap_or(len);
                    for chunk in bufs[i][..len].chunks_mut(seg.max(1)) {
                        f(chunk);
                        datagrams += 1;
                    }
                }
                Ok(datagrams)
            });
            match res {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }
}

fn probe_gro(sock: &Socket) -> bool {
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_GRO,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Extract the `UDP_GRO` segment size cmsg, if present.
fn gro_segment_size(msg: &libc::msghdr) -> Option<usize> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
                let seg = ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int);
                if seg > 0 {
                    return Some(seg as usize);
                }
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GSO send → GRO receive over loopback, verifying segment boundaries.
    #[tokio::test]
    async fn gso_batch_round_trips() {
        let mut rx = UdpRx::bind(0).unwrap();
        let port = rx.local_port().unwrap();
        let tx = UdpTx::connect(format!("127.0.0.1:{port}").parse().unwrap()).unwrap();
        eprintln!("gso={} gro={}", tx.gso(), rx.gro());

        // 20 datagrams of 1000 bytes, each filled with its index.
        const SEG: usize = 1000;
        const COUNT: usize = 20;
        let mut buf = Vec::with_capacity(SEG * COUNT);
        for i in 0..COUNT {
            buf.extend(std::iter::repeat_n(i as u8, SEG));
        }
        tx.send_segments(&buf, SEG).await.unwrap();

        let mut seen = [false; COUNT];
        let mut got = 0usize;
        while got < COUNT {
            got += rx
                .recv_batch(|dgram| {
                    assert_eq!(dgram.len(), SEG);
                    let i = dgram[0] as usize;
                    assert!(dgram.iter().all(|&b| b == dgram[0]), "segment not intact");
                    assert!(!seen[i], "duplicate datagram {i}");
                    seen[i] = true;
                })
                .await
                .unwrap();
        }
        assert!(seen.iter().all(|&s| s));
    }

    /// A short tail (last datagram smaller than seg) survives the batch path.
    #[tokio::test]
    async fn short_tail_datagram() {
        let mut rx = UdpRx::bind(0).unwrap();
        let port = rx.local_port().unwrap();
        let tx = UdpTx::connect(format!("127.0.0.1:{port}").parse().unwrap()).unwrap();

        let mut buf = vec![7u8; 1200 * 3];
        buf.extend_from_slice(&[9u8; 100]);
        tx.send_segments(&buf, 1200).await.unwrap();

        let mut lens = Vec::new();
        while lens.len() < 4 {
            rx.recv_batch(|d| lens.push(d.len())).await.unwrap();
        }
        lens.sort_unstable();
        assert_eq!(lens, vec![100, 1200, 1200, 1200]);
    }
}
