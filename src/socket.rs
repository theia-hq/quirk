//! The datagram socket seam.
//!
//! quirk drives its reliability layer over a single UDP socket. Real networks drop datagrams; loopback
//! never does, which is precisely why the reliability layer needs a fault-injecting socket to be tested
//! honestly. [`Socket`] is that seam: a plain [`UdpSocket`] in production, or a fault-injecting wrapper
//! in tests, chosen at bind time and invisible above the socket boundary. It is also where a smarter
//! UDP layer (maggie: reflexive-address discovery, hole-punching, relay upgrade) will one day drop in
//! without touching the reliability engine.

use core::net::SocketAddr;
use std::io;
use std::sync::Mutex;

use tokio::net::UdpSocket;

/// The socket quirk sends and receives datagrams over.
///
/// Every send and receive in the engine flows through this type, so a test can substitute a lossy,
/// reordering link for the lossless loopback the reliability layer would otherwise never be exercised
/// against.
pub enum Socket {
    /// A real UDP socket: no loss, no reordering beyond what the network imposes.
    Plain(UdpSocket),
    /// A UDP socket wrapped in a deterministic fault injector, for tests.
    Faulty(Faulty),
}

impl Socket {
    /// Send `bytes` to `peer`, subject to any injected faults.
    pub async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> io::Result<usize> {
        match self {
            Socket::Plain(socket) => socket.send_to(bytes, peer).await,
            Socket::Faulty(faulty) => faulty.send_to(bytes, peer).await,
        }
    }

    /// Receive the next datagram into `buf`, subject to any injected faults.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Socket::Plain(socket) => socket.recv_from(buf).await,
            Socket::Faulty(faulty) => faulty.recv_from(buf).await,
        }
    }

    /// The local address this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Socket::Plain(socket) => socket.local_addr(),
            Socket::Faulty(faulty) => faulty.inner.local_addr(),
        }
    }
}

impl From<UdpSocket> for Socket {
    fn from(socket: UdpSocket) -> Self {
        Socket::Plain(socket)
    }
}

/// A deterministic fault policy for a test link: which outbound datagrams to drop.
///
/// Determinism is the point. A flaky, probabilistic test proves nothing repeatably; a fixed schedule
/// keyed to the send count lets a test assert "a dropped FIN is recovered" and get the same answer
/// every run. Drops are the one fault stop-and-wait actually exposes end to end: with a single frame
/// in flight the receiver never observes reordering, so only loss (of data, of the FIN, or of an ack)
/// exercises the reliability layer. Reordering becomes observable once a send window lands, and the
/// receiver's in-order reassembly ([`crate::stream::StreamRx`]) is unit-tested against it directly.
#[derive(Debug, Clone, Default)]
pub struct Faults {
    /// 1-based indices of outbound datagrams to drop entirely.
    pub drop_sends: Vec<u64>,
}

impl Faults {
    /// Drop the outbound datagrams at these 1-based send counts.
    pub fn drop_sends(indices: impl IntoIterator<Item = u64>) -> Self {
        Self {
            drop_sends: indices.into_iter().collect(),
        }
    }
}

/// A UDP socket that applies a [`Faults`] schedule to the datagrams crossing it.
pub struct Faulty {
    inner: UdpSocket,
    faults: Faults,
    sends: Mutex<u64>,
}

impl Faulty {
    /// Wrap a bound socket in a fault injector.
    pub fn new(inner: UdpSocket, faults: Faults) -> Self {
        Self {
            inner,
            faults,
            sends: Mutex::new(0),
        }
    }

    async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> io::Result<usize> {
        let count = {
            // The counter lock guards only an infallible increment, so it is never poisoned; the expect
            // is unreachable.
            #[allow(clippy::expect_used)]
            let mut sends = self.sends.lock().expect("send counter never poisoned");
            *sends += 1;
            *sends
        };
        if self.faults.drop_sends.contains(&count) {
            // Report success so the sender proceeds exactly as if the datagram had left the host; the
            // reliability layer must recover it, which is the whole point of the test.
            return Ok(bytes.len());
        }
        self.inner.send_to(bytes, peer).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }
}
