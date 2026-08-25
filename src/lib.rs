//! quirk: our own QUIC over UDP.
//!
//! A from-scratch, QUIC-shaped transport implemented to learn networking internals rather than wrap
//! an existing stack (it is not built on quinn). quirk is standalone and knows nothing about bifrost;
//! a separate `bifrost-quirk` adapter maps it onto the bifrost transport seam, exactly as
//! `bifrost-iroh` wraps iroh.
//!
//! Identity is an ed25519 public key. Phase 0 (in progress): a plaintext transport over UDP. Done so
//! far: the wire codec, a two-message handshake, a socket demultiplexer (one background task owns the
//! socket and routes datagrams to per-connection queues, keyed by peer address), and unreliable
//! datagrams. Next: reliable bidirectional streams; then connection ids (today one connection per
//! peer address). Phase 1 adds a Noise handshake so the identity becomes cryptographically real.

pub mod stream;

mod wire;

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::stream::StreamRx;
use crate::wire::Frame;

/// The largest datagram quirk will read. Comfortably below common path MTUs.
const MAX_DATAGRAM: usize = 1500;

/// The payload size of each reliable-stream data frame.
const STREAM_CHUNK: usize = 1024;

/// How long to wait for an ack before retransmitting a stream frame.
const RETRANSMIT: Duration = Duration::from_millis(200);

/// A peer-address routing table shared between the driver and connecting callers.
type Routes = Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Frame>>>>;

/// A quirk endpoint: a bound UDP socket, its identity, and a background demultiplexer.
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    signing: SigningKey,
    routes: Routes,
    accept_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Connection>>,
}

impl Endpoint {
    /// Bind to an ephemeral local UDP port with a fresh identity and start the demultiplexer.
    pub async fn bind() -> Result<Self, Error> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(Error::Bind)?;
        let socket = Arc::new(socket);
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();

        tokio::spawn(drive(
            socket.clone(),
            routes.clone(),
            accept_tx,
            signing.verifying_key().to_bytes(),
        ));

        Ok(Self {
            socket,
            signing,
            routes,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
        })
    }

    /// This endpoint's public identity: a raw ed25519 verifying key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// The local socket address this endpoint is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Dial a peer and complete the plaintext handshake.
    pub async fn connect(&self, peer: SocketAddr) -> Result<Connection, Error> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.routes.lock().unwrap().insert(peer, tx);

        let hello = Frame::Hello {
            key: self.key_bytes(),
        };
        self.socket
            .send_to(&hello.to_bytes(), peer)
            .await
            .map_err(Error::Io)?;

        match rx.recv().await {
            Some(Frame::HelloAck { key }) => {
                Ok(Connection::new(self.socket.clone(), peer, key, rx))
            }
            _ => Err(Error::Handshake),
        }
    }

    /// Accept the next inbound connection.
    pub async fn accept(&self) -> Result<Connection, Error> {
        self.accept_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(Error::Closed)
    }

    fn key_bytes(&self) -> [u8; wire::KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }
}

/// The demultiplexer: read every datagram, route it to its connection, or accept a new one.
async fn drive(
    socket: Arc<UdpSocket>,
    routes: Routes,
    accept_tx: mpsc::UnboundedSender<Connection>,
    our_key: [u8; wire::KEY_LEN],
) {
    let mut buf = [0u8; MAX_DATAGRAM];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(datagram) => datagram,
            Err(_) => break,
        };
        let Ok(frame) = Frame::decode(&buf[..len]) else {
            continue;
        };

        // Route to an existing connection (lock released before any await).
        let existing = routes.lock().unwrap().get(&from).cloned();
        if let Some(tx) = existing {
            let _ = tx.send(frame);
            continue;
        }

        // A new peer: only a Hello opens a connection.
        if let Frame::Hello { key } = frame {
            let (tx, rx) = mpsc::unbounded_channel();
            routes.lock().unwrap().insert(from, tx);
            let ack = Frame::HelloAck { key: our_key };
            let _ = socket.send_to(&ack.to_bytes(), from).await;
            let _ = accept_tx.send(Connection::new(socket.clone(), from, key, rx));
        }
    }
}

/// An established quirk connection to one peer.
///
/// Carries the peer's identity from the handshake and unreliable datagrams. The identity is nominal
/// and unauthenticated in phase 0; phase 1's Noise handshake makes it real. Reliable streams are the
/// next slice.
pub struct Connection {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    peer_key: [u8; wire::KEY_LEN],
    inbound: mpsc::UnboundedReceiver<Frame>,
}

impl Connection {
    fn new(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        peer_key: [u8; wire::KEY_LEN],
        inbound: mpsc::UnboundedReceiver<Frame>,
    ) -> Self {
        Self {
            socket,
            peer_addr,
            peer_key,
            inbound,
        }
    }

    /// The peer's raw ed25519 public key, as announced in the handshake.
    pub fn peer_key(&self) -> [u8; wire::KEY_LEN] {
        self.peer_key
    }

    /// The peer's socket address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Send an unreliable datagram to the peer.
    pub async fn send_datagram(&self, data: &[u8]) -> Result<(), Error> {
        let frame = Frame::Datagram {
            data: data.to_vec(),
        };
        self.socket
            .send_to(&frame.to_bytes(), self.peer_addr)
            .await
            .map_err(Error::Io)?;
        Ok(())
    }

    /// Receive the next datagram from the peer, or `None` once the connection is closed.
    pub async fn recv_datagram(&mut self) -> Option<Vec<u8>> {
        while let Some(frame) = self.inbound.recv().await {
            if let Frame::Datagram { data } = frame {
                return Some(data);
            }
        }
        None
    }

    /// Reliably send `data` as one ordered stream, then finish. Stop-and-wait with retransmission on
    /// timeout. Phase 0 has one stream per connection; streams and datagrams share the inbound queue,
    /// so a connection does one at a time until the per-stream dispatcher lands.
    pub async fn send_reliable(&mut self, data: &[u8]) -> Result<(), Error> {
        for (seq, chunk) in data.chunks(STREAM_CHUNK).enumerate() {
            self.send_until_acked(seq as u32, chunk).await?;
        }
        // Best-effort finish; a proper close handshake comes with the dispatcher.
        let fin = Frame::Fin { stream: 0 }.to_bytes();
        for _ in 0..3 {
            self.socket
                .send_to(&fin, self.peer_addr)
                .await
                .map_err(Error::Io)?;
        }
        Ok(())
    }

    async fn send_until_acked(&mut self, seq: u32, chunk: &[u8]) -> Result<(), Error> {
        let frame = Frame::Data {
            stream: 0,
            seq,
            bytes: chunk.to_vec(),
        }
        .to_bytes();
        loop {
            self.socket
                .send_to(&frame, self.peer_addr)
                .await
                .map_err(Error::Io)?;
            loop {
                match tokio::time::timeout(RETRANSMIT, self.next_ack()).await {
                    Ok(Some(ack)) if ack > seq => return Ok(()),
                    Ok(Some(_)) => continue, // a stale ack; keep waiting
                    Ok(None) => return Err(Error::Closed),
                    Err(_) => break, // timed out; retransmit
                }
            }
        }
    }

    async fn next_ack(&mut self) -> Option<u32> {
        while let Some(frame) = self.inbound.recv().await {
            if let Frame::Ack { seq, .. } = frame {
                return Some(seq);
            }
        }
        None
    }

    /// Receive a reliable ordered stream until the sender finishes.
    pub async fn recv_reliable(&mut self) -> Result<Vec<u8>, Error> {
        let mut reassembler = StreamRx::new();
        let mut data = Vec::new();
        while let Some(frame) = self.inbound.recv().await {
            match frame {
                Frame::Data { seq, bytes, .. } => {
                    data.extend_from_slice(&reassembler.accept(seq, bytes));
                    self.send_ack(reassembler.ack()).await?;
                }
                Frame::Fin { .. } => {
                    let _ = self.send_ack(reassembler.ack()).await;
                    return Ok(data);
                }
                _ => continue,
            }
        }
        Err(Error::Closed)
    }

    async fn send_ack(&self, seq: u32) -> Result<(), Error> {
        let ack = Frame::Ack { stream: 0, seq }.to_bytes();
        self.socket
            .send_to(&ack, self.peer_addr)
            .await
            .map_err(Error::Io)?;
        Ok(())
    }
}

/// A quirk error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Binding the UDP socket failed.
    #[error("bind udp socket")]
    Bind(#[source] io::Error),
    /// Sending or receiving on the socket failed.
    #[error("socket io")]
    Io(#[source] io::Error),
    /// The peer sent a frame that does not belong at this point in the handshake.
    #[error("unexpected handshake frame")]
    Handshake,
    /// The endpoint has shut down.
    #[error("endpoint closed")]
    Closed,
}
