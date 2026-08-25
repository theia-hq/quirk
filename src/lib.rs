//! quirk: our own QUIC over UDP.
//!
//! A from-scratch, QUIC-shaped transport implemented to learn networking internals rather than wrap
//! an existing stack (it is not built on quinn). quirk is standalone and knows nothing about bifrost;
//! a separate `bifrost-quirk` adapter maps it onto the bifrost transport interface, exactly as
//! `bifrost-iroh` wraps iroh.
//!
//! Identity is an ed25519 public key. Phase 0 (in progress): a plaintext transport over UDP. Done so
//! far: the wire codec, a two-message handshake, a socket demultiplexer (one background task owns the
//! socket and routes frames to per-connection queues, keyed by peer address), unreliable datagrams,
//! and a reliable, full-duplex bidirectional stream exposed as `AsyncRead` / `AsyncWrite`
//! ([`Connection::open_bi`] / [`accept_bi`], stop-and-wait with retransmission). Next: multiple streams
//! per connection, then connection ids (today one connection per peer address). Phase 1 adds a Noise
//! handshake so the identity becomes cryptographically real.
//!
//! [`accept_bi`]: Connection::accept_bi

pub mod stream;

mod wire;

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf,
};
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

/// Buffer size of the in-process duplex bridging a stream's user half and its engine.
const DUPLEX_BUF: usize = 64 * 1024;

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

        tokio::spawn(
            Driver {
                socket: socket.clone(),
                routes: routes.clone(),
                accept_tx,
                our_key: signing.verifying_key().to_bytes(),
            }
            .run(),
        );

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

/// The demultiplexer: reads every datagram, routing it to its connection or accepting a new one.
struct Driver {
    socket: Arc<UdpSocket>,
    routes: Routes,
    accept_tx: mpsc::UnboundedSender<Connection>,
    our_key: [u8; wire::KEY_LEN],
}

impl Driver {
    /// Run the demultiplexer until the socket errors.
    async fn run(self) {
        let mut buf = [0u8; MAX_DATAGRAM];
        loop {
            let (len, from) = match self.socket.recv_from(&mut buf).await {
                Ok(datagram) => datagram,
                Err(_) => break,
            };
            let Ok(frame) = Frame::decode(&buf[..len]) else {
                continue;
            };

            // Route to an existing connection (lock released before any await).
            let existing = self.routes.lock().unwrap().get(&from).cloned();
            if let Some(tx) = existing {
                let _ = tx.send(frame);
                continue;
            }

            // A new peer: only a Hello opens a connection.
            if let Frame::Hello { key } = frame {
                let (tx, rx) = mpsc::unbounded_channel();
                self.routes.lock().unwrap().insert(from, tx);
                let ack = Frame::HelloAck { key: self.our_key };
                let _ = self.socket.send_to(&ack.to_bytes(), from).await;
                let _ = self
                    .accept_tx
                    .send(Connection::new(self.socket.clone(), from, key, rx));
            }
        }
    }
}

/// An established quirk connection to one peer: unreliable datagrams and one reliable, full-duplex
/// bidirectional stream. A background dispatcher owns the inbound frames, routing datagrams to
/// [`recv_datagram`](Connection::recv_datagram), stream data to the read half, and acks to the write
/// half. The identity is nominal in phase 0; Noise makes it real in phase 1.
pub struct Connection {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    peer_key: [u8; wire::KEY_LEN],
    datagrams: mpsc::UnboundedReceiver<Bytes>,
    stream: Mutex<Option<(SendStream, RecvStream)>>,
}

impl Connection {
    fn new(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        peer_key: [u8; wire::KEY_LEN],
        inbound: mpsc::UnboundedReceiver<Frame>,
    ) -> Self {
        let (datagram_tx, datagram_rx) = mpsc::unbounded_channel();
        let (recv_engine, recv_user) = tokio::io::duplex(DUPLEX_BUF);
        let (send_user, send_engine) = tokio::io::duplex(DUPLEX_BUF);
        let (ack_tx, ack_rx) = mpsc::unbounded_channel();

        tokio::spawn(
            Dispatcher {
                inbound,
                socket: socket.clone(),
                peer_addr,
                datagram_tx,
                recv: recv_engine,
                ack_tx,
            }
            .run(),
        );
        tokio::spawn(
            Sender {
                socket: socket.clone(),
                peer_addr,
                send: send_engine,
                ack_rx,
            }
            .run(),
        );

        Self {
            socket,
            peer_addr,
            peer_key,
            datagrams: datagram_rx,
            stream: Mutex::new(Some((
                SendStream { inner: send_user },
                RecvStream { inner: recv_user },
            ))),
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
            data: Bytes::copy_from_slice(data),
        };
        self.socket
            .send_to(&frame.to_bytes(), self.peer_addr)
            .await
            .map_err(Error::Io)?;
        Ok(())
    }

    /// Receive the next datagram from the peer, or `None` once the connection is closed.
    pub async fn recv_datagram(&mut self) -> Option<Bytes> {
        self.datagrams.recv().await
    }

    /// Take the connection's bidirectional stream: a write half and a read half. Available once.
    pub fn open_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        self.stream.lock().unwrap().take().ok_or(Error::Closed)
    }

    /// The single stream is symmetric, so accepting it is the same as opening it.
    pub fn accept_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        self.open_bi()
    }

    /// Wait for the connection to finish. Phase 0: the send/recv engines are detached tasks that drain
    /// buffered data independently and the peer's read gates delivery, so this is currently a no-op.
    pub async fn wait_closed(&self) {}
}

/// The writable half of a quirk stream. Bytes written are chunked and reliably delivered by the
/// connection's send engine; `shutdown` finishes the stream.
pub struct SendStream {
    inner: DuplexStream,
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The readable half of a quirk stream, delivering reassembled bytes until the peer finishes.
pub struct RecvStream {
    inner: DuplexStream,
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

/// The connection's receive engine: routes each inbound frame to the datagram queue, the stream's read
/// half (reassembling and acking), or the send engine (acks of our writes).
struct Dispatcher {
    inbound: mpsc::UnboundedReceiver<Frame>,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    datagram_tx: mpsc::UnboundedSender<Bytes>,
    recv: DuplexStream,
    ack_tx: mpsc::UnboundedSender<u32>,
}

impl Dispatcher {
    async fn run(mut self) {
        let mut reassembler = StreamRx::new();
        while let Some(frame) = self.inbound.recv().await {
            match frame {
                Frame::Datagram { data } => {
                    let _ = self.datagram_tx.send(data);
                }
                Frame::Data { seq, bytes, .. } => {
                    let delivered = reassembler.accept(seq, bytes);
                    if !delivered.is_empty() {
                        let _ = self.recv.write_all(&delivered).await;
                    }
                    self.send_ack(reassembler.ack()).await;
                }
                Frame::Fin { .. } => {
                    self.send_ack(reassembler.ack()).await;
                    let _ = self.recv.shutdown().await;
                }
                Frame::Ack { seq, .. } => {
                    let _ = self.ack_tx.send(seq);
                }
                _ => {}
            }
        }
    }

    async fn send_ack(&self, seq: u32) {
        let ack = Frame::Ack { stream: 0, seq };
        let _ = self.socket.send_to(&ack.to_bytes(), self.peer_addr).await;
    }
}

/// The connection's send engine: reads the user's writes, chunks them, delivers each reliably with
/// stop-and-wait retransmission, then finishes the stream when the user closes the write half.
struct Sender {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    send: DuplexStream,
    ack_rx: mpsc::UnboundedReceiver<u32>,
}

impl Sender {
    async fn run(mut self) {
        let mut seq = 0u32;
        let mut buf = vec![0u8; STREAM_CHUNK];
        loop {
            let read = match self.send.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            let frame = Frame::Data {
                stream: 0,
                seq,
                bytes: Bytes::copy_from_slice(&buf[..read]),
            }
            .to_bytes();
            loop {
                let _ = self.socket.send_to(&frame, self.peer_addr).await;
                let acked = loop {
                    match tokio::time::timeout(RETRANSMIT, self.ack_rx.recv()).await {
                        Ok(Some(ack)) if ack > seq => break true,
                        Ok(Some(_)) => continue, // stale ack; keep waiting
                        Ok(None) => return,      // channel closed; dispatcher gone
                        Err(_) => break false,   // timed out; retransmit
                    }
                };
                if acked {
                    break;
                }
            }
            seq += 1;
        }
        let fin = Frame::Fin { stream: 0 }.to_bytes();
        for _ in 0..3 {
            let _ = self.socket.send_to(&fin, self.peer_addr).await;
        }
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
