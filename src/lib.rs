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

pub mod socket;
pub mod stream;

mod wire;

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
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

use crate::socket::{Faults, Faulty, Socket};
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

/// How many inbound connections may await [`Endpoint::accept`] before a flooding dialer is shed.
/// Bounded so a peer opening connections faster than the application accepts them cannot grow memory
/// without limit; excess `Hello`s are dropped and the dialer, seeing no `HelloAck`, retries or fails.
const ACCEPT_CAPACITY: usize = 128;

/// How many undispatched frames may queue per connection before further arrivals are shed. Stop-and-
/// wait keeps at most one data frame outstanding, so a small window suffices for the honest path; a
/// flooding peer that overruns it simply looks like a lossy link, and the reliability layer recovers.
const INBOUND_CAPACITY: usize = 256;

/// How many received datagrams may queue for the application before the oldest are shed. Datagrams are
/// unreliable by definition, so dropping under flood is the contract, not a failure.
const DATAGRAM_CAPACITY: usize = 256;

/// How many acks may queue for the send engine before further acks are shed. Acks are cumulative and
/// stop-and-wait needs only the latest, so a dropped ack at most triggers one retransmit.
const ACK_CAPACITY: usize = 64;

/// A peer-address routing table shared between the driver and connecting callers.
///
/// Entries are pruned when the owning [`Connection`] drops (see its `Drop` impl), so a closed
/// connection cannot leave a dead sender behind for a peer reusing the same address to be routed into.
/// Each entry carries a generation so a dropping connection removes only its own route and never a
/// newer one installed for the same address by a peer that redialed before the old drop ran.
type Routes = Arc<Mutex<HashMap<SocketAddr, Route>>>;

/// One entry in the routing table: the inbound-frame sender for a connection, tagged with the
/// generation that installed it.
struct Route {
    generation: u64,
    inbound: mpsc::Sender<Frame>,
}

/// Remove `peer`'s route only if it is still the one installed at `generation`. A newer route for the
/// same address (a peer that redialed before an old connection's drop ran) is left in place.
fn prune_route(routes: &Routes, peer: SocketAddr, generation: u64) {
    let mut routes = routes.lock().expect("routes never poisoned");
    if routes
        .get(&peer)
        .is_some_and(|route| route.generation == generation)
    {
        routes.remove(&peer);
    }
}

/// A quirk endpoint: a bound UDP socket, its identity, and a background demultiplexer.
pub struct Endpoint {
    socket: Arc<Socket>,
    signing: SigningKey,
    routes: Routes,
    generations: Arc<AtomicU64>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<Connection>>,
}

impl Endpoint {
    /// Bind to an ephemeral local UDP port with a fresh identity and start the demultiplexer.
    pub async fn bind() -> Result<Self, Error> {
        Self::bind_socket(Socket::Plain(Self::udp().await?)).await
    }

    /// Bind an endpoint whose socket applies a deterministic [`Faults`] schedule, for tests that must
    /// exercise the reliability layer against a lossy, reordering link rather than lossless loopback.
    pub async fn bind_lossy(faults: Faults) -> Result<Self, Error> {
        Self::bind_socket(Socket::Faulty(Faulty::new(Self::udp().await?, faults))).await
    }

    async fn udp() -> Result<UdpSocket, Error> {
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(Error::Bind)
    }

    async fn bind_socket(socket: Socket) -> Result<Self, Error> {
        let socket = Arc::new(socket);
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let generations = Arc::new(AtomicU64::new(0));
        let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_CAPACITY);

        tokio::spawn(
            Driver {
                socket: Arc::clone(&socket),
                routes: Arc::clone(&routes),
                generations: Arc::clone(&generations),
                accept_tx,
                our_key: signing.verifying_key().to_bytes(),
            }
            .run(),
        );

        Ok(Self {
            socket,
            signing,
            routes,
            generations,
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
        let (tx, mut rx) = mpsc::channel(INBOUND_CAPACITY);
        let generation = self.generations.fetch_add(1, Ordering::Relaxed);
        self.routes.lock().expect("routes never poisoned").insert(
            peer,
            Route {
                generation,
                inbound: tx,
            },
        );

        let hello = Frame::Hello {
            key: self.key_bytes(),
        };
        self.socket
            .send_to(&hello.to_bytes(), peer)
            .await
            .map_err(Error::Io)?;

        // Await the HelloAck, skipping any late frames still draining from a prior connection at this
        // reused address (a stray stale ack must not be mistaken for a failed handshake). The channel
        // closing means the endpoint is gone.
        loop {
            match rx.recv().await {
                Some(Frame::HelloAck { key }) => {
                    return Ok(Connection::new(
                        Arc::clone(&self.socket),
                        Arc::clone(&self.routes),
                        generation,
                        peer,
                        key,
                        rx,
                    ));
                }
                Some(_) => continue,
                None => {
                    // The endpoint shut down before the handshake completed. Prune only our own route
                    // so a concurrent redial's entry is untouched.
                    prune_route(&self.routes, peer, generation);
                    return Err(Error::Handshake);
                }
            }
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
    socket: Arc<Socket>,
    routes: Routes,
    generations: Arc<AtomicU64>,
    accept_tx: mpsc::Sender<Connection>,
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

            // A `Hello` always (re)opens a connection: it signals a peer starting a fresh session, so
            // it must never be routed into an existing (possibly dead) connection for its address.
            let Frame::Hello { key } = frame else {
                self.route_to_existing(from, frame);
                continue;
            };

            // A Hello opens (or replaces) the connection for this address.
            let (tx, rx) = mpsc::channel(INBOUND_CAPACITY);
            let generation = self.generations.fetch_add(1, Ordering::Relaxed);
            self.routes.lock().expect("routes never poisoned").insert(
                from,
                Route {
                    generation,
                    inbound: tx,
                },
            );
            let ack = Frame::HelloAck { key: self.our_key };
            let _ = self.socket.send_to(&ack.to_bytes(), from).await;
            let connection = Connection::new(
                Arc::clone(&self.socket),
                Arc::clone(&self.routes),
                generation,
                from,
                key,
                rx,
            );
            // The accept queue is full or the endpoint is gone: shed this connection. Dropping it
            // prunes its own route, so a later retry from the same address can still succeed.
            let _ = self.accept_tx.try_send(connection);
        }
    }

    /// Deliver a non-`Hello` frame to the live route for `from`, pruning a route whose connection has
    /// been dropped so it cannot keep absorbing (and black-holing) frames.
    fn route_to_existing(&self, from: SocketAddr, frame: Frame) {
        let existing = self
            .routes
            .lock()
            .expect("routes never poisoned")
            .get(&from)
            .map(|route| mpsc::Sender::clone(&route.inbound));
        let Some(inbound) = existing else {
            return;
        };
        match inbound.try_send(frame) {
            // Delivered, or shed under flood: handled for a live route either way.
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
            // The receiver is gone: prune the dead route so it stops absorbing frames.
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.routes
                    .lock()
                    .expect("routes never poisoned")
                    .remove(&from);
            }
        }
    }
}

/// An established quirk connection to one peer: unreliable datagrams and one reliable, full-duplex
/// bidirectional stream. A background dispatcher owns the inbound frames, routing datagrams to
/// [`recv_datagram`](Connection::recv_datagram), stream data to the read half, and acks to the write
/// half. The identity is nominal in phase 0; Noise makes it real in phase 1.
pub struct Connection {
    socket: Arc<Socket>,
    routes: Routes,
    /// The generation that installed this connection's route, so `Drop` prunes only its own entry and
    /// never a newer connection's route for the same reused address.
    generation: u64,
    peer_addr: SocketAddr,
    peer_key: [u8; wire::KEY_LEN],
    datagrams: mpsc::Receiver<Bytes>,
    stream: Mutex<Option<(SendStream, RecvStream)>>,
    /// Turns `true` once the receive engine has delivered every stream byte and seen the peer's FIN,
    /// so [`wait_closed`](Connection::wait_closed) resolves only after inbound data has drained.
    closed: tokio::sync::watch::Receiver<bool>,
    /// Turns `true` once the send engine has delivered every written byte and its FIN has been acked,
    /// so [`wait_closed`](Connection::wait_closed) also waits for our outbound data to reach the peer
    /// before the caller may drop the connection (which would otherwise sever in-flight retransmits).
    drained: tokio::sync::watch::Receiver<bool>,
}

impl Connection {
    fn new(
        socket: Arc<Socket>,
        routes: Routes,
        generation: u64,
        peer_addr: SocketAddr,
        peer_key: [u8; wire::KEY_LEN],
        inbound: mpsc::Receiver<Frame>,
    ) -> Self {
        let (datagram_tx, datagram_rx) = mpsc::channel(DATAGRAM_CAPACITY);
        let (recv_engine, recv_user) = tokio::io::duplex(DUPLEX_BUF);
        let (send_user, send_engine) = tokio::io::duplex(DUPLEX_BUF);
        let (ack_tx, ack_rx) = mpsc::channel(ACK_CAPACITY);
        let (closed_tx, closed_rx) = tokio::sync::watch::channel(false);
        let (drained_tx, drained_rx) = tokio::sync::watch::channel(false);

        tokio::spawn(
            Dispatcher {
                inbound,
                socket: Arc::clone(&socket),
                peer_addr,
                datagram_tx,
                recv: recv_engine,
                ack_tx,
                closed: closed_tx,
            }
            .run(),
        );
        tokio::spawn(
            Sender {
                socket: Arc::clone(&socket),
                peer_addr,
                send: send_engine,
                ack_rx,
                drained: drained_tx,
            }
            .run(),
        );

        Self {
            socket,
            routes,
            generation,
            peer_addr,
            peer_key,
            datagrams: datagram_rx,
            stream: Mutex::new(Some((
                SendStream { inner: send_user },
                RecvStream { inner: recv_user },
            ))),
            closed: closed_rx,
            drained: drained_rx,
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
        self.stream
            .lock()
            .expect("stream mutex never poisoned")
            .take()
            .ok_or(Error::Closed)
    }

    /// The single stream is symmetric, so accepting it is the same as opening it.
    pub fn accept_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        self.open_bi()
    }

    /// Wait until both directions have quiesced: the peer has finished sending (its FIN seen and all
    /// inbound bytes delivered) and our own writes have been delivered and acked. Only then is it safe
    /// to drop the connection, which prunes its route and severs the engines; returning on the inbound
    /// FIN alone would let a caller drop mid-retransmit and truncate outbound data still in flight.
    pub async fn wait_closed(&self) {
        Self::wait_true(self.closed.clone()).await;
        Self::wait_true(self.drained.clone()).await;
    }

    /// Await a watch flag becoming `true`, resolving early if its sender is dropped (the engine exited,
    /// so no further progress is possible and blocking would hang forever).
    async fn wait_true(mut flag: tokio::sync::watch::Receiver<bool>) {
        while !*flag.borrow() {
            if flag.changed().await.is_err() {
                break;
            }
        }
    }
}

impl Drop for Connection {
    /// Prune this connection's peer-address route so a dead connection cannot black-hole a peer that
    /// later dials from the same address, and so the routing table does not grow without bound. Removes
    /// only its own entry (matched by generation), never a newer connection's route for a reused address.
    fn drop(&mut self) {
        prune_route(&self.routes, self.peer_addr, self.generation);
    }
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
    inbound: mpsc::Receiver<Frame>,
    socket: Arc<Socket>,
    peer_addr: SocketAddr,
    datagram_tx: mpsc::Sender<Bytes>,
    recv: DuplexStream,
    ack_tx: mpsc::Sender<u32>,
    closed: tokio::sync::watch::Sender<bool>,
}

impl Dispatcher {
    async fn run(mut self) {
        let mut reassembler = StreamRx::new();
        // The FIN's sequence, once seen. The read half is only shut down once reassembly has caught up
        // to it, so a reordered or retransmitted final data segment arriving after the FIN cannot be
        // delivered as a truncated clean EOF.
        let mut fin_seq: Option<u32> = None;
        // Whether the read half has been closed. The engine keeps running past this to route the peer's
        // acks of our own writes (the reverse direction outlives our read half), so it must not exit
        // when the stream terminates, only stop delivering and re-acking data.
        let mut read_closed = false;
        while let Some(frame) = self.inbound.recv().await {
            match frame {
                Frame::Datagram { data } => {
                    // Unreliable: shed rather than block or grow memory when the application lags.
                    let _ = self.datagram_tx.try_send(data);
                }
                Frame::Data { seq, bytes, .. } if !read_closed => {
                    let delivered = reassembler.accept(seq, bytes);
                    if !delivered.is_empty() {
                        let _ = self.recv.write_all(&delivered).await;
                    }
                    if !self.terminate_if_complete(reassembler.ack(), fin_seq).await {
                        self.send_ack(reassembler.ack()).await;
                    } else {
                        read_closed = true;
                    }
                }
                Frame::Fin { seq, .. } if !read_closed => {
                    fin_seq = Some(seq);
                    if self.terminate_if_complete(reassembler.ack(), fin_seq).await {
                        read_closed = true;
                    } else {
                        // Data is still missing; ack progress so the sender retransmits the gap.
                        self.send_ack(reassembler.ack()).await;
                    }
                }
                // A retransmitted FIN or trailing data after clean EOF: re-ack past the FIN so a peer
                // that lost our terminating ack stops retransmitting, then ignore.
                Frame::Data { .. } | Frame::Fin { .. } => {
                    if let Some(fin_seq) = fin_seq {
                        self.send_ack(fin_seq + 1).await;
                    }
                }
                Frame::Ack { seq, .. } => {
                    let _ = self.ack_tx.try_send(seq);
                }
                _ => {}
            }
        }
    }

    /// If the FIN has been seen and reassembly has reached it, all data is delivered: shut the read
    /// half for a clean EOF, ack past the FIN so the sender stops retransmitting, and signal closed.
    /// Returns whether the stream terminated.
    async fn terminate_if_complete(&mut self, ack: u32, fin_seq: Option<u32>) -> bool {
        let Some(fin_seq) = fin_seq else {
            return false;
        };
        if ack < fin_seq {
            return false;
        }
        let _ = self.recv.shutdown().await;
        // Ack one past the FIN so the sender's stop-and-wait loop sees the terminator acknowledged.
        self.send_ack(fin_seq + 1).await;
        let _ = self.closed.send(true);
        true
    }

    async fn send_ack(&self, seq: u32) {
        let ack = Frame::Ack { stream: 0, seq };
        let _ = self.socket.send_to(&ack.to_bytes(), self.peer_addr).await;
    }
}

/// The connection's send engine: reads the user's writes, chunks them, delivers each reliably with
/// stop-and-wait retransmission, then finishes the stream by delivering a FIN reliably too, so a lost
/// terminator is retransmitted rather than hanging the peer's reader forever.
struct Sender {
    socket: Arc<Socket>,
    peer_addr: SocketAddr,
    send: DuplexStream,
    ack_rx: mpsc::Receiver<u32>,
    /// Set to `true` once every written byte and the FIN have been acked, so
    /// [`Connection::wait_closed`] can guarantee outbound delivery before the connection is dropped.
    drained: tokio::sync::watch::Sender<bool>,
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
            };
            if self.deliver(seq, &frame.to_bytes()).await.is_break() {
                return;
            }
            seq += 1;
        }
        // Every data byte is acked, so all outbound content has reached the peer: wait_closed may now
        // let the connection drop. The FIN below is retransmitted only so a peer reading to EOF sees a
        // clean end; delivery of the payload itself no longer depends on that terminator being acked,
        // and a peer that read a known length has already moved on.
        let _ = self.drained.send(true);
        // The FIN occupies the sequence one past the last data segment and is delivered reliably under
        // the same stop-and-wait loop, so a lossy link cannot lose the stream terminator.
        let fin = Frame::Fin { stream: 0, seq };
        let _ = self.deliver(seq, &fin.to_bytes()).await;
    }

    /// Send one frame occupying sequence `seq` and retransmit it on timeout until the peer's cumulative
    /// ack passes it. Breaks (stops the engine) if the ack channel closes, meaning the dispatcher is
    /// gone and no ack can ever arrive.
    async fn deliver(&mut self, seq: u32, frame: &[u8]) -> core::ops::ControlFlow<()> {
        loop {
            let _ = self.socket.send_to(frame, self.peer_addr).await;
            loop {
                match tokio::time::timeout(RETRANSMIT, self.ack_rx.recv()).await {
                    Ok(Some(ack)) if ack > seq => return core::ops::ControlFlow::Continue(()),
                    Ok(Some(_)) => continue, // stale ack; keep waiting
                    Ok(None) => return core::ops::ControlFlow::Break(()), // dispatcher gone
                    Err(_) => break,         // timed out; retransmit
                }
            }
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
