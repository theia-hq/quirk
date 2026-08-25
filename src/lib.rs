//! quirk: our own QUIC over UDP.
//!
//! A from-scratch, QUIC-shaped transport implemented to learn networking internals rather than wrap
//! an existing stack (it is not built on quinn). quirk is standalone and knows nothing about bifrost;
//! a separate `bifrost-quirk` adapter maps it onto the bifrost transport seam, exactly as
//! `bifrost-iroh` wraps iroh.
//!
//! Identity is an ed25519 public key. Phase 0 (in progress): a plaintext transport over UDP. Done so
//! far: the wire codec and a two-message handshake ([`Endpoint::connect`] / [`Endpoint::accept`])
//! that exchanges identities. Next: a socket demultiplexer routing datagrams to per-connection
//! queues, then reliable bidirectional streams. Phase 1 adds a Noise handshake so the identity
//! becomes cryptographically real (static key = public key).

mod wire;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::net::UdpSocket;

use crate::wire::{DecodeError, Frame};

/// The largest datagram quirk will read. Comfortably below common path MTUs.
const MAX_DATAGRAM: usize = 1500;

/// A quirk endpoint: a bound UDP socket and the ed25519 identity it speaks for.
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    signing: SigningKey,
}

impl Endpoint {
    /// Bind to an ephemeral local UDP port with a fresh identity.
    pub async fn bind() -> Result<Self, Error> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(Error::Bind)?;
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        Ok(Self {
            socket: Arc::new(socket),
            signing,
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
    ///
    /// Phase 0 reads the reply directly off the socket, so an endpoint serves one dial or one accept
    /// at a time; the socket demultiplexer that lifts this restriction is the next step.
    pub async fn connect(&self, peer: SocketAddr) -> Result<Connection, Error> {
        let hello = Frame::Hello {
            key: self.key_bytes(),
        };
        self.socket
            .send_to(&hello.to_bytes(), peer)
            .await
            .map_err(Error::Io)?;

        let mut buf = [0u8; MAX_DATAGRAM];
        let (len, _from) = self.socket.recv_from(&mut buf).await.map_err(Error::Io)?;
        match Frame::decode(&buf[..len])? {
            Frame::HelloAck { key } => Ok(Connection::new(peer, key)),
            _ => Err(Error::Handshake),
        }
    }

    /// Accept the next inbound handshake.
    pub async fn accept(&self) -> Result<Connection, Error> {
        let mut buf = [0u8; MAX_DATAGRAM];
        let (len, from) = self.socket.recv_from(&mut buf).await.map_err(Error::Io)?;
        match Frame::decode(&buf[..len])? {
            Frame::Hello { key } => {
                let ack = Frame::HelloAck {
                    key: self.key_bytes(),
                };
                self.socket
                    .send_to(&ack.to_bytes(), from)
                    .await
                    .map_err(Error::Io)?;
                Ok(Connection::new(from, key))
            }
            _ => Err(Error::Handshake),
        }
    }

    fn key_bytes(&self) -> [u8; wire::KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }
}

/// An established quirk connection to one peer.
///
/// Phase 0 carries the peer's identity from the handshake but no streams yet; the reliable stream
/// layer arrives with the socket demultiplexer.
pub struct Connection {
    peer_addr: SocketAddr,
    peer_key: [u8; wire::KEY_LEN],
}

impl Connection {
    fn new(peer_addr: SocketAddr, peer_key: [u8; wire::KEY_LEN]) -> Self {
        Self {
            peer_addr,
            peer_key,
        }
    }

    /// The peer's raw ed25519 public key, as announced in the handshake.
    ///
    /// Nominal and unauthenticated in phase 0: nothing yet proves the peer holds the matching private
    /// key. Phase 1's Noise handshake makes it real.
    pub fn peer_key(&self) -> [u8; wire::KEY_LEN] {
        self.peer_key
    }

    /// The peer's socket address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
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
    /// A datagram could not be decoded.
    #[error("decode frame")]
    Decode(#[from] DecodeError),
    /// The peer sent a frame that does not belong at this point in the handshake.
    #[error("unexpected handshake frame")]
    Handshake,
}
