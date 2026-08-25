//! quirk: our own QUIC over UDP.
//!
//! A from-scratch, QUIC-shaped transport implemented to learn networking internals rather than wrap
//! an existing stack (it is not built on quinn). quirk is standalone and knows nothing about bifrost;
//! a separate `bifrost-quirk` adapter maps it onto the bifrost transport seam, exactly as
//! `bifrost-iroh` wraps iroh.
//!
//! Identity is an ed25519 public key. Phase 0 (current): a plaintext transport over UDP with a
//! packet/frame codec, a connection handshake carrying a nominal (unauthenticated) identity, one
//! bidirectional stream, and reliability. Phase 1 adds a Noise handshake so the identity becomes
//! cryptographically real (static key = public key).

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::net::UdpSocket;

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
}

/// A quirk error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Binding the UDP socket failed.
    #[error("bind udp socket")]
    Bind(#[source] io::Error),
}
