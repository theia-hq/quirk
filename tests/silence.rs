//! The one answer a spoofable wire may give: none.
//!
//! quirk reads unauthenticated UDP datagrams, so a source address is a CLAIM and nothing more. Every
//! other wire in this family answers a peer whose identity it recognised at a version it does not
//! serve, because silence there sends an operator hunting a broken network instead of a version skew.
//! This wire must not, and the reason is a security property rather than an omission: a reply to an
//! unsolicited datagram is a packet an attacker aims at a third party by writing that party's address
//! into the `from` field, which makes the endpoint a reflection amplifier and an unauthenticated scan
//! responder. Version negotiation, when quirk needs it, comes from the QUIC mechanism that is designed
//! for a forgeable source, not from the stream-preamble convention.
//!
//! This file exists so a later uniformity pass cannot quietly "finish the pattern" here.

use core::net::{Ipv4Addr, SocketAddr};
use core::time::Duration;

use quirk::Endpoint;
use tokio::net::UdpSocket;

/// How long a prober waits to be answered before the silence counts. Loopback delivery is
/// microseconds, so a quarter second is three orders of magnitude of headroom: long enough that a
/// reply cannot be missed by timing, short enough that the suite does not notice.
const LISTEN_FOR: Duration = Duration::from_millis(250);

/// Send one datagram to a live endpoint and report whether anything came back within [`LISTEN_FOR`].
// A test helper, not a `#[test]` fn, so `allow-*-in-tests` does not reach the unwraps inside it.
#[allow(clippy::unwrap_used)]
async fn is_answered(datagram: &[u8]) -> bool {
    let endpoint = Endpoint::bind().await.unwrap();
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.local_addr().unwrap().port()));

    // The prober is a bare UDP socket, not a quirk endpoint: it must observe whatever the endpoint
    // emits, including bytes no quirk codec would accept.
    let prober = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    prober.send_to(datagram, target).await.unwrap();

    let mut buf = [0u8; 1500];
    tokio::time::timeout(LISTEN_FOR, prober.recv_from(&mut buf))
        .await
        .is_ok()
}

/// THE guard: a datagram this endpoint cannot decode gets no packet back, whichever half of the magic
/// is wrong.
///
/// `QRK1` is the case that matters and the case a uniformity pass would break. Its identity is ours,
/// so the receiver knows it is holding a quirk peer on a grammar it does not serve, which is exactly
/// the condition every sibling wire answers. Make the demux reply to it (or to anything else it fails
/// to decode) and this goes red.
#[tokio::test]
async fn an_undecodable_datagram_is_never_answered() {
    // A quirk identity at a version this build does not serve: the tempting one to answer.
    assert!(
        !is_answered(b"QRK1\x01").await,
        "a version mismatch was answered: this endpoint now reflects packets at any address an \
         attacker writes into a source field"
    );
    // A foreign identity: a stray scan, another protocol, noise on a shared port.
    assert!(
        !is_answered(b"XRK0\x01").await,
        "a foreign datagram was answered: this endpoint now confirms itself to a scanner"
    );
    // Well-formed magic, nothing behind it.
    assert!(
        !is_answered(b"QRK0").await,
        "a truncated datagram was answered"
    );
}
