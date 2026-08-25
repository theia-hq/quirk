use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};

use quirk::Endpoint;

fn loopback(endpoint: &Endpoint) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.local_addr().unwrap().port()))
}

/// After the handshake, unreliable datagrams flow both ways.
#[tokio::test]
async fn datagrams_flow_both_ways() {
    let acceptor = Endpoint::bind().await.unwrap();
    let dialer = Endpoint::bind().await.unwrap();
    let acceptor_addr = loopback(&acceptor);

    let (accepted, connected) = tokio::join!(acceptor.accept(), dialer.connect(acceptor_addr));
    let mut accepted = accepted.unwrap();
    let mut connected = connected.unwrap();

    connected.send_datagram(b"ping").await.unwrap();
    assert_eq!(accepted.recv_datagram().await.unwrap().as_ref(), b"ping");

    accepted.send_datagram(b"pong").await.unwrap();
    assert_eq!(connected.recv_datagram().await.unwrap().as_ref(), b"pong");
}

/// The demultiplexer lets one endpoint accept several connections at once (impossible with a direct
/// per-call socket read).
#[tokio::test]
async fn accepts_multiple_concurrent_connections() {
    let acceptor = Endpoint::bind().await.unwrap();
    let acceptor_addr = loopback(&acceptor);

    let dialers = [
        Endpoint::bind().await.unwrap(),
        Endpoint::bind().await.unwrap(),
        Endpoint::bind().await.unwrap(),
    ];

    let (c0, c1, c2, a0, a1, a2) = tokio::join!(
        dialers[0].connect(acceptor_addr),
        dialers[1].connect(acceptor_addr),
        dialers[2].connect(acceptor_addr),
        acceptor.accept(),
        acceptor.accept(),
        acceptor.accept(),
    );
    let connected = [c0.unwrap(), c1.unwrap(), c2.unwrap()];
    let accepted = [a0.unwrap(), a1.unwrap(), a2.unwrap()];

    let dialer_keys: HashSet<[u8; 32]> =
        dialers.iter().map(|d| d.public_key().to_bytes()).collect();
    let accepted_keys: HashSet<[u8; 32]> = accepted.iter().map(|c| c.peer_key()).collect();
    assert_eq!(
        dialer_keys, accepted_keys,
        "every dialer was accepted exactly once"
    );

    let _ = connected; // keep the connections (and their routes) alive
}
