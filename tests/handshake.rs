use std::net::{Ipv4Addr, SocketAddr};

use quirk::Endpoint;

/// Two endpoints on loopback complete the plaintext handshake and each learns the other's identity.
#[tokio::test]
async fn handshake_exchanges_identities() {
    let acceptor = Endpoint::bind().await.unwrap();
    let dialer = Endpoint::bind().await.unwrap();

    let acceptor_key = acceptor.public_key().to_bytes();
    let dialer_key = dialer.public_key().to_bytes();
    let acceptor_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, acceptor.local_addr().unwrap().port()));

    let (accepted, connected) = tokio::join!(acceptor.accept(), dialer.connect(acceptor_addr));
    let accepted = accepted.unwrap();
    let connected = connected.unwrap();

    assert_eq!(accepted.peer_key(), dialer_key, "acceptor sees the dialer");
    assert_eq!(
        connected.peer_key(),
        acceptor_key,
        "dialer sees the acceptor"
    );
}
