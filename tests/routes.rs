//! Route lifetime: a dropped connection must not black-hole a later peer at the same address.
//!
//! quirk demultiplexes inbound datagrams by peer `SocketAddr`. If a closed connection's route were
//! left in the table, a new peer dialing from a reused address (OS port reuse, NAT rebinding) would be
//! routed into the dead connection and its `Hello` silently discarded. The connection's `Drop` prunes
//! its route, so the address is free to be dialed again.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use quirk::Endpoint;

fn loopback(endpoint: &Endpoint) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.local_addr().unwrap().port()))
}

/// After a connection from a given source address is dropped on both ends, a fresh connection from the
/// same source address (the same dialer socket) is accepted rather than black-holed into the dead route.
#[tokio::test]
async fn reused_address_is_not_black_holed_after_close() {
    let acceptor = Endpoint::bind().await.unwrap();
    let dialer = Endpoint::bind().await.unwrap();
    let acceptor_addr = loopback(&acceptor);

    // First connection from the dialer's socket address.
    let (accepted, connected) = tokio::join!(acceptor.accept(), dialer.connect(acceptor_addr));
    let accepted = accepted.unwrap();
    let connected = connected.unwrap();
    let dialer_key = dialer.public_key().to_bytes();
    assert_eq!(accepted.peer_key(), dialer_key);

    // Close both ends. Dropping the accepted connection prunes the acceptor's route for the dialer's
    // address; without that pruning the next Hello from the same address would be short-circuited.
    drop(accepted);
    drop(connected);

    // A fresh connection from the same dialer socket (hence the same source address) must be accepted.
    let redial = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(acceptor.accept(), dialer.connect(acceptor_addr))
    })
    .await
    .expect("re-dial from a reused address was black-holed");

    let (accepted2, connected2) = redial;
    let accepted2 = accepted2.unwrap();
    let _connected2 = connected2.unwrap();
    assert_eq!(
        accepted2.peer_key(),
        dialer_key,
        "the reused address opened a new connection to the same dialer"
    );
}
