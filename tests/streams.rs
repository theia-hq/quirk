use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use quirk::Endpoint;

fn loopback(endpoint: &Endpoint) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.local_addr().unwrap().port()))
}

/// A multi-chunk payload arrives intact and in order over one reliable stream.
#[tokio::test]
async fn reliable_stream_delivers_large_payload() {
    let acceptor = Endpoint::bind().await.unwrap();
    let dialer = Endpoint::bind().await.unwrap();
    let acceptor_addr = loopback(&acceptor);

    let (accepted, connected) = tokio::join!(acceptor.accept(), dialer.connect(acceptor_addr));
    let mut accepted = accepted.unwrap();
    let mut connected = connected.unwrap();

    // Spans many stream chunks (chunk size is 1024).
    let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let to_send = payload.clone();

    let received = tokio::time::timeout(Duration::from_secs(10), async move {
        let (sent, received) =
            tokio::join!(connected.send_reliable(&to_send), accepted.recv_reliable());
        sent.unwrap();
        received.unwrap()
    })
    .await
    .expect("reliable stream timed out");

    assert_eq!(received, payload);
}
