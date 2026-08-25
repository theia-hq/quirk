use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use quirk::Endpoint;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn loopback(endpoint: &Endpoint) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.local_addr().unwrap().port()))
}

/// A large multi-chunk payload round-trips intact over one full-duplex bidirectional stream: the
/// dialer writes it, the acceptor echoes it back, the dialer reads the echo.
#[tokio::test]
async fn stream_echoes_a_large_payload() {
    let acceptor = Endpoint::bind().await.unwrap();
    let dialer = Endpoint::bind().await.unwrap();
    let acceptor_addr = loopback(&acceptor);

    let (accepted, connected) = tokio::join!(acceptor.accept(), dialer.connect(acceptor_addr));
    let accepted = accepted.unwrap();
    let connected = connected.unwrap();

    let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    let echoed = tokio::time::timeout(Duration::from_secs(10), async move {
        let (mut acceptor_write, mut acceptor_read) = accepted.accept_bi().unwrap();
        let (mut dialer_write, mut dialer_read) = connected.open_bi().unwrap();

        // Acceptor: read the whole payload, echo it back, finish.
        let echo = async move {
            let mut received = Vec::new();
            acceptor_read.read_to_end(&mut received).await.unwrap();
            acceptor_write.write_all(&received).await.unwrap();
            acceptor_write.shutdown().await.unwrap();
        };
        // Dialer: send the payload, finish writing, then read the echo.
        let send = async move {
            dialer_write.write_all(&payload).await.unwrap();
            dialer_write.shutdown().await.unwrap();
            let mut echo = Vec::new();
            dialer_read.read_to_end(&mut echo).await.unwrap();
            echo
        };

        let (_, echo) = tokio::join!(echo, send);
        echo
    })
    .await
    .expect("stream echo timed out");

    assert_eq!(echoed, expected);
}
