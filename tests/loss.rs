//! The reliability layer under a lossy link.
//!
//! Loopback never drops a datagram, so these are the tests that actually exercise stop-and-wait
//! retransmission: a dropped data frame, a dropped FIN, and a dropped ack that forces a duplicate.
//! Every scenario uses a fault-injecting endpoint (see [`quirk::socket::Faults`]) with a fixed drop
//! schedule, and the transfer is one-way with both idle stream halves kept alive, so the faulty
//! endpoint's outbound datagram sequence is exactly `Hello, data 0, data 1, ..., FIN` (or, on the
//! acceptor, `HelloAck, ack, ...`) and each dropped index targets a known frame.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use quirk::Endpoint;
use quirk::socket::Faults;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn loopback(endpoint: &Endpoint) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.local_addr().unwrap().port()))
}

/// Run a one-way transfer of `payload` from a dialer applying `dialer_faults` to a plain acceptor, and
/// return the bytes the acceptor reads to a clean end. Both idle stream halves are held open so the
/// only datagrams the dialer sends are its own stream's, keeping the fault schedule predictable: send
/// #1 is the Hello, #2 the first data frame, one per chunk after, and the FIN last.
async fn one_way_over(dialer_faults: Faults, payload: Vec<u8>) -> Vec<u8> {
    let acceptor = Endpoint::bind().await.unwrap();
    let dialer = Endpoint::bind_lossy(dialer_faults).await.unwrap();
    let acceptor_addr = loopback(&acceptor);

    let (accepted, connected) = tokio::join!(acceptor.accept(), dialer.connect(acceptor_addr));
    let accepted = accepted.unwrap();
    let connected = connected.unwrap();

    tokio::time::timeout(Duration::from_secs(10), async move {
        // Keep the unused halves alive: a dropped acceptor write half would send a reverse FIN and a
        // dropped dialer read half nothing, but holding both keeps the dialer's outbound purely its own.
        let (_acceptor_write, mut acceptor_read) = accepted.accept_bi().unwrap();
        let (mut dialer_write, _dialer_read) = connected.open_bi().unwrap();

        let receive = async move {
            let mut received = Vec::new();
            acceptor_read.read_to_end(&mut received).await.unwrap();
            received
        };
        let send = async move {
            dialer_write.write_all(&payload).await.unwrap();
            dialer_write.shutdown().await.unwrap();
        };

        let (received, ()) = tokio::join!(receive, send);
        received
    })
    .await
    .expect("transfer timed out under injected faults")
}

/// A dropped stream data frame is retransmitted, so every byte still arrives in order.
#[tokio::test]
async fn recovers_a_dropped_data_frame() {
    // Two data frames (2 * 1024 payload). Sends: #1 Hello, #2 data seq 0, #3 data seq 1, #4 FIN.
    // Drop #3 so the second segment is lost and must be retransmitted before the FIN can be acked.
    let payload: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
    let received = one_way_over(Faults::drop_sends([3]), payload.clone()).await;
    assert_eq!(received, payload, "the dropped data frame was recovered");
}

/// A repeatedly-dropped FIN is retransmitted until acked, so the reader observes a clean end rather
/// than hanging forever. Dropping three consecutive terminators defeats any fixed-count best-effort
/// blast; only a real retransmit-until-acked loop recovers it.
#[tokio::test]
async fn recovers_a_dropped_fin() {
    // One data frame. Sends: #1 Hello, #2 data seq 0, then FINs at #3, #4, #5, ... Drop the first three
    // FIN transmissions; without retransmit-until-acked the acceptor's `read_to_end` blocks forever.
    let payload: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
    let received = one_way_over(Faults::drop_sends([3, 4, 5]), payload.clone()).await;
    assert_eq!(
        received, payload,
        "the dropped FIN was recovered as a clean EOF"
    );
}

/// A data frame the sender retransmits (because an ack was lost) is not double-delivered: the receiver
/// suppresses the duplicate and the payload arrives exactly once, byte-identical.
#[tokio::test]
async fn suppresses_a_retransmitted_duplicate() {
    // One data frame. Sends on the receiver side: the acceptor's first ack of data seq 0 is dropped
    // (recv-side drop of an outbound ack), so the sender times out and retransmits data seq 0. The
    // receiver then sees seq 0 twice and must deliver it once, dropping the duplicate.
    let payload: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
    let received = duplicate_via_dropped_ack(payload.clone()).await;
    assert_eq!(
        received, payload,
        "the retransmitted duplicate was suppressed"
    );
}

/// Run a one-way transfer where the acceptor drops its first outbound ack, forcing the sender to
/// retransmit the acked data frame so the receiver observes a duplicate. Returns the acceptor's bytes.
async fn duplicate_via_dropped_ack(payload: Vec<u8>) -> Vec<u8> {
    // The acceptor's outbound datagrams are: #1 HelloAck, #2 the ack of data seq 0. Drop #2 so the
    // sender never learns data seq 0 landed and retransmits it.
    let acceptor = Endpoint::bind_lossy(Faults::drop_sends([2])).await.unwrap();
    let dialer = Endpoint::bind().await.unwrap();
    let acceptor_addr = loopback(&acceptor);

    let (accepted, connected) = tokio::join!(acceptor.accept(), dialer.connect(acceptor_addr));
    let accepted = accepted.unwrap();
    let connected = connected.unwrap();

    tokio::time::timeout(Duration::from_secs(10), async move {
        let (_acceptor_write, mut acceptor_read) = accepted.accept_bi().unwrap();
        let (mut dialer_write, _dialer_read) = connected.open_bi().unwrap();

        let receive = async move {
            let mut received = Vec::new();
            acceptor_read.read_to_end(&mut received).await.unwrap();
            received
        };
        let send = async move {
            dialer_write.write_all(&payload).await.unwrap();
            dialer_write.shutdown().await.unwrap();
        };

        let (received, ()) = tokio::join!(receive, send);
        received
    })
    .await
    .expect("transfer timed out under a dropped ack")
}
