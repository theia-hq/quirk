use bytes::Bytes;

use crate::stream::StreamRx;

#[test]
fn delivers_in_order() {
    let mut rx = StreamRx::new();
    assert_eq!(rx.accept(0, Bytes::from_static(b"a")), b"a".to_vec());
    assert_eq!(rx.accept(1, Bytes::from_static(b"b")), b"b".to_vec());
    assert_eq!(rx.ack(), 2);
}

#[test]
fn buffers_out_of_order_then_drains() {
    let mut rx = StreamRx::new();
    assert!(rx.accept(2, Bytes::from_static(b"c")).is_empty());
    assert!(rx.accept(1, Bytes::from_static(b"b")).is_empty());
    assert_eq!(rx.ack(), 0);
    assert_eq!(rx.accept(0, Bytes::from_static(b"a")), b"abc".to_vec());
    assert_eq!(rx.ack(), 3);
}

#[test]
fn drops_duplicates() {
    let mut rx = StreamRx::new();
    assert_eq!(rx.accept(0, Bytes::from_static(b"a")), b"a".to_vec());
    assert!(rx.accept(0, Bytes::from_static(b"a")).is_empty());
    assert_eq!(rx.accept(1, Bytes::from_static(b"b")), b"b".to_vec());
    assert_eq!(rx.ack(), 2);
}
