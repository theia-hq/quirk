//! Reliable-stream reassembly: pure, deterministic logic with no I/O, so it is exhaustively
//! unit-testable. The async wiring (per-stream tasks, `AsyncRead`/`AsyncWrite`, retransmit) builds on
//! this in the next slice.

use std::collections::BTreeMap;

use bytes::Bytes;

/// Reassembles a reliable stream from per-frame `Data` segments: delivers bytes in order, drops
/// duplicates, and buffers out-of-order segments until the gap fills.
#[derive(Debug, Default)]
pub struct StreamRx {
    next: u32,
    buffered: BTreeMap<u32, Bytes>,
}

impl StreamRx {
    /// A fresh reassembler expecting sequence 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a segment, returning the bytes that are now deliverable in order (possibly empty).
    pub fn accept(&mut self, seq: u32, bytes: Bytes) -> Vec<u8> {
        if seq < self.next {
            return Vec::new(); // already delivered; a retransmit
        }
        self.buffered.entry(seq).or_insert(bytes);

        let mut delivered = Vec::new();
        while let Some(segment) = self.buffered.remove(&self.next) {
            delivered.extend_from_slice(&segment);
            self.next += 1;
        }
        delivered
    }

    /// The next sequence number still needed: the cumulative ack to send back.
    pub fn ack(&self) -> u32 {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
