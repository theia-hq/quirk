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
