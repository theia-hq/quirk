use bytes::Bytes;

use crate::wire::{DecodeError, Frame, KEY_LEN};

/// The four magic bytes a well-formed datagram opens with, spelled out rather than imported, so a
/// test cannot agree with the codec by sharing its constant.
const MAGIC: [u8; 4] = *b"QRK0";

fn roundtrips(frame: Frame) {
    assert_eq!(Frame::decode(&frame.to_bytes()), Ok(frame));
}

#[test]
fn hello_roundtrips() {
    roundtrips(Frame::Hello {
        key: [7u8; KEY_LEN],
    });
}

#[test]
fn hello_ack_roundtrips() {
    roundtrips(Frame::HelloAck {
        key: [9u8; KEY_LEN],
    });
}

#[test]
fn datagram_roundtrips() {
    roundtrips(Frame::Datagram {
        data: Bytes::from_static(b"hello overlay"),
    });
    roundtrips(Frame::Datagram { data: Bytes::new() });
}

#[test]
fn data_roundtrips() {
    roundtrips(Frame::Data {
        stream: 3,
        seq: 42,
        bytes: Bytes::from_static(b"payload"),
    });
    roundtrips(Frame::Data {
        stream: 0,
        seq: 0,
        bytes: Bytes::new(),
    });
}

#[test]
fn ack_roundtrips() {
    roundtrips(Frame::Ack { stream: 3, seq: 43 });
}

#[test]
fn fin_roundtrips() {
    roundtrips(Frame::Fin { stream: 3, seq: 17 });
}

/// One well-formed `Hello` datagram with the byte at `at` replaced. The two tests below differ only
/// in WHICH half of the magic they corrupt, because that single difference is the whole claim.
fn datagram_with(at: usize, byte: u8) -> Vec<u8> {
    let mut bytes = Frame::Hello { key: [0; KEY_LEN] }.to_bytes();
    bytes[at] = byte;
    bytes
}

/// A datagram whose IDENTITY is not ours is not a quirk datagram, and that is all it is.
#[test]
fn rejects_a_foreign_identity() {
    // `XRK0`: one byte of the identity changed, and nothing else.
    assert_eq!(
        Frame::decode(&datagram_with(0, b'X')),
        Err(DecodeError::Foreign)
    );
}

/// The version half of the magic is PARSED, so a quirk peer on another build is a distinguishable
/// condition rather than a foreign datagram. Revert the parse to a four-byte comparison and this goes
/// red at the first assertion. It stays a DROP either way (`tests/silence.rs` holds that); what this
/// pins is that the receiver knows which of the two it dropped.
#[test]
fn a_version_mismatch_is_not_a_foreign_datagram() {
    // `QRK1`: one byte of the version changed, and nothing else.
    let error = Frame::decode(&datagram_with(3, b'1')).expect_err("QRK1 is not this grammar");

    assert_ne!(
        error,
        DecodeError::Foreign,
        "a quirk peer on another build is not a foreign protocol"
    );
    assert_eq!(
        error.to_string(),
        "quirk wire version mismatch: the datagram is QRK1, this build speaks QRK0"
    );
}

#[test]
fn rejects_truncated_key() {
    let bytes = Frame::Hello { key: [0; KEY_LEN] }.to_bytes();
    assert_eq!(Frame::decode(&bytes[..10]), Err(DecodeError::Truncated));
}

#[test]
fn rejects_truncated_ack() {
    let bytes = Frame::Ack { stream: 1, seq: 2 }.to_bytes();
    assert_eq!(Frame::decode(&bytes[..7]), Err(DecodeError::Truncated));
}

#[test]
fn rejects_empty_after_magic() {
    assert_eq!(Frame::decode(&MAGIC), Err(DecodeError::Truncated));
}

#[test]
fn rejects_unknown_type() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.push(0xff);
    assert_eq!(Frame::decode(&bytes), Err(DecodeError::UnknownType(0xff)));
}
