use bytes::Bytes;

use crate::wire::{DecodeError, Frame, KEY_LEN, MAGIC};

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

#[test]
fn rejects_bad_magic() {
    let mut bytes = Frame::Hello { key: [0; KEY_LEN] }.to_bytes();
    bytes[0] = b'X';
    assert_eq!(Frame::decode(&bytes), Err(DecodeError::BadMagic));
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
