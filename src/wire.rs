//! quirk wire format (phase 0, plaintext).
//!
//! One frame per UDP datagram: a 4-byte magic, a one-byte frame type, then the frame body. This
//! module is pure bytes in and out; no I/O lives here.

/// Magic prefixing every quirk datagram. Stray or foreign packets are rejected on decode.
pub const MAGIC: [u8; 4] = *b"QRK0";

/// The length of a raw ed25519 public key.
pub const KEY_LEN: usize = 32;

const T_HELLO: u8 = 0x01;
const T_HELLO_ACK: u8 = 0x02;
const T_DATAGRAM: u8 = 0x03;
const T_DATA: u8 = 0x04;
const T_ACK: u8 = 0x05;
const T_FIN: u8 = 0x06;

/// A single quirk protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Connection initiator announcing its identity.
    Hello {
        /// The initiator's raw ed25519 public key.
        key: [u8; KEY_LEN],
    },
    /// Connection responder announcing its identity.
    HelloAck {
        /// The responder's raw ed25519 public key.
        key: [u8; KEY_LEN],
    },
    /// An unreliable datagram payload on an established connection.
    Datagram {
        /// The datagram bytes.
        data: Vec<u8>,
    },
    /// A reliable stream data segment: the `seq`-th frame of stream `stream`.
    Data {
        /// The stream this segment belongs to.
        stream: u32,
        /// The per-frame sequence number within the stream.
        seq: u32,
        /// The segment bytes.
        bytes: Vec<u8>,
    },
    /// Cumulative acknowledgement: the receiver has every segment below `seq` of `stream`.
    Ack {
        /// The acknowledged stream.
        stream: u32,
        /// The next sequence number the receiver still needs.
        seq: u32,
    },
    /// The sender has finished writing to `stream`.
    Fin {
        /// The finished stream.
        stream: u32,
    },
}

impl Frame {
    /// Append the framed byte encoding to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&MAGIC);
        match self {
            Frame::Hello { key } => {
                buf.push(T_HELLO);
                buf.extend_from_slice(key);
            }
            Frame::HelloAck { key } => {
                buf.push(T_HELLO_ACK);
                buf.extend_from_slice(key);
            }
            Frame::Datagram { data } => {
                buf.push(T_DATAGRAM);
                buf.extend_from_slice(data);
            }
            Frame::Data { stream, seq, bytes } => {
                buf.push(T_DATA);
                buf.extend_from_slice(&stream.to_be_bytes());
                buf.extend_from_slice(&seq.to_be_bytes());
                buf.extend_from_slice(bytes);
            }
            Frame::Ack { stream, seq } => {
                buf.push(T_ACK);
                buf.extend_from_slice(&stream.to_be_bytes());
                buf.extend_from_slice(&seq.to_be_bytes());
            }
            Frame::Fin { stream } => {
                buf.push(T_FIN);
                buf.extend_from_slice(&stream.to_be_bytes());
            }
        }
    }

    /// Encode into a fresh buffer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    /// Decode one frame from a datagram.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let rest = bytes.strip_prefix(&MAGIC).ok_or(DecodeError::BadMagic)?;
        let (&ty, body) = rest.split_first().ok_or(DecodeError::Truncated)?;
        match ty {
            T_HELLO => Ok(Frame::Hello {
                key: key_from(body)?,
            }),
            T_HELLO_ACK => Ok(Frame::HelloAck {
                key: key_from(body)?,
            }),
            T_DATAGRAM => Ok(Frame::Datagram {
                data: body.to_vec(),
            }),
            T_DATA => {
                let (stream, rest) = read_u32(body)?;
                let (seq, rest) = read_u32(rest)?;
                Ok(Frame::Data {
                    stream,
                    seq,
                    bytes: rest.to_vec(),
                })
            }
            T_ACK => {
                let (stream, rest) = read_u32(body)?;
                let (seq, rest) = read_u32(rest)?;
                expect_empty(rest)?;
                Ok(Frame::Ack { stream, seq })
            }
            T_FIN => {
                let (stream, rest) = read_u32(body)?;
                expect_empty(rest)?;
                Ok(Frame::Fin { stream })
            }
            other => Err(DecodeError::UnknownType(other)),
        }
    }
}

fn key_from(body: &[u8]) -> Result<[u8; KEY_LEN], DecodeError> {
    <[u8; KEY_LEN]>::try_from(body).map_err(|_| DecodeError::Truncated)
}

fn read_u32(body: &[u8]) -> Result<(u32, &[u8]), DecodeError> {
    let (head, rest) = body.split_at_checked(4).ok_or(DecodeError::Truncated)?;
    let value = u32::from_be_bytes(head.try_into().expect("split_at_checked yields four bytes"));
    Ok((value, rest))
}

fn expect_empty(rest: &[u8]) -> Result<(), DecodeError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(DecodeError::Truncated)
    }
}

/// Why a datagram could not be decoded into a [`Frame`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The datagram did not begin with the quirk magic.
    #[error("bad magic")]
    BadMagic,
    /// The datagram ended before a full frame was read, or carried trailing bytes.
    #[error("truncated frame")]
    Truncated,
    /// The frame type byte was not recognized.
    #[error("unknown frame type {0:#04x}")]
    UnknownType(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

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
            data: b"hello overlay".to_vec(),
        });
        roundtrips(Frame::Datagram { data: Vec::new() });
    }

    #[test]
    fn data_roundtrips() {
        roundtrips(Frame::Data {
            stream: 3,
            seq: 42,
            bytes: b"payload".to_vec(),
        });
        roundtrips(Frame::Data {
            stream: 0,
            seq: 0,
            bytes: Vec::new(),
        });
    }

    #[test]
    fn ack_roundtrips() {
        roundtrips(Frame::Ack { stream: 3, seq: 43 });
    }

    #[test]
    fn fin_roundtrips() {
        roundtrips(Frame::Fin { stream: 3 });
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
}
