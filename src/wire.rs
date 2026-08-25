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
            other => Err(DecodeError::UnknownType(other)),
        }
    }
}

fn key_from(body: &[u8]) -> Result<[u8; KEY_LEN], DecodeError> {
    <[u8; KEY_LEN]>::try_from(body).map_err(|_| DecodeError::Truncated)
}

/// Why a datagram could not be decoded into a [`Frame`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The datagram did not begin with the quirk magic.
    #[error("bad magic")]
    BadMagic,
    /// The datagram ended before a full frame was read.
    #[error("truncated frame")]
    Truncated,
    /// The frame type byte was not recognized.
    #[error("unknown frame type {0:#04x}")]
    UnknownType(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrips() {
        let frame = Frame::Hello {
            key: [7u8; KEY_LEN],
        };
        assert_eq!(Frame::decode(&frame.to_bytes()), Ok(frame));
    }

    #[test]
    fn hello_ack_roundtrips() {
        let frame = Frame::HelloAck {
            key: [9u8; KEY_LEN],
        };
        assert_eq!(Frame::decode(&frame.to_bytes()), Ok(frame));
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
