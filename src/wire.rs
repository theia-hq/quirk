//! quirk wire format (phase 0, plaintext).
//!
//! One frame per UDP datagram: a 4-byte magic, a one-byte frame type, then the frame body. This
//! module is pure bytes in and out; no I/O lives here.

use bytes::Bytes;

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
        data: Bytes,
    },
    /// A reliable stream data segment: the `seq`-th frame of stream `stream`.
    Data {
        /// The stream this segment belongs to.
        stream: u32,
        /// The per-frame sequence number within the stream.
        seq: u32,
        /// The segment bytes.
        bytes: Bytes,
    },
    /// Cumulative acknowledgement: the receiver has every segment below `seq` of `stream`.
    Ack {
        /// The acknowledged stream.
        stream: u32,
        /// The next sequence number the receiver still needs.
        seq: u32,
    },
    /// The sender has finished writing to `stream`. Carries the sequence number the terminator
    /// occupies (one past the last data segment), so the receiver only signals end-of-stream once
    /// reassembly has reached it and a reordered final segment cannot be delivered as a truncated EOF.
    Fin {
        /// The finished stream.
        stream: u32,
        /// The sequence number the FIN occupies: one past the sender's last data segment.
        seq: u32,
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
            Frame::Fin { stream, seq } => {
                buf.push(T_FIN);
                buf.extend_from_slice(&stream.to_be_bytes());
                buf.extend_from_slice(&seq.to_be_bytes());
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
                data: Bytes::copy_from_slice(body),
            }),
            T_DATA => {
                let (stream, rest) = read_u32(body)?;
                let (seq, rest) = read_u32(rest)?;
                Ok(Frame::Data {
                    stream,
                    seq,
                    bytes: Bytes::copy_from_slice(rest),
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
                let (seq, rest) = read_u32(rest)?;
                expect_empty(rest)?;
                Ok(Frame::Fin { stream, seq })
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
