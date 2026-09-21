//! quirk wire format (phase 0, plaintext).
//!
//! One frame per UDP datagram: a 4-byte magic, a one-byte frame type, then the frame body. This
//! module is pure bytes in and out; no I/O lives here.

use bytes::Bytes;

/// quirk's protocol identity: the bytes every datagram opens with, at every version, forever. A
/// datagram that does not open with these is not a quirk datagram, and that is the only thing an
/// identity mismatch is allowed to mean.
const IDENTITY: [u8; 3] = *b"QRK";

/// The packet grammar THIS build speaks, written after [`IDENTITY`] and parsed (never compared whole)
/// on read: together they are the four magic bytes `QRK0`.
const VERSION: WireVersion = WireVersion(*b"0");

/// The magic splits by RULE, not by a remembered offset: the identity is the leading run of capitals,
/// the version is the digits after it, four bytes in all. Held at build time so a magic that breaks the
/// rule fails to compile rather than splitting somewhere the next reader would not look. A digit is
/// never a capital, so "all capitals, then all digits" is exactly "the maximal leading capital run".
const _: () = assert!(
    all_between(&IDENTITY, b'A', b'Z')
        && all_between(VERSION.as_bytes(), b'0', b'9')
        && IDENTITY.len() + VERSION.as_bytes().len() == 4,
    "the magic must be four bytes: a run of capitals (the identity) then digits (the version)"
);

/// Whether `bytes` is non-empty and every byte falls in `lo..=hi`. `const` because its one caller is a
/// build-time claim about the magic.
const fn all_between(bytes: &[u8], lo: u8, hi: u8) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] < lo || bytes[at] > hi {
            return false;
        }
        at += 1;
    }
    !bytes.is_empty()
}

/// The version half of a datagram's magic: the byte after [`IDENTITY`], naming which packet grammar
/// the peer that wrote it speaks.
///
/// Parsed as a value rather than folded into one four-byte comparison, because the two halves of the
/// magic answer different questions: "not our protocol" and "our protocol, another build" are two
/// facts, and a receiver that throws the distinction away cannot tell an operator which one it saw.
/// Both are DROPPED here, for the reason on [`DecodeError`], but they are dropped as distinct
/// conditions rather than as one undifferentiated failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireVersion([u8; 1]);

impl WireVersion {
    /// Split the version half off the front of `after_identity`. The width of the field lives here, in
    /// the type that owns it, so the reader and the writer cannot drift apart.
    fn split(after_identity: &[u8]) -> Option<(Self, &[u8])> {
        let (bytes, rest) = after_identity.split_at_checked(1)?;
        Some((Self([bytes[0]]), rest))
    }

    /// The bytes as they go on the wire.
    const fn as_bytes(&self) -> &[u8; 1] {
        &self.0
    }
}

impl core::fmt::Display for WireVersion {
    /// Renders the WHOLE four-byte tag (`QRK0`), because that is the form the source and the changelog
    /// use, so anyone holding one from a log line can match it against what they read. A peer's version
    /// byte is arbitrary and need not be printable, so it is escaped rather than trusted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{}", IDENTITY.escape_ascii(), self.0.escape_ascii())
    }
}

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
        buf.extend_from_slice(&IDENTITY);
        buf.extend_from_slice(VERSION.as_bytes());
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
    ///
    /// The magic is parsed as [`IDENTITY`] plus a [`WireVersion`], never compared as four bytes, so
    /// that "not our protocol" and "our protocol, another build" stay two facts instead of one.
    /// Neither is answered: see [`DecodeError`] for why this wire, alone in its family, must stay
    /// silent about both.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let rest = bytes.strip_prefix(&IDENTITY).ok_or(DecodeError::Foreign)?;
        let (version, rest) = WireVersion::split(rest).ok_or(DecodeError::Truncated)?;
        if version != VERSION {
            return Err(DecodeError::Version { peer: version });
        }
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
    // `split_at_checked(4)` returned `Some`, so `head` is exactly four bytes and the array conversion
    // is infallible; the expect can only fire if that guarantee is ever broken above.
    #[allow(clippy::expect_used)]
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
///
/// **Every variant is dropped in silence, and a version mismatch MUST stay that way.** Every other
/// wire in this family answers a peer whose identity it recognised at a version it does not serve,
/// because there silence sends an operator hunting a broken network instead of a version skew. This
/// wire is the exception, and the exception is a security property, not an omission: these bytes
/// arrive in an unauthenticated UDP datagram whose source address is a CLAIM, so any reply is a
/// packet an attacker can aim at a third party by writing that party's address into the `from` field.
/// A responder that answers unsolicited datagrams is a reflection amplifier and an unauthenticated
/// scan target, and that outweighs the diagnostic every time.
///
/// So this type deliberately carries no `answer` constructor, unlike its siblings on the stream
/// wires. When quirk needs version negotiation it takes the QUIC mechanism (a Version Negotiation
/// packet under its own anti-amplification limits), which is designed for a spoofable source; it does
/// not take the stream-preamble convention. Do not "fix" the silence for uniformity.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The datagram did not begin with [`IDENTITY`], so it is not a quirk datagram. On a shared UDP
    /// port this is the ordinary case: stray scans and other protocols land here.
    #[error("not a quirk datagram")]
    Foreign,
    /// A quirk datagram from a build that speaks a different packet grammar. Distinguishable from a
    /// foreign datagram so a log line can say which was seen; never answered, per this type's doc.
    #[error("quirk wire version mismatch: the datagram is {peer}, this build speaks {VERSION}")]
    Version {
        /// The version the peer's datagram named.
        peer: WireVersion,
    },
    /// The datagram ended before a full frame was read, or carried trailing bytes.
    #[error("truncated frame")]
    Truncated,
    /// The frame type byte was not recognized.
    #[error("unknown frame type {0:#04x}")]
    UnknownType(u8),
}
