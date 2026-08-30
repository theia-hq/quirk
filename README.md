# quirk

A QUIC-style transport over UDP, written from scratch: connections, reliable in-order streams, and
unreliable datagrams, with the framing, handshake, and retransmission implemented by hand rather than
taken from a library. It is a learning implementation, built to understand how a modern transport works
by building one, and it is not interoperable with standard QUIC.

It also works as a real transport backend: an adapter makes quirk pass the same connection test suite as
iroh and the in-memory backend, so an application dialing a given identity runs unchanged over it.

**The name.** quirk is QUIC built by hand: the framing, handshake, and retransmission a library
would hide, written out so you can read them. The name plays on QUIC, with the quirk of a
from-scratch build that goes its own way and does not speak to standard QUIC.

> Experimental and incomplete. Not production-ready, and not wire-compatible with standard QUIC.

## What's implemented

- **Wire codec.** Magic-prefixed frames (`Hello`, `HelloAck`, `Datagram`, `Data`, `Ack`, `Fin`); pure
  bytes in and out.
- **Handshake.** Two endpoints exchange ed25519 identities over UDP.
- **Socket demultiplexer.** One background task owns the UDP socket and routes packets to the right
  connection by peer address, so an endpoint handles many connections at once.
- **Unreliable datagrams.** Fire-and-forget messages on a connection.
- **Reliable bidirectional streams.** A full-duplex `AsyncRead` + `AsyncWrite` pair per connection,
  with in-order reassembly and stop-and-wait retransmission.

Not yet: a Noise handshake (identity is nominal today), multiple streams per connection, connection
ids, congestion control, and NAT traversal.

## Usage

```rust
use quirk::Endpoint;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

// Acceptor: bind, share its address, accept a connection and its stream.
let acceptor = Endpoint::bind().await?;
let address = acceptor.local_addr()?;

// Dialer: bind, connect to that address, open the bidirectional stream.
let dialer = Endpoint::bind().await?;
let connection = dialer.connect(address).await?;
let (mut writer, mut reader) = connection.open_bi()?;

writer.write_all(b"hello").await?;
writer.shutdown().await?;
let mut echo = Vec::new();
reader.read_to_end(&mut echo).await?;
```

Datagrams are `connection.send_datagram(&bytes).await?` and `connection.recv_datagram().await`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
