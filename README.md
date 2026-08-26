# quirk

Our own QUIC, built from scratch over UDP to learn how the transport machinery (framing, handshake,
streams, reliability) actually works, rather than reach for an existing stack. The name is a play on
"QUIC".

quirk is also a real `bifrost` transport, not just a toy: an out-of-tree `bifrost-quirk` adapter makes
it pass the same `reach` conformance suite as iroh and the in-memory transport. The same app, dialing
the same identity, runs unchanged over our own QUIC.

> Experimental and incomplete. A learning implementation: not production-ready, and not interoperable
> with standard QUIC.

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
