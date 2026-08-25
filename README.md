# quirk

Our own QUIC transport, implemented from scratch over UDP — a play on "QUIC". quirk is a `bifrost`
transport backend: it establishes authenticated sessions to a `NodeId` by speaking a QUIC-shaped
protocol we build ourselves, to learn the internals rather than wrap an existing stack.

> Experimental and incomplete. A learning implementation: not ready for production use and not
> interoperable with standard QUIC.

## Usage

quirk implements `bifrost_transport::Transport`, so it composes into a `bifrost` `Node` like any other
transport:

```rust
use bifrost::Node;

let node = Node::new(quirk::Endpoint::bind().await?, discovery);
```

## Things to know

- Not quinn-based and not standards-compliant QUIC. quirk implements the transport machinery itself
  (packets, streams, flow control, loss recovery); `bifrost-iroh` is the standards-compliant path.
- Crypto is a Noise handshake (static key = `NodeId`), not TLS. Phase 0 runs plaintext with a nominal,
  unauthenticated identity; phase 1 adds the handshake.
- Held to the same behaviour as every bifrost transport by `bifrost-conformance`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
