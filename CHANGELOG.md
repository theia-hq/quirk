# Changelog

All notable changes to quirk, newest first.

## v0.1.0

The first release: a QUIC-style transport written from scratch, with connections, reliable streams, and
unreliable datagrams over UDP, passing the bifrost conformance suite through the `bifrost-quirk` adapter.
Phase 1 (the Noise handshake) is still pending, so identity is nominal today, and the implementation is
not wire-compatible with standard QUIC.

### New
- **The wire codec and handshake.** Magic-prefixed frames (`Hello`, `HelloAck`, `Datagram`, `Data`, `Ack`,
  `Fin`) encoded and decoded by hand, with two endpoints exchanging ed25519 identities over UDP.
- **Connections over UDP.** `Endpoint::bind`, `bind_with_secret` (a caller-provided ed25519 secret, so a
  node keeps one public key across runs), and `bind_lossy` (a deterministic fault-injecting socket), plus
  `connect` and `accept`.
- **A socket demultiplexer.** One background task owns the UDP socket and routes packets to the right
  connection by peer address, so one endpoint serves many connections at once; the accept, inbound,
  datagram, and ack queues are bounded and shed on full.
- **Reliable bidirectional streams.** A full-duplex `AsyncRead` + `AsyncWrite` pair per connection, with
  in-order reassembly, cumulative acks, and stop-and-wait retransmission; the FIN retransmits until acked
  and the read half only shuts once reassembly reaches the FIN's sequence, so a late segment cannot read
  as a truncated clean EOF.
- **Unreliable datagrams.** Fire-and-forget messages on a connection (`send_datagram` / `recv_datagram`).
- **Close and route lifecycle.** `Connection::wait_closed` resolves once both directions quiesce; routes
  are generation-tagged and pruned on drop, a `Hello` reopens rather than routing into a stale connection,
  and a dial from a reused peer address is no longer black-holed.
