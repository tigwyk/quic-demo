# quic-demo

A QUIC hello world in Rust, built on [quinn](https://github.com/quinn-rs/quinn).

One process starts a QUIC server and a client on `127.0.0.1`. The client:

1. completes the QUIC + TLS 1.3 handshake (self-signed cert generated in memory, pinned by the client; ALPN `hello-quic`),
2. opens one bidirectional stream and sends `"Hello"`,
3. reads the server's reply `"Hello, world!"`,
4. closes the connection cleanly.

## Run

```bash
cargo run
```

Example output:

```
[server] listening on 127.0.0.1:60120 (UDP)
[client] handshake complete: ALPN=Some("hello-quic"), RTT=2.4759ms
[client] sending "Hello" on client bidirectional stream 0
[server] accepted connection from 127.0.0.1:60121
[server] received: "Hello"
[client] received: "Hello, world!"
[client] connection closed
```

## Test

```bash
cargo test
```

## Deliberately left out

Multiple/unidirectional streams, datagrams, 0-RTT, connection migration, `SSLKEYLOGFILE` (Wireshark decryption), separate client/server binaries.
