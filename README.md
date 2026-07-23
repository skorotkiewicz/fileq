# fileq

A small QUIC file transfer tool for slow or intermittent connections. It adjusts chunk sizes as latency changes and retries interrupted downloads from the last byte written.

## Usage

Serve a directory on UDP port `4433`:

```sh
cargo run --release -- serve ./files
```

Download a file into the current directory:

```sh
cargo run --release -- get quic://localhost:4433/example.bin
```

Continue an existing download:

```sh
cargo run --release -- get -c quic://localhost:4433/example.bin
```

## Security

The server listens on all interfaces and creates a self-signed certificate each time it starts. The client accepts any certificate, so use this only on a trusted network.
