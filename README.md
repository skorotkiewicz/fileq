# quic

A tiny file server and client built on QUIC over UDP.

## Usage

Serve a directory on UDP port `4433`:

```sh
cargo run --release -- serve ./files
```

Download a file into the current directory:

```sh
cargo run --release -- get quic://localhost:4433/example.bin
```

Resume an interrupted download:

```sh
cargo run --release -- get -c quic://localhost:4433/example.bin
```

## Security

The server generates a self-signed certificate and the client skips certificate verification. Use this tool only on trusted networks.
