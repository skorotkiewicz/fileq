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

Set a minimum speed in KB/s and a retry limit:

```sh
cargo run --release -- get --min-speed=100 --max-retry=20 quic://localhost:4433/example.bin
```

If a 30-second window averages below the minimum, fileq reconnects and resumes. Without these options, there is no minimum speed and failed transfers retry up to 15 times.

IPv4 is the default. Use `-v4` or `-v6` with either command to force an IP version:

```sh
cargo run --release -- serve -v6 ./files
cargo run --release -- get -v6 'quic://[::1]:4433/example.bin'
```

## Security

The server listens on all interfaces and creates a self-signed certificate each time it starts. The client accepts any certificate, so use this only on a trusted network.
