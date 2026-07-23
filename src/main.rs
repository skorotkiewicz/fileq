use anyhow::{bail, Context, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

const ALPN: &[u8] = b"fileq/2";
const DEFAULT_PORT: u16 = 4433;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    fn bind_addr(self, port: u16) -> SocketAddr {
        match self {
            Self::V4 => SocketAddr::from(([0, 0, 0, 0], port)),
            Self::V6 => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)),
        }
    }

    fn matches(self, addr: &SocketAddr) -> bool {
        match self {
            Self::V4 => addr.is_ipv4(),
            Self::V6 => addr.is_ipv6(),
        }
    }
}

fn endpoint(
    ip_version: IpVersion,
    port: u16,
    server_config: Option<ServerConfig>,
) -> Result<Endpoint> {
    let addr = ip_version.bind_addr(port);
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if ip_version == IpVersion::V6 {
        socket.set_only_v6(true)?;
    }
    socket.bind(&addr.into())?;

    Ok(Endpoint::new(
        Default::default(),
        server_config,
        socket.into(),
        Arc::new(TokioRuntime),
    )?)
}

// --- Constants ---

const INITIAL_CHUNK: usize = 4 * 1024;
const MAX_CHUNK: usize = 256 * 1024;
const MIN_CHUNK: usize = 512;
const GROW_THRESHOLD: u32 = 8;

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const MAX_IDLE_TIMEOUT_MS: u64 = 180_000;

const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(90);

const MAX_RETRIES: u32 = 15;
const MIN_SPEED_WINDOW: Duration = Duration::from_secs(30);
const RETRY_BASE: Duration = Duration::from_secs(1);
const RETRY_CAP: Duration = Duration::from_secs(30);

const STREAM_WINDOW: u64 = 256 * 1024;
const CONNECTION_WINDOW: u64 = 512 * 1024;

const PROGRESS_FAST: Duration = Duration::from_millis(200);
const PROGRESS_SLOW: Duration = Duration::from_millis(2000);
const SLOW_THRESHOLD_BPS: f64 = 32.0 * 1024.0;

// --- Ramp detection ---

const RAMP_WINDOW: usize = 5;
const RAMP_FACTOR: f64 = 1.4;
const RAMP_CONFIRM: usize = 3;
const DRAIN_FLOOR: Duration = Duration::from_millis(500);
const BASELINE_SAMPLES: usize = 4;

/// ★ Ignore latencies below this.  A 0.1ms → 0.3ms "ramp" is disk I/O noise,
///   not bufferbloat.  Real congestion shows up as 500ms+ latencies.
const MIN_LATENCY: Duration = Duration::from_millis(500);

// --- TLS helpers ---

fn server_tls() -> Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "0.0.0.0".into()])?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    Ok(ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    )))
}

fn client_tls() -> Result<ClientConfig> {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    )))
}

#[derive(Debug)]
struct SkipVerify;
impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer,
        _: &[rustls::pki_types::CertificateDer],
        _: &rustls::pki_types::ServerName,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// --- Transport config ---

fn survival_transport() -> TransportConfig {
    let mut cfg = TransportConfig::default();

    cfg.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    cfg.max_idle_timeout(Some(VarInt::from_u64(MAX_IDLE_TIMEOUT_MS).unwrap().into()));

    cfg.initial_rtt(Duration::from_secs(2));

    cfg.stream_receive_window(VarInt::from_u64(STREAM_WINDOW).unwrap());
    cfg.receive_window(VarInt::from_u64(CONNECTION_WINDOW).unwrap());
    cfg.send_window(CONNECTION_WINDOW);

    cfg.max_concurrent_bidi_streams(VarInt::from_u64(4).unwrap());

    cfg.min_mtu(1200);
    cfg.initial_mtu(1200);

    cfg
}

// --- Latency tracker (server-side: detects ramp, triggers pause) ---

struct LatencyTracker {
    samples: Vec<Duration>,
    baseline: Option<Duration>,
    count: u64,
    ramp_streak: u32,
}

impl LatencyTracker {
    fn new() -> Self {
        Self {
            samples: Vec::with_capacity(RAMP_WINDOW + 1),
            baseline: None,
            count: 0,
            ramp_streak: 0,
        }
    }

    /// Record a latency.  Returns `Some(pause)` if a bufferbloat ramp is
    /// confirmed and the caller should stop sending to let the buffer drain.
    fn observe(&mut self, latency: Duration) -> Option<Duration> {
        // ★ Ignore sub-500ms latencies entirely.  They're disk I/O or
        //   local-loopback noise, not network congestion.
        if latency < MIN_LATENCY {
            // A fast write means the buffer is NOT full.  Reset the streak.
            self.ramp_streak = 0;
            return None;
        }

        self.count += 1;

        if self.count <= BASELINE_SAMPLES as u64 {
            self.baseline = Some(match self.baseline {
                Some(b) => b.min(latency),
                None => latency,
            });
        }

        if self.samples.len() >= RAMP_WINDOW {
            self.samples.remove(0);
        }
        self.samples.push(latency);

        if self.samples.len() >= 2 {
            let prev = self.samples[self.samples.len() - 2];
            let curr = self.samples[self.samples.len() - 1];
            if curr.as_secs_f64() > prev.as_secs_f64() * RAMP_FACTOR {
                self.ramp_streak += 1;
            } else {
                self.ramp_streak = 0;
            }
        }

        if self.ramp_streak >= RAMP_CONFIRM as u32 {
            let baseline = self.baseline.unwrap_or(MIN_LATENCY);
            let latest = *self.samples.last().unwrap();
            let pause = latest.saturating_sub(baseline).max(DRAIN_FLOOR);

            eprintln!(
                "\n⚠ bufferbloat ramp ({:.0}ms→{:.0}ms) — pausing {:.1}s to drain",
                baseline.as_secs_f64() * 1000.0,
                latest.as_secs_f64() * 1000.0,
                pause.as_secs_f64(),
            );

            self.ramp_streak = 0;
            self.samples.clear();
            return Some(pause);
        }

        None
    }
}

// --- Adaptive chunk size ---

struct AdaptiveChunk {
    size: usize,
    full_streak: u32,
}

impl AdaptiveChunk {
    fn new() -> Self {
        Self {
            size: INITIAL_CHUNK,
            full_streak: 0,
        }
    }

    fn observe_read(&mut self, n: usize, cap: usize) {
        if n == cap {
            self.full_streak += 1;
            if self.full_streak >= GROW_THRESHOLD {
                self.size = (self.size * 2).min(MAX_CHUNK);
                self.full_streak = 0;
            }
        } else {
            self.size = (self.size / 2).max(MIN_CHUNK);
            self.full_streak = 0;
        }
    }

    /// ★ Shrink based on how long we waited for data.
    ///   Long wait = congested network = use smaller chunks.
    fn observe_latency(&mut self, latency: Duration) {
        if latency > Duration::from_secs(5) {
            // Multi-second wait: slam to minimum.
            self.size = MIN_CHUNK;
            self.full_streak = 0;
        } else if latency > Duration::from_secs(1) {
            // 1-5s wait: halve.
            self.size = (self.size / 2).max(MIN_CHUNK);
            self.full_streak = 0;
        } else if latency > Duration::from_millis(200) {
            // 200ms-1s: mild congestion, nudge down.
            self.size = (self.size * 3 / 4).max(MIN_CHUNK);
            self.full_streak = 0;
        }
        // < 200ms: healthy, let the normal grow logic handle it.
    }

    fn reset_to_min(&mut self) {
        self.size = MIN_CHUNK;
        self.full_streak = 0;
    }

    fn buf(&self) -> Vec<u8> {
        vec![0u8; self.size]
    }
}

// --- Timeout wrapper (server-side) ---

async fn timed_write(send: &mut quinn::SendStream, data: &[u8]) -> Result<Duration> {
    let start = Instant::now();
    match tokio::time::timeout(WRITE_TIMEOUT, send.write_all(data)).await {
        Ok(Ok(())) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => bail!(
            "write timed out after {:.0}s — connection choked",
            WRITE_TIMEOUT.as_secs_f64()
        ),
    }
}

// --- Protocol ---

async fn send_request(stream: &mut quinn::SendStream, path: &str, offset: u64) -> Result<()> {
    let b = path.as_bytes();
    stream.write_all(&(b.len() as u64).to_be_bytes()).await?;
    stream.write_all(b).await?;
    stream.write_all(&offset.to_be_bytes()).await?;
    stream.finish()?;
    Ok(())
}

async fn recv_request(stream: &mut quinn::RecvStream) -> Result<(String, u64)> {
    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf).await?;
    let len = u64::from_be_bytes(len_buf) as usize;
    if len > 4096 {
        bail!("path too long");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let path = String::from_utf8(buf)?;

    let mut off_buf = [0u8; 8];
    stream.read_exact(&mut off_buf).await?;
    let offset = u64::from_be_bytes(off_buf);

    Ok((path, offset))
}

// --- Server ---

async fn serve(dir: &Path, ip_version: IpVersion) -> Result<()> {
    let dir = dir.canonicalize().context("bad dir")?;

    let mut server_cfg = server_tls()?;
    server_cfg.transport_config(Arc::new(survival_transport()));

    let ep = endpoint(ip_version, DEFAULT_PORT, Some(server_cfg))?;
    eprintln!(
        "serving {:?} on {}",
        dir,
        ip_version.bind_addr(DEFAULT_PORT)
    );

    while let Some(conn) = ep.accept().await {
        let dir = dir.clone();
        tokio::spawn(async move {
            let conn = match conn.await {
                Ok(c) => c,
                Err(_) => return,
            };
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let dir = dir.clone();
                tokio::spawn(async move {
                    let (path, offset) = match recv_request(&mut recv).await {
                        Ok(r) => r,
                        Err(_) => return,
                    };
                    let clean = path.trim_start_matches('/');
                    if clean.contains("..") {
                        let _ = send.write_all(b"403").await;
                        return;
                    }
                    let file_path = dir.join(clean);

                    let mut file = match tokio::fs::File::open(&file_path).await {
                        Ok(f) => f,
                        Err(_) => {
                            eprintln!("✗ {} not found", clean);
                            let _ = send.write_all(b"404").await;
                            let _ = send.finish();
                            return;
                        }
                    };

                    let file_size = match file.metadata().await {
                        Ok(meta) => meta.len(),
                        Err(_) => return,
                    };
                    if offset > file_size {
                        let _ = send.write_all(b"416").await;
                        let _ = send.finish();
                        return;
                    }

                    use tokio::io::{AsyncReadExt, AsyncSeekExt};
                    if offset > 0 {
                        if file.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
                            let _ = send.write_all(b"416").await;
                            let _ = send.finish();
                            return;
                        }
                        eprintln!("→ {} (resume from {})", clean, offset);
                    } else {
                        eprintln!("→ {}", clean);
                    }

                    if send.write_all(&file_size.to_be_bytes()).await.is_err() {
                        return;
                    }

                    let mut adaptive = AdaptiveChunk::new();
                    let mut latency = LatencyTracker::new();

                    loop {
                        let mut buf = adaptive.buf();
                        match file.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                adaptive.observe_read(n, buf.len());

                                // ★ timed_write measures QUIC backpressure.
                                //   When ACKs are 8s away, write_all blocks
                                //   until the send window opens.  THAT latency
                                //   is the real network signal.
                                let elapsed = match timed_write(&mut send, &buf[..n]).await {
                                    Ok(d) => d,
                                    Err(e) => {
                                        eprintln!("\n✗ server write: {}", e);
                                        let _ = send.reset(VarInt::from_u32(1));
                                        return;
                                    }
                                };

                                // ★ Ramp detection → pause-and-drain.
                                //   Only fires when latency > 500ms AND
                                //   increasing >1.4× for 3 consecutive writes.
                                if let Some(pause) = latency.observe(elapsed) {
                                    adaptive.reset_to_min();
                                    tokio::time::sleep(pause).await;
                                }

                                tokio::task::yield_now().await;
                            }
                            Err(_) => {
                                let _ = send.reset(VarInt::from_u32(1));
                                return;
                            }
                        }
                    }
                    let _ = send.finish();
                });
            }
        });
    }
    Ok(())
}

// --- Progress ---

fn progress_line(
    filename: &str,
    total: u64,
    transferred: u64,
    file_size: u64,
    elapsed: Duration,
) -> String {
    let percent = if file_size == 0 {
        100
    } else {
        (u128::from(total.min(file_size)) * 100 / u128::from(file_size)) as u64
    };
    let speed = if elapsed.is_zero() {
        0.0
    } else {
        transferred as f64 / elapsed.as_secs_f64()
    };
    let complete = total >= file_size;
    let seconds = if complete {
        elapsed.as_secs()
    } else if speed == 0.0 {
        0
    } else {
        (file_size.saturating_sub(total) as f64 / speed) as u64
    };
    let eta = if complete { "" } else { " ETA" };

    format!(
        "{filename:<32} {percent:3}% {:>8}KB {:>8.1}KB/s   {:02}:{:02}{eta}",
        total / 1024,
        speed / 1024.0,
        seconds / 60,
        seconds % 60
    )
}

fn check_min_speed(bytes: u64, elapsed: Duration, minimum: u64) -> Result<()> {
    let speed = bytes as f64 / elapsed.as_secs_f64();
    if speed < minimum as f64 {
        bail!(
            "download averaged {:.1}KB/s for {:.0}s, below minimum {}KB/s",
            speed / 1024.0,
            elapsed.as_secs_f64(),
            minimum / 1024
        );
    }
    Ok(())
}

// --- Single download attempt ---

async fn download_once(
    addr: SocketAddr,
    host: &str,
    path: &str,
    out_path: &std::path::Path,
    offset: u64,
    ip_version: IpVersion,
    min_speed_bps: Option<u64>,
) -> Result<u64> {
    let mut ep = endpoint(ip_version, 0, None)?;
    let mut client_cfg = client_tls()?;
    client_cfg.transport_config(Arc::new(survival_transport()));
    ep.set_default_client_config(client_cfg);

    let conn = ep.connect(addr, host)?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    send_request(&mut send, path, offset).await?;

    let mut size_buf = [0u8; 8];
    recv.read_exact(&mut size_buf)
        .await
        .context("server did not return file size")?;
    let file_size = u64::from_be_bytes(size_buf);

    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(offset > 0)
        .truncate(offset == 0)
        .open(out_path)
        .await?;

    let filename = out_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let mut adaptive = AdaptiveChunk::new();
    let mut total = offset;
    let mut transferred: u64 = 0;
    let started = Instant::now();
    let mut last_progress = started;
    let mut speed_window_started = started;
    let mut speed_window_bytes = 0;

    loop {
        let mut buf = adaptive.buf();

        // ★ Measure how long we WAIT for data.  This is the real network
        //   latency signal: on a healthy 50ms link, reads return in <100ms.
        //   On your 8s-RTT link, reads block for ~8s.
        let read_start = Instant::now();

        let read_timeout = min_speed_bps
            .map(|_| {
                MIN_SPEED_WINDOW
                    .saturating_sub(speed_window_started.elapsed())
                    .min(READ_TIMEOUT)
            })
            .unwrap_or(READ_TIMEOUT);
        let read_result = tokio::time::timeout(read_timeout, recv.read(&mut buf)).await;

        let read_latency = read_start.elapsed();

        match read_result {
            Err(_) => {
                if total >= file_size {
                    break;
                }
                if let Some(minimum) = min_speed_bps {
                    check_min_speed(speed_window_bytes, speed_window_started.elapsed(), minimum)?;
                    speed_window_started = Instant::now();
                    speed_window_bytes = 0;
                    continue;
                }
                bail!(
                    "read timed out after {:.0}s — no data",
                    READ_TIMEOUT.as_secs_f64()
                );
            }
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(None)) => break,
            Ok(Ok(Some(n))) => {
                adaptive.observe_read(n, buf.len());

                // ★ Adapt chunk size to network latency.
                //   8s read wait → slam to 512B.
                //   2s read wait → halve.
                //   300ms wait  → nudge down.
                //   <200ms      → healthy, let it grow.
                //   NO PAUSING.  The client is the receiver; pausing the
                //   receiver just wastes time.  The server handles draining.
                adaptive.observe_latency(read_latency);

                file.write_all(&buf[..n]).await?;
                total += n as u64;
                transferred += n as u64;
                speed_window_bytes += n as u64;

                let now = Instant::now();
                let window_elapsed = now.duration_since(speed_window_started);
                if let Some(minimum) = min_speed_bps {
                    if total < file_size && window_elapsed >= MIN_SPEED_WINDOW {
                        check_min_speed(speed_window_bytes, window_elapsed, minimum)?;
                        speed_window_started = now;
                        speed_window_bytes = 0;
                    }
                }

                let speed = if now.duration_since(started).is_zero() {
                    0.0
                } else {
                    transferred as f64 / now.duration_since(started).as_secs_f64()
                };
                let interval = if speed < SLOW_THRESHOLD_BPS {
                    PROGRESS_SLOW
                } else {
                    PROGRESS_FAST
                };
                if now.duration_since(last_progress) >= interval {
                    eprint!(
                        "\r{}\x1b[K",
                        progress_line(
                            filename,
                            total,
                            transferred,
                            file_size,
                            now.duration_since(started)
                        )
                    );
                    last_progress = now;
                }

                tokio::task::yield_now().await;
            }
        }
    }

    eprintln!(
        "\r{}\x1b[K",
        progress_line(filename, total, transferred, file_size, started.elapsed())
    );
    file.flush().await?;

    if total < file_size {
        bail!("transfer incomplete: got {total} of {file_size} bytes");
    }
    Ok(total)
}

// --- Auto-reconnecting client ---

async fn get(
    url_str: &str,
    resume: bool,
    ip_version: IpVersion,
    min_speed_bps: Option<u64>,
    max_retries: u32,
) -> Result<()> {
    let url = url::Url::parse(url_str)?;
    let host = url
        .host_str()
        .context("no host")?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = url.port().unwrap_or(DEFAULT_PORT);
    let path = url.path().to_string();

    let filename = path.rsplit('/').next().unwrap_or("download");
    let out_path = std::path::PathBuf::from(filename);

    let mut offset = if resume && out_path.exists() {
        let meta = tokio::fs::metadata(&out_path).await?;
        let sz = meta.len();
        eprintln!("resuming {} from byte {}", filename, sz);
        sz
    } else {
        0
    };

    let addr = tokio::net::lookup_host((host, port))
        .await?
        .find(|addr| ip_version.matches(addr))
        .context("host has no address for requested IP version")?;

    let mut attempt: u32 = 0;
    loop {
        if attempt > 0 {
            let backoff = RETRY_BASE
                .saturating_mul(1u32 << (attempt - 1).min(5))
                .min(RETRY_CAP);
            eprintln!(
                "\n⟳ retry {}/{} in {:.0}s (resuming from byte {})…",
                attempt,
                max_retries,
                backoff.as_secs_f64(),
                offset
            );
            tokio::time::sleep(backoff).await;
        }

        match download_once(
            addr,
            host,
            &path,
            &out_path,
            offset,
            ip_version,
            min_speed_bps,
        )
        .await
        {
            Ok(final_offset) => {
                eprintln!("\n✓ done: {} ({} KB)", filename, final_offset / 1024);
                return Ok(());
            }
            Err(e) => {
                eprintln!("\n✗ attempt {} failed: {}", attempt + 1, e);

                if out_path.exists() {
                    offset = tokio::fs::metadata(&out_path).await?.len();
                }

                attempt += 1;
                if attempt > max_retries {
                    return Err(e).context(format!(
                        "gave up after {} retries at byte {}",
                        max_retries, offset
                    ));
                }
            }
        }
    }
}

// --- CLI ---

fn take_ip_version(args: &mut Vec<String>) -> Result<IpVersion> {
    let v4 = args.iter().any(|arg| arg == "-v4");
    let v6 = args.iter().any(|arg| arg == "-v6");
    if v4 && v6 {
        bail!("-v4 and -v6 are mutually exclusive");
    }

    args.retain(|arg| arg != "-v4" && arg != "-v6");
    Ok(if v6 { IpVersion::V6 } else { IpVersion::V4 })
}

fn take_number_option(args: &mut Vec<String>, option: &str) -> Result<Option<u64>> {
    let prefix = format!("{option}=");
    let mut value = None;
    let mut index = 0;

    while index < args.len() {
        let Some(raw) = args[index].strip_prefix(&prefix) else {
            index += 1;
            continue;
        };
        if value.is_some() {
            bail!("{option} specified more than once");
        }
        value = Some(
            raw.parse()
                .with_context(|| format!("{option} requires a non-negative integer"))?,
        );
        args.remove(index);
    }

    Ok(value)
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().collect();
    let ip_version = take_ip_version(&mut args)?;
    let min_speed = take_number_option(&mut args, "--min-speed")?;
    let max_retries = take_number_option(&mut args, "--max-retry")?
        .map(u32::try_from)
        .transpose()
        .context("--max-retry is too large")?;
    let min_speed_bps = match min_speed {
        Some(0) => bail!("--min-speed must be greater than zero"),
        Some(speed) => Some(
            speed
                .checked_mul(1024)
                .context("--min-speed is too large")?,
        ),
        None => None,
    };

    match args.as_slice() {
        [_, command, dir] if command == "serve" && min_speed.is_none() && max_retries.is_none() => {
            serve(Path::new(dir), ip_version).await
        }
        [_, command, url] if command == "get" => {
            get(
                url,
                false,
                ip_version,
                min_speed_bps,
                max_retries.unwrap_or(MAX_RETRIES),
            )
            .await
        }
        [_, command, flag, url] if command == "get" && flag == "-c" => {
            get(
                url,
                true,
                ip_version,
                min_speed_bps,
                max_retries.unwrap_or(MAX_RETRIES),
            )
            .await
        }
        _ => {
            eprintln!(
                "usage:\n  fileq serve [-v4|-v6] <dir>\n  fileq get [-c] [-v4|-v6] [--min-speed=KBPS] [--max-retry=N] <url>"
            );
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn selects_ip_version() {
        let _v4_endpoint = endpoint(IpVersion::V4, 0, None).unwrap();
        let _v6_endpoint = endpoint(IpVersion::V6, 0, None).unwrap();

        let v4: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let v6: SocketAddr = "[::1]:4433".parse().unwrap();
        assert!(IpVersion::V4.matches(&v4));
        assert!(IpVersion::V6.matches(&v6));
        assert_eq!(
            IpVersion::V4.bind_addr(4433),
            "0.0.0.0:4433".parse().unwrap()
        );
        assert_eq!(IpVersion::V6.bind_addr(4433), "[::]:4433".parse().unwrap());

        let mut args = ["fileq", "get", "-v6", "quic://[::1]/file"]
            .map(String::from)
            .to_vec();
        assert_eq!(take_ip_version(&mut args).unwrap(), IpVersion::V6);
        assert_eq!(args.len(), 3);

        let mut conflicting = ["fileq", "get", "-v4", "-v6", "url"]
            .map(String::from)
            .to_vec();
        assert!(take_ip_version(&mut conflicting).is_err());
    }

    #[test]
    fn parses_and_checks_download_limits() {
        let mut args = ["fileq", "get", "--min-speed=100", "--max-retry=20", "url"]
            .map(String::from)
            .to_vec();
        assert_eq!(
            take_number_option(&mut args, "--min-speed").unwrap(),
            Some(100)
        );
        assert_eq!(
            take_number_option(&mut args, "--max-retry").unwrap(),
            Some(20)
        );
        assert_eq!(args, ["fileq", "get", "url"].map(String::from));

        let mut duplicate = ["fileq", "--min-speed=100", "--min-speed=200"]
            .map(String::from)
            .to_vec();
        assert!(take_number_option(&mut duplicate, "--min-speed").is_err());

        let minimum = 100 * 1024;
        assert!(check_min_speed(3000 * 1024, MIN_SPEED_WINDOW, minimum).is_ok());
        assert!(check_min_speed(2999 * 1024, MIN_SPEED_WINDOW, minimum).is_err());
    }

    #[test]
    fn formats_progress() {
        assert_eq!(
            progress_line(
                "fileq",
                1536 * 1024,
                1024 * 1024,
                3072 * 1024,
                Duration::from_secs(2)
            ),
            "fileq                             50%     1536KB    512.0KB/s   00:03 ETA"
        );
        assert_eq!(
            progress_line(
                "fileq",
                3465 * 1024,
                3440 * 1024,
                3465 * 1024,
                Duration::from_secs(16)
            ),
            "fileq                            100%     3465KB    215.0KB/s   00:16"
        );
    }

    #[test]
    fn adaptive_chunk_grows_and_shrinks() {
        let mut ac = AdaptiveChunk::new();
        assert_eq!(ac.size, INITIAL_CHUNK);

        for _ in 0..GROW_THRESHOLD {
            ac.observe_read(INITIAL_CHUNK, INITIAL_CHUNK);
        }
        assert_eq!(ac.size, INITIAL_CHUNK * 2);

        ac.observe_read(100, ac.size);
        assert_eq!(ac.size, INITIAL_CHUNK);
    }

    #[test]
    fn adaptive_chunk_responds_to_latency() {
        let mut ac = AdaptiveChunk::new();
        // Grow it up first.
        for _ in 0..GROW_THRESHOLD * 3 {
            ac.observe_read(ac.size, ac.size);
        }
        let big = ac.size;
        assert!(big > MIN_CHUNK);

        // 8s latency → slam to min.
        ac.observe_latency(Duration::from_secs(8));
        assert_eq!(ac.size, MIN_CHUNK);

        // Grow back.
        for _ in 0..GROW_THRESHOLD * 2 {
            ac.observe_read(ac.size, ac.size);
        }
        let medium = ac.size;
        assert!(medium > MIN_CHUNK);

        // 2s latency → halve.
        ac.observe_latency(Duration::from_secs(2));
        assert_eq!(ac.size, (medium / 2).max(MIN_CHUNK));
    }

    #[test]
    fn latency_tracker_ignores_fast_writes() {
        let mut lt = LatencyTracker::new();

        // Sub-500ms "ramps" must NOT trigger.
        for _ in 0..20 {
            assert!(lt.observe(Duration::from_millis(1)).is_none());
            assert!(lt.observe(Duration::from_millis(2)).is_none());
            assert!(lt.observe(Duration::from_millis(4)).is_none());
        }
    }

    #[test]
    fn latency_tracker_detects_real_ramp() {
        let mut lt = LatencyTracker::new();

        // Baseline: a few writes at ~600ms (just above MIN_LATENCY).
        for _ in 0..BASELINE_SAMPLES {
            assert!(lt.observe(Duration::from_millis(600)).is_none());
        }

        // Real ramp: 600 → 900 → 1400 → 2200 (each >1.4× previous).
        assert!(lt.observe(Duration::from_millis(900)).is_none()); // streak 1
        assert!(lt.observe(Duration::from_millis(1400)).is_none()); // streak 2
        let pause = lt.observe(Duration::from_millis(2200)); // streak 3 → fire
        assert!(pause.is_some());
        let pause = pause.unwrap();
        assert!(pause > Duration::from_secs(1));
    }

    // #[test]
    // fn latency_tracker_resets_on_fast_write() {
    //     let mut lt = LatencyTracker::new();

    //     lt.observe(Duration::from_millis(600));
    //     lt.observe(Duration::from_millis(900)); // streak 1
    //     lt.observe(Duration::from_millis(1400)); // streak 2

    //     // A fast write (<500ms) resets the streak.
    //     lt.observe(Duration::from_millis(10));

    //     // Need 3 MORE consecutive increases to fire.
    //     assert!(lt.observe(Duration::from_millis(900)).is_none()); // streak 1
    //     assert!(lt.observe(Duration::from_millis(1400)).is_none()); // streak 2
    //     let pause = lt.observe(Duration::from_millis(2200)); // streak 3
    //     assert!(pause.is_some());
    // }

    #[test]
    fn adaptive_chunk_caps_at_max() {
        let mut ac = AdaptiveChunk::new();
        for _ in 0..200 {
            for _ in 0..GROW_THRESHOLD {
                ac.observe_read(ac.size, ac.size);
            }
        }
        assert!(ac.size <= MAX_CHUNK);
    }
}
