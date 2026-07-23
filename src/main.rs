use anyhow::{bail, Context, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use std::{net::SocketAddr, path::Path, sync::Arc};

const ALPN: &[u8] = b"fileq/1";
const DEFAULT_PORT: u16 = 4433;

// --- TLS helpers (unchanged) ---

fn server_tls() -> Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "0.0.0.0".into()])?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
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

// --- Protocol v2: [u64 path_len][path][u64 offset] → [bytes until FIN]

async fn send_request(stream: &mut quinn::SendStream, path: &str, offset: u64) -> Result<()> {
    let b = path.as_bytes();
    stream.write_all(&(b.len() as u64).to_be_bytes()).await?;
    stream.write_all(b).await?;
    stream.write_all(&offset.to_be_bytes()).await?; // ← new
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

    let mut off_buf = [0u8; 8]; // ← new
    stream.read_exact(&mut off_buf).await?;
    let offset = u64::from_be_bytes(off_buf);

    Ok((path, offset))
}

// --- Server (now streams from disk, supports offset) ---

async fn serve(dir: &Path, addr: SocketAddr) -> Result<()> {
    let dir = dir.canonicalize().context("bad dir")?;
    let ep = Endpoint::server(server_tls()?, addr)?;
    eprintln!("serving {:?} on {}", dir, addr);

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

                    // Stream from disk instead of loading whole file into RAM
                    let mut file = match tokio::fs::File::open(&file_path).await {
                        Ok(f) => f,
                        Err(_) => {
                            eprintln!("✗ {} not found", clean);
                            let _ = send.write_all(b"404").await;
                            let _ = send.finish();
                            return;
                        }
                    };

                    use tokio::io::{AsyncReadExt, AsyncSeekExt};
                    if offset > 0 {
                        if file.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
                            let _ = send.write_all(b"416").await; // range not satisfiable
                            let _ = send.finish();
                            return;
                        }
                        eprintln!("→ {} (resume from {})", clean, offset);
                    } else {
                        eprintln!("→ {}", clean);
                    }

                    // Stream in chunks
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match file.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if send.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = send.finish();
                });
            }
        });
    }
    Ok(())
}

// --- Client ---

async fn get(url_str: &str, resume: bool) -> Result<()> {
    let url = url::Url::parse(url_str)?;
    let host = url.host_str().context("no host")?;
    let port = url.port().unwrap_or(DEFAULT_PORT);
    let path = url.path().to_string();

    // Figure out output: file (with -c) or stdout
    let filename = path.rsplit('/').next().unwrap_or("download");
    let out_path = std::path::PathBuf::from(filename);

    let offset = if resume && out_path.exists() {
        let meta = tokio::fs::metadata(&out_path).await?;
        let sz = meta.len();
        eprintln!("resuming {} from byte {}", filename, sz);
        sz
    } else {
        0
    };

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    let mut ep = Endpoint::client("0.0.0.0:0".parse()?)?;
    ep.set_default_client_config(client_tls()?);

    let conn = ep.connect(addr, host)?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    send_request(&mut send, &path, offset).await?;

    use tokio::io::AsyncWriteExt;

    if resume {
        // Append to file
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&out_path)
            .await?;

        let mut buf = vec![0u8; 64 * 1024];
        let mut total = offset;
        loop {
            match recv.read(&mut buf).await? {
                None => break,
                Some(n) => {
                    file.write_all(&buf[..n]).await?;
                    total += n as u64;
                    eprint!("\r{}: {} bytes", filename, total);
                }
            }
        }
        eprintln!(); // newline after progress
        file.flush().await?;
    } else {
        // Stdout (original behavior)
        let mut buf = vec![0u8; 64 * 1024];
        let mut out = tokio::io::stdout();
        loop {
            match recv.read(&mut buf).await? {
                None => break,
                Some(n) => out.write_all(&buf[..n]).await?,
            }
        }
        out.flush().await?;
    }

    Ok(())
}

// --- CLI ---

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("serve") => {
            let dir = args.get(2).context("usage: quic serve <dir>")?;
            let addr: SocketAddr = format!("0.0.0.0:{}", DEFAULT_PORT).parse()?;
            serve(Path::new(dir), addr).await
        }
        Some("get") => {
            // Parse optional -c flag
            let rest = &args[2..];
            let resume = rest.contains(&"-c".to_string());
            let url = rest
                .iter()
                .find(|a| a.starts_with("http"))
                .context("usage: quic get [-c] <url>")?;
            get(url, resume).await
        }
        _ => {
            eprintln!("usage:\n  quic serve <dir>\n  quic get [-c] <url>");
            std::process::exit(1);
        }
    }
}
