use anyhow::{bail, Context, Result};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use std::{
    io::ErrorKind,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

const ALPN: &[u8] = b"fileq/1";
const DEFAULT_PORT: u16 = 4433;
const MAX_PATH: usize = 4096;
const USAGE: &str = "usage:\n  quic serve <dir>\n  quic get <url>\n  quic get -c <url>";

// --- CLI ---

#[derive(Debug, PartialEq)]
enum Command<'a> {
    Serve(&'a str),
    Get { url: &'a str, resume: bool },
}

fn parse_command(args: &[String]) -> Result<Command<'_>> {
    match args {
        [_, command, dir] if command == "serve" => Ok(Command::Serve(dir)),
        [_, command, url] if command == "get" => Ok(Command::Get { url, resume: false }),
        [_, command, flag, url] if command == "get" && flag == "-c" => {
            Ok(Command::Get { url, resume: true })
        }
        _ => bail!(USAGE),
    }
}

// --- TLS helpers ---

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

// --- Protocol: [u64 path_len][path][u64 offset] → [bytes until FIN] ---

async fn write_request<W: AsyncWrite + Unpin>(
    stream: &mut W,
    path: &str,
    offset: u64,
) -> Result<()> {
    let path = path.as_bytes();
    if path.len() > MAX_PATH {
        bail!("path too long");
    }
    stream.write_all(&(path.len() as u64).to_be_bytes()).await?;
    stream.write_all(path).await?;
    stream.write_all(&offset.to_be_bytes()).await?;
    Ok(())
}

async fn read_request<R: AsyncRead + Unpin>(stream: &mut R) -> Result<(String, u64)> {
    let mut number = [0; 8];
    stream.read_exact(&mut number).await?;
    let length = u64::from_be_bytes(number);
    if length > MAX_PATH as u64 {
        bail!("path too long");
    }

    let mut path = vec![0; length as usize];
    stream.read_exact(&mut path).await?;
    stream.read_exact(&mut number).await?;
    Ok((String::from_utf8(path)?, u64::from_be_bytes(number)))
}

// --- Server ---

fn relative_path(path: &str) -> Result<&Path> {
    let path = Path::new(path.trim_start_matches('/'));
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("invalid path");
    }
    Ok(path)
}

async fn send_file(mut send: SendStream, mut recv: RecvStream, root: &Path) -> Result<()> {
    let (path, offset) = read_request(&mut recv).await?;
    let relative = relative_path(&path)?;
    let file_path = tokio::fs::canonicalize(root.join(relative))
        .await
        .context("file not found")?;
    if !file_path.starts_with(root) {
        bail!("invalid path");
    }

    let mut file = tokio::fs::File::open(&file_path).await?;
    if offset > file.metadata().await?.len() {
        bail!("resume offset exceeds file size");
    }
    if offset != 0 {
        file.seek(std::io::SeekFrom::Start(offset)).await?;
    }

    eprintln!("→ {} (byte {})", relative.display(), offset);
    tokio::io::copy(&mut file, &mut send).await?;
    send.finish()?;
    Ok(())
}

async fn serve_connection(connection: Connection, root: PathBuf) {
    while let Ok((send, recv)) = connection.accept_bi().await {
        let root = root.clone();
        tokio::spawn(async move {
            if let Err(error) = send_file(send, recv, &root).await {
                eprintln!("✗ {error:#}");
            }
        });
    }
}

async fn serve(dir: &Path, addr: SocketAddr) -> Result<()> {
    let root = tokio::fs::canonicalize(dir).await.context("bad dir")?;
    let endpoint = Endpoint::server(server_tls()?, addr)?;
    eprintln!("serving {} on {}", root.display(), addr);

    while let Some(incoming) = endpoint.accept().await {
        let root = root.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => serve_connection(connection, root).await,
                Err(error) => eprintln!("✗ {error}"),
            }
        });
    }
    Ok(())
}

// --- Client ---

async fn get(url: &str, resume: bool) -> Result<()> {
    let url = url::Url::parse(url)?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("URL must use http or https");
    }

    let host = url.host_str().context("URL has no host")?;
    let port = url.port().unwrap_or(DEFAULT_PORT);
    let path = url.path();
    let output = Path::new(path)
        .file_name()
        .map(PathBuf::from)
        .context("URL has no filename")?;

    let offset = if resume {
        match tokio::fs::metadata(&output).await {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == ErrorKind::NotFound => 0,
            Err(error) => return Err(error).context("could not inspect output file"),
        }
    } else {
        0
    };

    let addr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .context("DNS lookup failed")?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_tls()?);

    let connection = endpoint.connect(addr, host)?.await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_request(&mut send, path, offset).await?;
    send.finish()?;

    // A normal download replaces the file; -c appends from its current length.
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(resume)
        .truncate(!resume)
        .open(&output)
        .await?;
    let received = tokio::io::copy(&mut recv, &mut file).await?;
    file.flush().await?;
    eprintln!("{}: {} bytes", output.display(), offset + received);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let command = match parse_command(&args) {
        Ok(command) => command,
        Err(_) => {
            eprintln!("{USAGE}");
            std::process::exit(1);
        }
    };

    match command {
        Command::Serve(dir) => {
            serve(Path::new(dir), format!("0.0.0.0:{DEFAULT_PORT}").parse()?).await
        }
        Command::Get { url, resume } => get(url, resume).await,
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn accepts_only_public_commands() {
        let serve = args(&["quic", "serve", "dir"]);
        let get = args(&["quic", "get", "http://example.com/eee.zip"]);
        let resume = args(&["quic", "get", "-c", "http://example.com/eee.zip"]);

        assert_eq!(parse_command(&serve).unwrap(), Command::Serve("dir"));
        assert_eq!(
            parse_command(&get).unwrap(),
            Command::Get {
                url: "http://example.com/eee.zip",
                resume: false,
            }
        );
        assert_eq!(
            parse_command(&resume).unwrap(),
            Command::Get {
                url: "http://example.com/eee.zip",
                resume: true,
            }
        );
        assert!(parse_command(&args(&["quic", "get"])).is_err());
        assert!(parse_command(&args(&["quic", "get", "x", "url"])).is_err());
    }

    #[test]
    fn rejects_paths_outside_the_server_root() {
        assert_eq!(relative_path("/dir/file").unwrap(), Path::new("dir/file"));
        assert!(relative_path("/").is_err());
        assert!(relative_path("../secret").is_err());
        assert!(relative_path("dir/../secret").is_err());
    }

    #[tokio::test]
    async fn request_round_trip() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        write_request(&mut writer, "/eee.zip", 42).await.unwrap();
        drop(writer);

        assert_eq!(
            read_request(&mut reader).await.unwrap(),
            ("/eee.zip".into(), 42)
        );
    }
}
