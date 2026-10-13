use anyhow::{anyhow, Context, Result};
use std::{fs::File, io::BufReader, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    crypto::aws_lc_rs,
    ServerConfig,
};
use tokio_rustls::TlsAcceptor;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response};
use hyper::service::service_fn;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let f = File::open(path).with_context(|| format!("open certs: {path}"))?;
    let mut reader = BufReader::new(f);
    // rustls_pemfile::certs returns an iterator of Result<CertificateDer, io::Error>,
    // so collect into a Result<Vec<_>, _> first and map errors.
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("parse certs: {e:?}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certs found in {path}"));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let f = File::open(path).map_err(|e| anyhow!("No file found at {path}: {e:?}"))?;
    let mut reader = BufReader::new(f);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| anyhow!("parse key: {e:?}"))?
        .ok_or_else(|| anyhow!("no private key found in {path}"))?;
    Ok(key)
}

fn make_server_config(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> anyhow::Result<ServerConfig> {
    let mut provider = aws_lc_rs::default_provider();

    provider.cipher_suites = vec![
        aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = vec![
        aws_lc_rs::kx_group::SECP256R1,
    ];

    let provider = Arc::new(provider);

    let cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(cfg)
}

async fn handle(_req: Request<hyper::body::Incoming>)
    -> Result<Response<Full<Bytes>>, hyper::Error>
{
    let body = Full::new(Bytes::from("CIAO SONO IL SERVER HTTP\n"));
    Ok(Response::new(body))
}


#[tokio::main]
async fn main() -> Result<()> {
    // Usage: server <bind_addr> <cert_pem> <key_pem>
    let args: Vec<String> = std::env::args().collect();
    let bind_addr = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1:8443");
    let cert_path = args.get(2).map(|s| s.as_str()).unwrap_or("certs/cert.pem");
    let key_path = args.get(3).map(|s| s.as_str()).unwrap_or("certs/key.pem");

    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let config = make_server_config(certs, key)?;



    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(bind_addr).await?;
    eprintln!("TLS server listening on {bind_addr}");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("handshake failed from {peer}: {e}");
                    return;
                }
            };

            let io = TokioIo::new(tls);
            let svc = service_fn(handle);
            eprintln!("TLS handshake completed with {peer}");

            // Serve HTTP over the TLS connection
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                eprintln!("Error serving connection from {peer}: {err}");
            } else {
                eprintln!("Successfully served connection from {peer}");
            }

        });
    }
}
