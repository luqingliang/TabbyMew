use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::{config::TlsClientConfig, net::dns::DnsResolver, net::timeout};

pub async fn connect_tls(
    server: &str,
    server_port: u16,
    tls: &TlsClientConfig,
) -> Result<TlsStream<TcpStream>> {
    connect_tls_with_dns(server, server_port, tls, None).await
}

pub async fn connect_tls_with_dns(
    server: &str,
    server_port: u16,
    tls: &TlsClientConfig,
    dns: Option<&DnsResolver>,
) -> Result<TlsStream<TcpStream>> {
    let tcp = timeout::connect_tcp_with_dns(
        server,
        server_port,
        dns,
        &format!("connecting TLS server {server}:{server_port}"),
    )
    .await?;

    connect_tls_over_stream(tcp, server, tls).await
}

pub async fn connect_tls_over_stream<S>(
    stream: S,
    server: &str,
    tls: &TlsClientConfig,
) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut config = if tls.insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = tls
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = tls.server_name.as_deref().unwrap_or(server).to_string();
    let server_name_value = server_name.clone();
    let server_name = ServerName::try_from(server_name).context("invalid TLS server name")?;

    timeout::with_handshake_timeout(&format!("TLS handshake with {server_name_value}"), async {
        connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")
    })
    .await
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
