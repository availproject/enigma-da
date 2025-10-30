use std::fs::File;

use crate::{
    api::{decrypt, encrypt, health, quote},
    config::ServerConfig,
    tracer::{TracingConfig, init_tracer},
};
use axum::{
    Router,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::{
    RootCertStore, ServerConfig as RustlsServerConfig, pki_types::CertificateDer,
    server::WebPkiClientVerifier,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{
    env,
    io::{BufReader, Cursor},
};
use tower_http::trace::TraceLayer;

pub mod api;
pub mod config;
pub mod error;
pub mod tracer;
pub mod types;
pub mod utils;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install default crypto provider"))?;

    init_tracer(TracingConfig::default());
    tracing::info!("Starting encryption server and services...");

    let config = ServerConfig::from_env();

    tracing::info!("Data store initialized");

    let ca_cert: Vec<CertificateDer> = if let Ok(cert_content) = env::var("CA_CERT") {
        tracing::info!(
            "Reading CA certificate from environment variable {}",
            cert_content
        );
        certs(&mut Cursor::new(cert_content.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to read CA certificate: {}", e))?
    } else {
        certs(&mut BufReader::new(File::open("ca.crt")?))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to read CA certificate: {}", e))?
    };

    tracing::info!(
        "CA certificate read successfully with length: {}",
        ca_cert.len()
    );

    let server_cert: Vec<CertificateDer> = if let Ok(cert_content) = env::var("SERVER_CERT") {
        tracing::info!(
            "Reading server certificate from environment variable {}",
            cert_content
        );
        certs(&mut Cursor::new(cert_content.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to read server certificate: {}", e))?
    } else {
        certs(&mut BufReader::new(File::open("server.crt")?))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to read server certificate: {}", e))?
    };

    tracing::info!(
        "Server certificate read successfully with length: {}",
        server_cert.len()
    );

    let server_key = if let Ok(key_content) = env::var("SERVER_KEY") {
        tracing::info!(
            "Reading server key from environment variable {}",
            key_content
        );
        pkcs8_private_keys(&mut Cursor::new(key_content.as_bytes()))
            .next()
            .ok_or_else(|| anyhow::anyhow!("No private key found"))??
    } else {
        pkcs8_private_keys(&mut BufReader::new(File::open("server.key")?))
            .next()
            .ok_or_else(|| anyhow::anyhow!("No private key found"))??
    };

    tracing::info!("Server key read successfully");

    let mut root_store = RootCertStore::empty();
    tracing::info!("Adding CA certificates to root store");
    for cert in ca_cert {
        root_store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("Failed to add CA certificate: {}", e))?;
    }

    tracing::info!(
        "Root store built successfully with length: {}",
        root_store.len()
    );

    let client_auth = WebPkiClientVerifier::builder(root_store.into())
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build client auth: {}", e))?;

    tracing::info!("Building server config");
    let rustls_server_config = RustlsServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(server_cert, server_key.into())
        .map_err(|e| anyhow::anyhow!("Failed to build server config: {}", e))?;

    tracing::info!("Building Rustls config");
    let rustls_config = RustlsConfig::from_config(std::sync::Arc::new(rustls_server_config));

    tracing::info!("Building router");
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/encrypt", post(encrypt))
        .route("/v1/decrypt", post(decrypt))
        .route("/v1/quote", get(quote))
        .layer(TraceLayer::new_for_http());

    let addr = format!("{}:{}", config.host, config.port);
    let socket_addr: std::net::SocketAddr = addr.parse()?;

    tracing::info!(address = %addr, "Encryption server listening");

    let handle = axum_server::Handle::new();

    let handle_shutdown = handle.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl+c");
        tracing::info!("Received shutdown signal");
        handle_shutdown.shutdown();
    });

    axum_server::bind_rustls(socket_addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}
