#[cfg(not(debug_assertions))]
use std::fs::File;

use crate::{
    api::{
        add_participant, create_decrypt_request, delete_participant, encrypt, get_decrypt_request,
        health, register, submit_signature,
    },
    config::ServerConfig,
    tracer::{init_tracer, TracingConfig},
};
use axum::{
    routing::{delete, get, post},
    Router,
};

#[cfg(not(debug_assertions))]
use axum_server::tls_rustls::RustlsConfig;
#[cfg(not(debug_assertions))]
use rustls::{
    pki_types::CertificateDer, server::WebPkiClientVerifier, RootCertStore,
    ServerConfig as RustlsServerConfig,
};

#[cfg(not(debug_assertions))]
use rustls_pemfile::{certs, pkcs8_private_keys};
#[cfg(not(debug_assertions))]
use std::{
    env,
    io::{BufReader, Cursor},
};
use tower_http::trace::TraceLayer;

pub mod api;
pub mod config;
pub mod db;
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

    // Initialize SQLite database
    let db_pool = db::init_db().await?;
    tracing::info!("Database initialized successfully");

    tracing::info!("Data store initialized");

    tracing::info!("Building router");
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/register", post(register))
        .route("/v1/add_participant", post(add_participant))
        .route("/v1/delete_participant", delete(delete_participant))
        .route("/v1/encrypt", post(encrypt))
        .route("/v1/create_decrypt_request", post(create_decrypt_request))
        .route("/v1/decrypt_request/{id}", get(get_decrypt_request))
        .route("/v1/decrypt_request/{id}/signatures", post(submit_signature))
        .layer(TraceLayer::new_for_http())
        .with_state(db_pool);

    let addr = format!("{}:{}", config.host, config.port);
    let socket_addr: std::net::SocketAddr = addr.parse()?;

    let handle = axum_server::Handle::new();

    let handle_shutdown = handle.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl+c");
        tracing::info!("Received shutdown signal");
        handle_shutdown.shutdown();
    });

    #[cfg(not(debug_assertions))]
    {
        // Release build: Full mTLS with client certificate verification
        tracing::info!("Release mode: Configuring mTLS");

        let ca_cert: Vec<CertificateDer> = if let Ok(cert_content) = env::var("CA_CERT") {
            tracing::info!("Reading CA certificate from environment variable");
            let cert_normalized = normalize_cert(cert_content);

            certs(&mut Cursor::new(cert_normalized.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("Failed to read CA certificate: {}", e))?
        } else {
            certs(&mut BufReader::new(File::open("ca.crt")?))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("Failed to read CA certificate: {}", e))?
        };

        tracing::info!("CA certificate read successfully");

        let server_cert: Vec<CertificateDer> = if let Ok(cert_content) = env::var("SERVER_CERT") {
            tracing::info!("Reading server certificate from environment variable");
            let cert_normalized = normalize_cert(cert_content);
            certs(&mut Cursor::new(cert_normalized.as_bytes()))
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
            tracing::info!("Reading server key from environment variable");
            let key_normalized = normalize_cert(key_content);

            let x = pkcs8_private_keys(&mut Cursor::new(key_normalized.as_bytes()))
                .next()
                .ok_or_else(|| anyhow::anyhow!("No private key found"))??;
            x
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

        tracing::info!(address = %addr, "Starting HTTPS server with mTLS");

        axum_server::bind_rustls(socket_addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    }

    #[cfg(debug_assertions)]
    {
        // Debug build: Plain HTTP server (no TLS)
        tracing::info!(address = %addr, "Starting HTTP server (debug mode - no TLS)");

        axum_server::bind(socket_addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    }

    tracing::info!("Server shutdown complete");
    Ok(())
}
fn normalize_cert(content: String) -> String {
    if !content.contains('\n') {
        let headers = [
            (
                "-----BEGIN CERTIFICATE----- ",
                "-----BEGIN CERTIFICATE-----\n",
            ),
            (
                "-----BEGIN PRIVATE KEY----- ",
                "-----BEGIN PRIVATE KEY-----\n",
            ),
            (
                "-----BEGIN RSA PRIVATE KEY----- ",
                "-----BEGIN RSA PRIVATE KEY-----\n",
            ),
            (
                "-----BEGIN EC PRIVATE KEY----- ",
                "-----BEGIN EC PRIVATE KEY-----\n",
            ),
            (
                "-----BEGIN ENCRYPTED PRIVATE KEY----- ",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
            ),
        ];

        let footers = [
            (
                " -----END CERTIFICATE-----",
                "\n-----END CERTIFICATE-----\n",
            ),
            (
                " -----END PRIVATE KEY-----",
                "\n-----END PRIVATE KEY-----\n",
            ),
            (
                " -----END RSA PRIVATE KEY-----",
                "\n-----END RSA PRIVATE KEY-----\n",
            ),
            (
                " -----END EC PRIVATE KEY-----",
                "\n-----END EC PRIVATE KEY-----\n",
            ),
            (
                " -----END ENCRYPTED PRIVATE KEY-----",
                "\n-----END ENCRYPTED PRIVATE KEY-----\n",
            ),
        ];

        let fixes = [
            (
                "-----BEGIN\nCERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----",
            ),
            ("-----END\nCERTIFICATE-----", "-----END CERTIFICATE-----"),
            (
                "-----BEGIN\nPRIVATE\nKEY-----",
                "-----BEGIN PRIVATE KEY-----",
            ),
            ("-----END\nPRIVATE\nKEY-----", "-----END PRIVATE KEY-----"),
            (
                "-----BEGIN\nRSA\nPRIVATE\nKEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
            ),
            (
                "-----END\nRSA\nPRIVATE\nKEY-----",
                "-----END RSA PRIVATE KEY-----",
            ),
            (
                "-----BEGIN\nEC\nPRIVATE\nKEY-----",
                "-----BEGIN EC PRIVATE KEY-----",
            ),
            (
                "-----END\nEC\nPRIVATE\nKEY-----",
                "-----END EC PRIVATE KEY-----",
            ),
            (
                "-----BEGIN\nENCRYPTED\nPRIVATE\nKEY-----",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            ),
            (
                "-----END\nENCRYPTED\nPRIVATE\nKEY-----",
                "-----END ENCRYPTED PRIVATE KEY-----",
            ),
        ];

        let mut normalized = content.clone();

        for (search, replace) in &headers {
            normalized = normalized.replace(search, replace);
        }

        for (search, replace) in &footers {
            normalized = normalized.replace(search, replace);
        }

        normalized = normalized.split_whitespace().collect::<Vec<_>>().join("\n");

        for (search, replace) in &fixes {
            normalized = normalized.replace(search, replace);
        }

        normalized
    } else {
        content
    }
}
