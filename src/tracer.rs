use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, fmt::format::FmtSpan};

#[derive(Debug, Clone)]
pub struct TracingConfig {
    pub service_name: String,
    pub env_filter: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        TracingConfig {
            service_name: "encryption_server".to_string(),
            env_filter: "encryption_server=debug,tower_http=debug".to_string(),
        }
    }
}

/// Initialize a global tracer with JSON formatting and spans
pub fn init_tracer(config: TracingConfig) {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| config.env_filter.into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                .with_file(true)
                .with_line_number(true)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_ansi(false)
        )
        .init();
}