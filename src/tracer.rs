use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

#[derive(Debug, Clone)]
pub struct TracingConfig {
    pub log_level: String,
    pub enable_json: bool,
    pub enable_metrics: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            enable_json: false,
            enable_metrics: true,
        }
    }
}

pub fn init_tracer(config: TracingConfig) {
    let (env_filter, effective_log_level) = match std::env::var("RUST_LOG") {
        Ok(val) => {
            eprintln!("Using RUST_LOG from environment: {}", val);
            (EnvFilter::new(&val), val)
        }
        Err(_) => {
            eprintln!("RUST_LOG not set, using default: {}", config.log_level);
            (EnvFilter::new(&config.log_level), config.log_level.clone())
        }
    };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true);

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    if config.enable_metrics {
        // Add metrics layer if needed
        tracing::info!("Metrics collection enabled");
    }

    registry.init();

    tracing::info!(
        log_level = %effective_log_level,
        enable_json = %config.enable_json,
        enable_metrics = %config.enable_metrics,
        "Tracing initialized"
    );
}
