use tracing_subscriber::{fmt, EnvFilter};

pub fn init(level: &str, format: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        "pretty" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .pretty()
                .init();
        }
        _ => {
            // Default: JSON
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
    }
}
