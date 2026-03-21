use gatekeeper::config::Config;
use gatekeeper::logging;
use gatekeeper::proxy::{ProxyServer, ProxyState};

use arc_swap::ArcSwap;
use clap::Parser;
use std::sync::Arc;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "gatekeeper", about = "Opinionated domain-allowlist HTTP proxy")]
struct Cli {
    #[arg(long, short)]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config
    let config = Config::load(&cli.config)?;

    // Initialize logging
    logging::init(&config.logging.level, &config.logging.format);

    info!(config_path = %cli.config, "Starting gatekeeper");

    // Build initial state
    let state = ProxyState::new(config)?;
    let domain_count = state.allowlist.len();
    info!(domain_count = domain_count, "Allowlist loaded");

    let shared_state = Arc::new(ArcSwap::from(Arc::new(state)));
    let server = Arc::new(ProxyServer::new(shared_state, cli.config.clone()));

    // Set up SIGHUP handler for config reload
    let server_for_sighup = server.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "Failed to register SIGHUP handler");
                return;
            }
        };
        loop {
            sighup.recv().await;
            info!("SIGHUP received, reloading config");
            server_for_sighup.reload_config();
        }
    });

    // Run proxy
    gatekeeper::proxy::run_proxy(server).await?;

    Ok(())
}
