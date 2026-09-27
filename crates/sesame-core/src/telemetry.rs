// SPDX-License-Identifier: Apache-2.0
//! Logs structurés JSON sur stdout. L'export OpenTelemetry viendra s'y greffer.

use tracing_subscriber::EnvFilter;

/// Initialise les logs JSON ; niveau réglable par `RUST_LOG` (défaut : `info`).
pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_env_filter(filter)
        .init();
}
