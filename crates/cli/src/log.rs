//! The log of the commands that run for long, `pinkvault service` and `pinkvault grandfather`.

use std::fmt;
use std::io;

use tracing::field::{Field, Visit};
use tracing::{Event, Metadata};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Filter};

/// Where iroh-relay logs each HTTPS connection that failed.
const RELAY_HTTP: &str = "iroh_relay::server::http_server";
const CONNECTION_FAILED: &str = "failed to handle connection";

/// Sends the log to stderr, filtered by `PINKVAULT_LOG` or else by `default` and without the
/// relay's connection errors.
pub(crate) fn to_stderr(default: &str) {
    use tracing_subscriber::filter::FilterExt as _;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Layer, fmt};

    let variable = log_variable(|name| std::env::var_os(name).is_some());
    let (filter, quiet) = match EnvFilter::try_from_env(variable) {
        Ok(filter) => (filter, false),
        Err(_) => (EnvFilter::new(default), true),
    };
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(io::stderr)
                .with_target(false)
                .with_filter(filter.and(QuietConnectionErrors { quiet })),
        )
        // Starts mDNS again when it stops, whatever PINKVAULT_LOG leaves out (service.md).
        .with(pinkvault_net::discovery_watch())
        .init();
}

/// The log's variable: `PINKVAULT_LOG`, or else the first of its old names that `is_set`, 0.6's
/// and then openvault's, still read for one release.
fn log_variable(is_set: impl Fn(&str) -> bool) -> &'static str {
    ["PINKVAULT_LOG", "LATEM_VAULT_LOG", "OPENVAULT_LOG"]
        .into_iter()
        .find(|name| is_set(name))
        .unwrap_or("PINKVAULT_LOG")
}

/// Leaves out iroh-relay's error for each HTTPS connection that failed, when `quiet`. On a
/// grandfather's public port they come from scanners and from handshakes that end early, Let's
/// Encrypt's among them: dozens an hour, and none from the relay itself (coordinator.md, relay).
/// `PINKVAULT_LOG` shows them again.
struct QuietConnectionErrors {
    quiet: bool,
}

impl<S> Filter<S> for QuietConnectionErrors {
    fn enabled(&self, _: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        true
    }

    // It leaves the levels to the other filter.
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn event_enabled(&self, event: &Event<'_>, _: &Context<'_, S>) -> bool {
        if !self.quiet || event.metadata().target() != RELAY_HTTP {
            return true;
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        message.0 != CONNECTION_FAILED
    }
}

/// An event's message, as it was formatted.
struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tracing::Subscriber;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[test]
    fn the_old_log_variables_are_still_read() {
        let set = |names: &'static [&'static str]| move |name: &str| names.contains(&name);
        assert_eq!(log_variable(set(&[])), "PINKVAULT_LOG");
        assert_eq!(log_variable(set(&["OPENVAULT_LOG"])), "OPENVAULT_LOG");
        assert_eq!(
            log_variable(set(&["OPENVAULT_LOG", "LATEM_VAULT_LOG"])),
            "LATEM_VAULT_LOG"
        );
        assert_eq!(
            log_variable(set(&["OPENVAULT_LOG", "LATEM_VAULT_LOG", "PINKVAULT_LOG"])),
            "PINKVAULT_LOG"
        );
    }

    struct Count(Arc<AtomicUsize>);

    impl<S: Subscriber> Layer<S> for Count {
        fn on_event(&self, _: &Event<'_>, _: Context<'_, S>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Logs a failed connection, a line after it, another relay error and an error from elsewhere,
    /// twice, and returns how many got through.
    fn logged(quiet: bool) -> usize {
        use tracing_subscriber::EnvFilter;
        use tracing_subscriber::filter::FilterExt as _;

        // As to_stderr puts them together.
        let count = Arc::new(AtomicUsize::new(0));
        let filter = EnvFilter::new("info,iroh_relay=warn").and(QuietConnectionErrors { quiet });
        let subscriber = tracing_subscriber::registry()
            .with(Count(count.clone()).with_filter(filter))
            .with(pinkvault_net::discovery_watch());
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..2 {
                tracing::error!(target: RELAY_HTTP, error = "tls handshake eof", "{CONNECTION_FAILED}");
                tracing::info!(target: "pinkvault", "the log is at entry 24");
                tracing::error!(target: RELAY_HTTP, "failed to accept connection: too many open files");
                tracing::error!(target: "pinkvault", "{CONNECTION_FAILED}");
            }
        });
        count.load(Ordering::Relaxed)
    }

    #[test]
    fn only_the_relays_failed_connections_are_left_out() {
        assert_eq!(logged(true), 6);
        assert_eq!(logged(false), 8);
    }
}
