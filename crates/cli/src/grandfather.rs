//! `openvault grandfather`, and `openvault coordinator [set|unset]` on devices
//! (coordinator.md, running the grandfather and devices).

use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use openvault_core::{Vault, VaultId};
use openvault_net::coord::{self, Address};
use openvault_service::{COORDINATOR, configured_coordinator};
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Filter};

use crate::Home;

/// Where iroh-relay logs each HTTPS connection that failed.
const RELAY_HTTP: &str = "iroh_relay::server::http_server";
const CONNECTION_FAILED: &str = "failed to handle connection";

#[derive(clap::Args)]
pub struct Args {
    /// The name devices reach this machine by. It must resolve to the home connection's public
    /// address, and the router must forward the port, TCP and UDP, to this machine
    #[arg(long)]
    hostname: String,
    /// The vault it's for, as `openvault init` showed it; needed the first time [default: this
    /// device's vault, if it has one]
    #[arg(long)]
    vault: Option<String>,
    /// TCP for the relay's HTTPS, and UDP for the coordinator. Without --cert, Let's Encrypt
    /// needs it to be 443 as seen from outside
    #[arg(long, default_value_t = coord::DEFAULT_PORT)]
    port: u16,
    /// Where it keeps its files [default: grandfather in the openvault directory]
    #[arg(long)]
    data: Option<PathBuf>,
    /// A PEM certificate for the hostname, instead of one from Let's Encrypt. It's read again
    /// every hour
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    /// The PEM private key of --cert
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
}

/// Runs the grandfather until Ctrl-C or SIGTERM.
#[cfg(unix)]
pub fn run(home: &Home, args: Args) -> Result<()> {
    use openvault_grandfather::{ACME, Certificate, Config, Grandfather, Listen};
    use tokio::signal::unix::{SignalKind, signal};

    if !coord::is_hostname(&args.hostname) {
        bail!("{} isn't a hostname", args.hostname);
    }
    let vault = match &args.vault {
        Some(id) => Some(
            id.parse::<VaultId>()
                .with_context(|| format!("{id} isn't a vault id"))?,
        ),
        None => Vault::<openvault_keystore::Keys>::id_at(&home.vault()).ok(),
    };
    let data = args.data.unwrap_or_else(|| home.0.join("grandfather"));
    let certificate = match (args.cert, args.key) {
        (Some(cert), Some(key)) => Certificate::Files { cert, key },
        _ => Certificate::LetsEncrypt {
            hostname: args.hostname.clone(),
            cache: data.join(ACME),
        },
    };
    crate::log_to_stderr("info,iroh=warn,iroh_relay=warn,rustls=warn,tokio_rustls_acme=warn");
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let grandfather = Grandfather::start(Config {
                data,
                vault,
                hostname: args.hostname,
                port: args.port,
                certificate,
                listen: Listen::all(args.port),
            })
            .await?;
            println!(
                "Give the vault's devices this address with `openvault coordinator set`:\n  {}",
                grandfather.address()
            );
            let mut terminate = signal(SignalKind::terminate())?;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            grandfather.shutdown().await;
            Ok(())
        })
}

#[cfg(not(unix))]
pub fn run(_: &Home, _: Args) -> Result<()> {
    bail!("`openvault grandfather` doesn't run on Windows yet")
}

/// Leaves out iroh-relay's error for each HTTPS connection that failed, when `quiet`. On a public
/// port they come from scanners and from handshakes that end early, Let's Encrypt's among them:
/// dozens an hour, and none from the relay itself (coordinator.md, relay). `OPENVAULT_LOG` shows
/// them again.
pub(crate) struct QuietConnectionErrors {
    pub(crate) quiet: bool,
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

/// Shows the coordinator this device uses, or how to get one.
pub fn show(home: &Home) -> Result<()> {
    home.require_vault()?;
    match configured_coordinator(&home.0)? {
        Some(address) => {
            println!("{address}");
            println!(
                "The service uses the relay at {} and keeps a connection to its coordinator.",
                address.hostname
            );
        }
        None => {
            let vault = Vault::<openvault_keystore::Keys>::id_at(&home.vault())?;
            println!(
                "None: this device finds the vault's other devices on the local network only."
            );
            println!(
                "To reach them away from home, run `openvault grandfather --vault {vault} \
                 --hostname <name>` on the vault's always-on machine, then `openvault coordinator \
                 set <the address it shows>` here."
            );
        }
    }
    Ok(())
}

pub fn set(home: &Home, address: &str) -> Result<()> {
    home.require_vault()?;
    let address: Address = address.parse()?;
    fs::write(home.0.join(COORDINATOR), format!("{address}\n"))?;
    println!(
        "This device now uses the grandfather at {}: its relay, and its coordinator.",
        address.hostname
    );
    restart_note(home);
    Ok(())
}

pub fn unset(home: &Home) -> Result<()> {
    home.require_vault()?;
    match fs::remove_file(home.0.join(COORDINATOR)) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => bail!("this device has no coordinator set"),
        Err(e) => return Err(e.into()),
    }
    println!("This device now finds the vault's other devices on the local network only.");
    restart_note(home);
    Ok(())
}

/// A running service reads the setting when it starts.
fn restart_note(home: &Home) {
    #[cfg(unix)]
    if openvault_service::client::is_running(&home.0.join(openvault_service::SOCKET)) {
        println!(
            "The service takes this up when it starts again: `openvault service install` \
             restarts it if it's installed."
        );
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

        // As log_to_stderr puts them together.
        let count = Arc::new(AtomicUsize::new(0));
        let filter = EnvFilter::new("info,iroh_relay=warn").and(QuietConnectionErrors { quiet });
        let subscriber = tracing_subscriber::registry()
            .with(Count(count.clone()).with_filter(filter))
            .with(openvault_net::discovery_watch());
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..2 {
                tracing::error!(target: RELAY_HTTP, error = "tls handshake eof", "{CONNECTION_FAILED}");
                tracing::info!(target: "openvault", "the log is at entry 24");
                tracing::error!(target: RELAY_HTTP, "failed to accept connection: too many open files");
                tracing::error!(target: "openvault", "{CONNECTION_FAILED}");
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
