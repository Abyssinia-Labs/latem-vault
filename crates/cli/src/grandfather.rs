//! `latem-vault grandfather`, and `latem-vault coordinator [set|unset]` on devices
//! (coordinator.md, running the grandfather and devices).

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use latem_vault_core::{Vault, VaultId};
use latem_vault_net::coord::{self, Address};
use latem_vault_service::{COORDINATOR, configured_coordinator};

use crate::Home;

#[derive(clap::Args)]
pub struct Args {
    /// The name devices reach this machine by. It must resolve to the home connection's public
    /// address, and the router must forward the port, TCP and UDP, to this machine
    #[arg(long)]
    hostname: String,
    /// The vault it's for, as `latem-vault init` showed it; needed the first time [default: this
    /// device's vault, if it has one]
    #[arg(long)]
    vault: Option<String>,
    /// TCP for the relay's HTTPS, and UDP for the coordinator. Without --cert, Let's Encrypt
    /// needs it to be 443 as seen from outside
    #[arg(long, default_value_t = coord::DEFAULT_PORT)]
    port: u16,
    /// Where it keeps its files [default: grandfather in the vault directory]
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
    use latem_vault_grandfather::{ACME, Certificate, Config, Grandfather, Listen};
    use tokio::signal::unix::{SignalKind, signal};

    if !coord::is_hostname(&args.hostname) {
        bail!("{} isn't a hostname", args.hostname);
    }
    let vault = match &args.vault {
        Some(id) => Some(
            id.parse::<VaultId>()
                .with_context(|| format!("{id} isn't a vault id"))?,
        ),
        None => Vault::<latem_vault_keystore::Keys>::id_at(&home.vault()).ok(),
    };
    let data = args.data.unwrap_or_else(|| home.0.join("grandfather"));
    let certificate = match (args.cert, args.key) {
        (Some(cert), Some(key)) => Certificate::Files { cert, key },
        _ => Certificate::LetsEncrypt {
            hostname: args.hostname.clone(),
            cache: data.join(ACME),
        },
    };
    crate::log::to_stderr("info,iroh=warn,iroh_relay=warn,rustls=warn,tokio_rustls_acme=warn");
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
                "Give the vault's devices this address with `latem-vault coordinator set`:\n  {}",
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
    bail!("`latem-vault grandfather` doesn't run on Windows yet")
}

/// Shows the coordinator this device uses, or how to get one.
pub fn show(home: &Home) -> Result<()> {
    home.require_vault()?;
    match configured_coordinator(&home.0)? {
        Some(address) => {
            println!("{address}");
            println!(
                "The service uses the relay at {}, and exchanges with its coordinator when the \
                 log changes and every 15 minutes.",
                address.hostname
            );
        }
        None => {
            let vault = Vault::<latem_vault_keystore::Keys>::id_at(&home.vault())?;
            println!(
                "None: this device finds the vault's other devices on the local network only."
            );
            println!(
                "To reach them away from home, run `latem-vault grandfather --vault {vault} \
                 --hostname <name>` on the vault's always-on machine, then `latem-vault coordinator \
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
    if latem_vault_service::client::is_running(&home.0.join(latem_vault_service::SOCKET)) {
        println!(
            "The service takes this up when it starts again: `latem-vault service install` \
             restarts it if it's installed."
        );
    }
}
