//! The grandfather (`docs/spec/coordinator.md`): a vault's relay and coordinator, run on its
//! always-on machine. Both are untrusted: the relay forwards traffic that is encrypted end to
//! end, and the coordinator keeps a copy of the membership log that devices check themselves.
//!
//! It keeps its files in one data directory: its endpoint's secret key (`grandfather.key`), the
//! log copy (`coordinator.db`) and, with Let's Encrypt, its certificates (`acme`).

mod coordinator;
mod relay;
mod store;

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use iroh::endpoint::{BindOpts, presets};
use iroh::{Endpoint, RelayMode, SecretKey};
use iroh_relay::server::Server;
use openvault_core::VaultId;
use openvault_net::coord::{self, Address};
use tokio::task::JoinHandle;
use tracing::{debug, info};

pub use relay::Certificate;

use crate::coordinator::Coordinator;
use crate::relay::Admitted;
use crate::store::Store;

/// The files in the data directory.
pub const KEY: &str = "grandfather.key";
pub const DATABASE: &str = "coordinator.db";
pub const ACME: &str = "acme";

/// How to start a [`Grandfather`].
#[derive(Clone, Debug)]
pub struct Config {
    pub data: PathBuf,
    /// The vault it's for: needed at the first start, and checked after.
    pub vault: Option<VaultId>,
    /// The name devices reach it by, which its address carries.
    pub hostname: String,
    /// TCP for the relay's HTTPS and UDP for the coordinator, as its address says.
    pub port: u16,
    pub certificate: Certificate,
    /// Where it listens; [`Listen::all`] outside tests.
    pub listen: Listen,
}

/// The sockets a grandfather listens on.
#[derive(Clone, Debug)]
pub struct Listen {
    /// The relay's HTTPS, on TCP.
    pub https: SocketAddr,
    /// The coordinator, on UDP: one socket per address family.
    pub coordinator: Vec<SocketAddr>,
    /// The relay's QUIC address discovery, on UDP.
    pub quic: SocketAddr,
}

impl Listen {
    /// Every interface: TCP and UDP on `port`, and UDP [`coord::QAD_PORT`].
    pub fn all(port: u16) -> Self {
        Self {
            https: (Ipv6Addr::UNSPECIFIED, port).into(),
            coordinator: vec![
                (std::net::Ipv4Addr::UNSPECIFIED, port).into(),
                (Ipv6Addr::UNSPECIFIED, port).into(),
            ],
            quic: (Ipv6Addr::UNSPECIFIED, coord::QAD_PORT).into(),
        }
    }
}

/// A running grandfather.
pub struct Grandfather {
    address: Address,
    vault: VaultId,
    coordinator: Arc<Coordinator>,
    endpoint: Endpoint,
    relay: Server,
    accepting: JoinHandle<()>,
}

impl Grandfather {
    /// Starts the coordinator and the relay. Must be called inside a multi-threaded tokio
    /// runtime.
    pub async fn start(config: Config) -> Result<Self> {
        create_dir(&config.data)?;
        let key = load_or_create_key(&config.data.join(KEY))?;
        let store = Store::open(&config.data.join(DATABASE), config.vault)?;
        let vault = store.vault();
        let coordinator = Coordinator::new(store);

        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .alpns(vec![coord::ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .transport_config(coord::transport_config())
            .clear_ip_transports();
        // A host without IPv6 still runs it, over IPv4.
        for addr in &config.listen.coordinator {
            let required = BindOpts::default().set_is_required(addr.is_ipv4());
            builder = builder.bind_addr_with_opts(*addr, required)?;
        }
        let endpoint = builder
            .bind()
            .await
            .with_context(|| format!("can't listen on {:?}", config.listen.coordinator))?;
        let id = *endpoint.id().as_bytes();

        let relay = relay::spawn(
            config.listen.https,
            config.listen.quic,
            &config.certificate,
            Admitted {
                coordinator: id,
                members: coordinator.members(),
            },
        )
        .await?;

        let accepting = tokio::spawn(accept(endpoint.clone(), coordinator.clone()));
        let address = Address {
            endpoint: id,
            hostname: config.hostname,
            port: config.port,
        };
        info!(vault = %vault, "grandfather running; its address is {address}");
        Ok(Self {
            address,
            vault,
            coordinator,
            endpoint,
            relay,
            accepting,
        })
    }

    /// The address devices are given.
    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn vault(&self) -> VaultId {
        self.vault
    }

    /// The `seq` of the last entry in the coordinator's log copy, if it has one.
    pub fn log_head(&self) -> Option<u64> {
        self.coordinator.head().map(|(seq, _)| seq)
    }

    /// Where the relay's HTTPS listens.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.relay.https_addr()
    }

    /// Where the relay's QUIC address discovery listens.
    pub fn quic_addr(&self) -> Option<SocketAddr> {
        self.relay.quic_addr()
    }

    /// Where the coordinator listens.
    pub fn coordinator_addrs(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Stops the coordinator and the relay.
    pub async fn shutdown(self) {
        self.accepting.abort();
        self.endpoint.close().await;
        if let Err(e) = self.relay.shutdown().await {
            debug!("the relay stopped with an error: {e}");
        }
    }
}

/// Serves connections until the endpoint closes.
async fn accept(endpoint: Endpoint, coordinator: Arc<Coordinator>) {
    while let Some(incoming) = endpoint.accept().await {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) if connection.alpn() == coord::ALPN => {
                    coordinator.serve(connection).await;
                }
                Ok(connection) => connection.close(0u32.into(), b"unknown protocol"),
                Err(e) => debug!("an incoming connection failed: {e}"),
            }
        });
    }
}

/// Creates the data directory, readable only by this user.
fn create_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(path)
        .with_context(|| format!("can't create {}", path.display()))
}

/// The endpoint's secret key, created at the first start.
fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        Ok(mut file) => {
            let seed = openvault_crypto::random_bytes::<32>();
            file.write_all(&*seed)?;
            file.sync_all()?;
            Ok(SecretKey::from_bytes(&seed))
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            let mut seed = zeroize::Zeroizing::new([0; 32]);
            let mut file = fs::File::open(path)?;
            file.read_exact(&mut *seed)
                .with_context(|| format!("{} isn't a key", path.display()))?;
            Ok(SecretKey::from_bytes(&seed))
        }
        Err(e) => Err(e).with_context(|| format!("can't create {}", path.display())),
    }
}
