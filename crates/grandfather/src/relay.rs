//! The grandfather's relay (coordinator.md, relay): iroh's relay server in this process, which
//! admits the vault's members and the coordinator, and nobody else.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context as _;
use iroh_relay::server::{
    Access, AccessControl, AcmeConfig, CertConfig, ClientRequest, RelayConfig, Server,
    ServerConfig, TlsConfig, reloading_resolver,
};
use openvault_net::EndpointKey;
use tracing::debug;

/// How often certificate files are read again (coordinator.md, TLS).
const RELOAD: Duration = Duration::from_secs(60 * 60);

/// Where the relay's certificate comes from.
#[derive(Clone, Debug)]
pub enum Certificate {
    /// Let's Encrypt, answering its challenge on the HTTPS port. Certificates are kept in
    /// `cache`.
    LetsEncrypt { hostname: String, cache: PathBuf },
    /// PEM files, read again every hour.
    Files { cert: PathBuf, key: PathBuf },
}

/// Who the relay admits: the members in the coordinator's log copy, by transport key, and the
/// coordinator's own endpoint.
#[derive(Debug)]
pub(crate) struct Admitted {
    pub(crate) coordinator: EndpointKey,
    pub(crate) members: Arc<RwLock<HashSet<EndpointKey>>>,
}

impl AccessControl for Admitted {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let key = *request.endpoint_id().as_bytes();
        if key == self.coordinator || self.members.read().expect("poisoned").contains(&key) {
            Access::Allow
        } else {
            debug!("the relay refused {}", request.endpoint_id().fmt_short());
            Access::Deny {
                reason: Some("not a member of this vault".into()),
            }
        }
    }
}

/// Starts the relay: HTTPS on `https`, with no QUIC address discovery (coordinator.md, relay).
pub(crate) async fn spawn(
    https: SocketAddr,
    certificate: &Certificate,
    admitted: Admitted,
) -> anyhow::Result<Server> {
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocols ring supports")
    .with_no_client_auth();
    let cert = match certificate {
        Certificate::LetsEncrypt { hostname, cache } => CertConfig::LetsEncrypt {
            acme_config: AcmeConfig::letsencrypt(true)
                .domains(vec![hostname.clone()])
                .cache_path(cache.clone()),
            server_config_builder: tls,
        },
        Certificate::Files { cert, key } => {
            let resolver =
                reloading_resolver(tls.crypto_provider(), cert.clone(), key.clone(), RELOAD)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))
                    .with_context(|| {
                        format!(
                            "can't read the certificate in {} and its key in {}",
                            cert.display(),
                            key.display()
                        )
                    })?;
            CertConfig::Manual {
                server_config: tls.with_cert_resolver(resolver),
            }
        }
    };
    // The plain-HTTP side, for captive-portal checks, stays on this machine (coordinator.md,
    // relay).
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls = Some(TlsConfig::new(https, cert));
    relay.access = Arc::new(admitted);
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    config.metrics_addr = None;
    Server::spawn(config)
        .await
        .with_context(|| format!("can't start the relay on {https}"))
}
