//! A device's iroh endpoint, and how it finds the vault's other devices (`docs/spec/service.md`).
//!
//! The endpoint uses no relay, no DNS or pkarr publishing and no port mapping, so nothing
//! outside the local network learns its id or addresses. It finds other OpenVault endpoints with
//! mDNS under its own service name; which of them are members is for the membership log to say.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMode, SecretKey};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use n0_future::StreamExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The mDNS service name: endpoints appear as `<endpoint id>._openvault._udp.local.`.
pub const MDNS_SERVICE: &str = "openvault";

/// How often mDNS queries go out, before swarm-discovery's random delay.
const MDNS_CADENCE: Duration = Duration::from_secs(5);

/// An endpoint id: the Ed25519 public key of a device's transport key.
pub type EndpointKey = [u8; 32];

/// A change in which OpenVault endpoints mDNS can see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Visible(EndpointKey),
    Gone(EndpointKey),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("can't start the network endpoint: {0}")]
    Bind(String),
    #[error("can't start mDNS discovery: {0}")]
    Mdns(String),
}

/// This device's endpoint, with mDNS discovery running.
pub struct Node {
    endpoint: Endpoint,
    visible: Arc<Mutex<BTreeSet<EndpointKey>>>,
    discovery: JoinHandle<()>,
}

impl Node {
    /// Binds the endpoint with `seed` as its Ed25519 secret key (records.md, local store) and
    /// starts mDNS. Changes in what it can see arrive on the returned receiver.
    ///
    /// Must be called inside a tokio runtime.
    pub async fn start(seed: &[u8; 32]) -> Result<(Self, mpsc::Receiver<Event>), Error> {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(seed))
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .map_err(|e| Error::Bind(e.to_string()))?;
        let mdns = MdnsAddressLookup::builder()
            .service_name(MDNS_SERVICE)
            .discovery_cadence(MDNS_CADENCE)
            .build(endpoint.id())
            .map_err(|e| Error::Mdns(e.to_string()))?;
        // Added after binding, which publishes the endpoint's current addresses straight away.
        endpoint
            .address_lookup()
            .map_err(|e| Error::Mdns(e.to_string()))?
            .add(mdns.clone());

        let visible = Arc::new(Mutex::new(BTreeSet::new()));
        let (send, receive) = mpsc::channel(64);
        let mut events = mdns.subscribe().await;
        let seen = visible.clone();
        let discovery = tokio::spawn(async move {
            // Keeps the lookup alive for as long as the task runs.
            let _mdns = mdns;
            while let Some(event) = events.next().await {
                let event = match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        let key = *endpoint_info.endpoint_id.as_bytes();
                        // Discovered also reports changed addresses for an endpoint already seen.
                        if !seen.lock().expect("poisoned").insert(key) {
                            continue;
                        }
                        Event::Visible(key)
                    }
                    DiscoveryEvent::Expired { endpoint_id } => {
                        let key = *endpoint_id.as_bytes();
                        if !seen.lock().expect("poisoned").remove(&key) {
                            continue;
                        }
                        Event::Gone(key)
                    }
                    _ => continue,
                };
                if send.send(event).await.is_err() {
                    break;
                }
            }
        });
        Ok((
            Self {
                endpoint,
                visible,
                discovery,
            },
            receive,
        ))
    }

    /// This endpoint's id, which is the device's transport key.
    pub fn id(&self) -> EndpointKey {
        *self.endpoint.id().as_bytes()
    }

    /// The OpenVault endpoints mDNS can see now, members or not.
    pub fn visible(&self) -> BTreeSet<EndpointKey> {
        self.visible.lock().expect("poisoned").clone()
    }

    /// The addresses the endpoint is bound to.
    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Stops discovery and closes the endpoint.
    pub async fn close(self) {
        self.discovery.abort();
        self.endpoint.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_endpoint_id_is_the_transport_key() {
        let (node, _events) = Node::start(&seed(7)).await.unwrap();
        let expected = SecretKey::from_bytes(&seed(7)).public();
        assert_eq!(node.id(), *expected.as_bytes());
        node.close().await;
    }

    /// Two endpoints in one process find each other over mDNS, and one disappears when it
    /// closes. Needs a network interface that carries multicast.
    #[tokio::test(flavor = "multi_thread")]
    async fn endpoints_find_each_other() {
        let (a, mut a_events) = Node::start(&seed(1)).await.unwrap();
        let (b, mut b_events) = Node::start(&seed(2)).await.unwrap();
        let wait = Duration::from_secs(30);

        let seen = tokio::time::timeout(wait, a_events.recv()).await.unwrap();
        assert_eq!(seen, Some(Event::Visible(b.id())));
        let seen = tokio::time::timeout(wait, b_events.recv()).await.unwrap();
        assert_eq!(seen, Some(Event::Visible(a.id())));
        assert!(a.visible().contains(&b.id()));

        let b_id = b.id();
        b.close().await;
        let gone = tokio::time::timeout(Duration::from_secs(120), a_events.recv())
            .await
            .unwrap();
        assert_eq!(gone, Some(Event::Gone(b_id)));
        assert!(a.visible().is_empty());
        a.close().await;
    }
}
