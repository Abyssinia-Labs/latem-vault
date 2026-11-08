//! A device's iroh endpoint, and how it finds the vault's other devices (`docs/spec/service.md`).
//!
//! The endpoint uses no relay, no DNS or pkarr publishing and no port mapping, so nothing
//! outside the local network learns its id or addresses. It finds other OpenVault endpoints with
//! mDNS under its own service name; which of them are members is for the membership log to say.

pub mod frame;
pub mod join;
pub mod sync;
pub mod wire;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::endpoint_info::UserData;
pub use iroh::{Endpoint, EndpointId};
use iroh::{RelayMode, SecretKey};
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

/// How to start a [`Node`].
#[derive(Clone, Debug)]
pub struct Options {
    /// The protocols it accepts connections for. None, for an endpoint that only connects out.
    pub alpns: Vec<Vec<u8>>,
    /// Whether mDNS announces it. `approve` finds joiners without announcing itself.
    pub advertise: bool,
    /// What it announces besides its id and addresses: a joining device's platform and name.
    pub announcement: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            alpns: Vec::new(),
            advertise: true,
            announcement: None,
        }
    }
}

/// This device's endpoint, with mDNS discovery running.
pub struct Node {
    endpoint: Endpoint,
    /// What mDNS can see, with what each endpoint announces.
    visible: Arc<Mutex<BTreeMap<EndpointKey, Option<String>>>>,
    discovery: JoinHandle<()>,
}

impl Node {
    /// Binds the endpoint with `seed` as its Ed25519 secret key (records.md, local store) and
    /// starts mDNS. Changes in what it can see arrive on the returned receiver.
    ///
    /// Must be called inside a tokio runtime.
    pub async fn start(
        seed: &[u8; 32],
        options: Options,
    ) -> Result<(Self, mpsc::Receiver<Event>), Error> {
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(seed))
            .relay_mode(RelayMode::Disabled)
            .alpns(options.alpns);
        if let Some(announcement) = options.announcement {
            let data = UserData::try_from(announcement)
                .map_err(|_| Error::Mdns("the announcement is too long".into()))?;
            builder = builder.user_data_for_address_lookup(data);
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| Error::Bind(e.to_string()))?;
        let mdns = MdnsAddressLookup::builder()
            .service_name(MDNS_SERVICE)
            .discovery_cadence(MDNS_CADENCE)
            .advertise(options.advertise)
            .build(endpoint.id())
            .map_err(|e| Error::Mdns(e.to_string()))?;
        // Added after binding, which publishes the endpoint's current addresses straight away.
        endpoint
            .address_lookup()
            .map_err(|e| Error::Mdns(e.to_string()))?
            .add(mdns.clone());

        let visible = Arc::new(Mutex::new(BTreeMap::new()));
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
                        let announcement = endpoint_info.data.user_data().map(|d| d.to_string());
                        // Discovered also reports changed addresses for an endpoint already seen.
                        if seen
                            .lock()
                            .expect("poisoned")
                            .insert(key, announcement)
                            .is_some()
                        {
                            continue;
                        }
                        Event::Visible(key)
                    }
                    DiscoveryEvent::Expired { endpoint_id } => {
                        let key = *endpoint_id.as_bytes();
                        if seen.lock().expect("poisoned").remove(&key).is_none() {
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
        self.visible
            .lock()
            .expect("poisoned")
            .keys()
            .copied()
            .collect()
    }

    /// The visible endpoints that announce something, with what they announce.
    pub fn announcements(&self) -> Vec<(EndpointKey, String)> {
        self.visible
            .lock()
            .expect("poisoned")
            .iter()
            .filter_map(|(key, announcement)| Some((*key, announcement.clone()?)))
            .collect()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The addresses the endpoint is bound to.
    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Stops discovery and closes the endpoint.
    pub async fn close(&self) {
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
        let (node, _events) = Node::start(&seed(7), Options::default()).await.unwrap();
        let expected = SecretKey::from_bytes(&seed(7)).public();
        assert_eq!(node.id(), *expected.as_bytes());
        node.close().await;
    }

    /// Two endpoints in one process find each other over mDNS, and one disappears when it
    /// closes. Needs a network interface that carries multicast.
    #[tokio::test(flavor = "multi_thread")]
    async fn endpoints_find_each_other() {
        let (a, mut a_events) = Node::start(&seed(1), Options::default()).await.unwrap();
        let announced = Options {
            announcement: Some("join:linux:Desktop".into()),
            ..Options::default()
        };
        let (b, mut b_events) = Node::start(&seed(2), announced).await.unwrap();
        let wait = Duration::from_secs(30);

        // Other tests' endpoints share the network, so each side waits for the one it expects.
        async fn until(events: &mut mpsc::Receiver<Event>, expected: Event, wait: Duration) {
            tokio::time::timeout(wait, async {
                while events.recv().await != Some(expected) {}
            })
            .await
            .unwrap_or_else(|_| panic!("no {expected:?}"));
        }
        until(&mut a_events, Event::Visible(b.id()), wait).await;
        until(&mut b_events, Event::Visible(a.id()), wait).await;
        assert!(a.visible().contains(&b.id()));
        assert!(
            a.announcements()
                .contains(&(b.id(), "join:linux:Desktop".to_owned()))
        );
        assert!(!b.announcements().iter().any(|(key, _)| *key == a.id()));

        let b_id = b.id();
        b.close().await;
        until(&mut a_events, Event::Gone(b_id), Duration::from_secs(120)).await;
        assert!(!a.visible().contains(&b_id));
        a.close().await;
    }
}
