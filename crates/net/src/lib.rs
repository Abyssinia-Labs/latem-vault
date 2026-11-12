//! A device's iroh endpoint, and how it finds the vault's other devices (`docs/spec/service.md`).
//!
//! The endpoint uses no DNS or pkarr publishing and no port mapping, and no relay unless the
//! device has a coordinator configured, whose grandfather's relay is then the only one it uses
//! (coordinator.md). It finds other OpenVault endpoints with mDNS under its own service name;
//! which of them are members is for the membership log to say. When mDNS stops, the node starts
//! it again ([`discovery_watch`]).

pub mod chunks;
pub mod coord;
pub mod frame;
pub mod join;
pub mod sync;
mod watch;
pub mod wire;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use iroh::endpoint::Connection;
use iroh::endpoint::{Builder, presets};
use iroh::endpoint_info::UserData;
pub use iroh::tls::CaTlsConfig;
pub use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use iroh::{NetReportConfig, RelayConfig, RelayMap, RelayMode, SecretKey};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use n0_future::StreamExt;
use n0_future::boxed::BoxStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

pub use watch::{discovery_stops, discovery_watch};

/// The mDNS service name: endpoints appear as `<endpoint id>._openvault._udp.local.`.
pub const MDNS_SERVICE: &str = "openvault";

/// How often mDNS queries go out, before swarm-discovery's random delay.
const MDNS_CADENCE: Duration = Duration::from_secs(5);

/// How long a node waits before starting mDNS again after it stops. The wait doubles each time
/// it stops again, up to [`RESTART_LONGEST`], and is back to this once mDNS has run for
/// [`RESTART_SETTLED`].
const RESTART_FIRST: Duration = Duration::from_secs(5);
const RESTART_LONGEST: Duration = Duration::from_secs(5 * 60);
const RESTART_SETTLED: Duration = Duration::from_secs(10 * 60);

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
    /// The grandfather's relay, for a device with a coordinator configured.
    pub relay: Option<Relay>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            alpns: Vec::new(),
            advertise: true,
            announcement: None,
            relay: None,
        }
    }
}

/// A relay for the endpoint to use, and no other (coordinator.md, devices).
#[derive(Clone, Debug)]
pub struct Relay {
    pub url: RelayUrl,
    /// What its certificate is checked against: the usual roots but in tests.
    pub roots: CaTlsConfig,
}

impl Relay {
    pub fn new(url: RelayUrl) -> Self {
        Self {
            url,
            roots: CaTlsConfig::default(),
        }
    }
}

/// The endpoint builder [`Node::start`] binds: `seed` as the Ed25519 secret key (records.md,
/// local store), and `options`' protocols, announcement and relay. Tests bind it themselves, to
/// take away direct paths.
pub fn builder(seed: &[u8; 32], options: &Options) -> Result<Builder, Error> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(seed))
        .alpns(options.alpns.clone());
    builder = match &options.relay {
        None => builder.relay_mode(RelayMode::Disabled),
        Some(relay) => {
            // No QUIC address discovery: iroh would keep a connection to it open from every
            // device. Its HTTPS probes, which name the home relay, stay (coordinator.md, relay).
            let config = RelayConfig::new(relay.url.clone(), None);
            // The relay's plain-HTTP side isn't reachable (coordinator.md, relay).
            let mut report = NetReportConfig::default();
            report.captive_portal_check = false;
            builder
                .relay_mode(RelayMode::Custom(RelayMap::from(config)))
                .ca_tls_config(relay.roots.clone())
                .net_report_config(report)
        }
    };
    if let Some(announcement) = &options.announcement {
        let data = UserData::try_from(announcement.clone())
            .map_err(|_| Error::Mdns("the announcement is too long".into()))?;
        builder = builder.user_data_for_address_lookup(data);
    }
    Ok(builder)
}

/// This device's endpoint, with mDNS discovery running.
pub struct Node {
    endpoint: Endpoint,
    visible: Visible,
    discovery: JoinHandle<()>,
}

impl Node {
    /// Binds the endpoint from [`builder`] and starts mDNS. Changes in what it can see arrive on
    /// the returned receiver.
    ///
    /// Must be called inside a tokio runtime.
    pub async fn start(
        seed: &[u8; 32],
        options: Options,
    ) -> Result<(Self, mpsc::Receiver<Event>), Error> {
        let endpoint = builder(seed, &options)?
            .bind()
            .await
            .map_err(|e| Error::Bind(e.to_string()))?;
        let mdns = start_mdns(&endpoint, options.advertise)?;

        let visible = Arc::new(Mutex::new(BTreeMap::new()));
        let (send, receive) = mpsc::channel(64);
        let events = mdns.subscribe().await.boxed();
        let discovery = tokio::spawn(discover(
            endpoint.clone(),
            options.advertise,
            mdns,
            events,
            visible.clone(),
            send,
        ));
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

/// What mDNS can see, with what each endpoint announces.
type Visible = Arc<Mutex<BTreeMap<EndpointKey, Option<String>>>>;

/// Starts mDNS discovery for `endpoint`, in place of any lookup it had. Its preset
/// (`presets::Minimal`) has none of its own, so the only one replaced is a stopped mDNS.
fn start_mdns(endpoint: &Endpoint, advertise: bool) -> Result<MdnsAddressLookup, Error> {
    let mdns = MdnsAddressLookup::builder()
        .service_name(MDNS_SERVICE)
        .discovery_cadence(MDNS_CADENCE)
        .advertise(advertise)
        .build(endpoint.id())
        .map_err(|e| Error::Mdns(e.to_string()))?;
    let lookups = endpoint
        .address_lookup()
        .map_err(|e| Error::Mdns(e.to_string()))?;
    lookups.clear();
    // Added after binding, which publishes the endpoint's current addresses straight away.
    lookups.add(mdns.clone());
    Ok(mdns)
}

/// Turns what mDNS finds into [`Event`]s, and starts mDNS again whenever it stops, until the
/// node closes or nobody receives the events.
async fn discover(
    endpoint: Endpoint,
    advertise: bool,
    mdns: MdnsAddressLookup,
    mut events: BoxStream<DiscoveryEvent>,
    visible: Visible,
    send: mpsc::Sender<Event>,
) {
    // Keeps the lookup alive for as long as it's the one in use.
    let mut _mdns = mdns;
    let mut stops = watch::stops();
    let mut started = Instant::now();
    let mut wait = RESTART_FIRST;
    loop {
        tokio::select! {
            event = events.next() => {
                let Some(event) = event else { return };
                if let Some(event) = change(&visible, event)
                    && send.send(event).await.is_err()
                {
                    return;
                }
            }
            Ok(()) = stops.changed() => {
                // The stopped lookup won't say who leaves, so its endpoints are gone until a new
                // one finds them again.
                let seen = std::mem::take(&mut *visible.lock().expect("poisoned"));
                for key in seen.into_keys() {
                    if send.send(Event::Gone(key)).await.is_err() {
                        return;
                    }
                }
                if started.elapsed() >= RESTART_SETTLED {
                    wait = RESTART_FIRST;
                }
                warn!("mDNS discovery stopped; starting it again in {}s", wait.as_secs());
                loop {
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(RESTART_LONGEST);
                    match start_mdns(&endpoint, advertise) {
                        Ok(mdns) => {
                            events = mdns.subscribe().await.boxed();
                            _mdns = mdns;
                            break;
                        }
                        Err(e) => warn!("{e}; trying again in {}s", wait.as_secs()),
                    }
                }
                // A stop counted while waiting was this one.
                stops.mark_unchanged();
                started = Instant::now();
                info!("mDNS discovery started again");
            }
        }
    }
}

/// The event that a change in what mDNS sees makes, if any.
fn change(visible: &Visible, event: DiscoveryEvent) -> Option<Event> {
    match event {
        DiscoveryEvent::Discovered { endpoint_info, .. } => {
            let key = *endpoint_info.endpoint_id.as_bytes();
            let announcement = endpoint_info.data.user_data().map(|d| d.to_string());
            // Discovered also reports changed addresses for an endpoint already seen.
            let seen = visible.lock().expect("poisoned").insert(key, announcement);
            seen.is_none().then_some(Event::Visible(key))
        }
        DiscoveryEvent::Expired { endpoint_id } => {
            let key = *endpoint_id.as_bytes();
            let seen = visible.lock().expect("poisoned").remove(&key);
            seen.is_some().then_some(Event::Gone(key))
        }
        _ => None,
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
