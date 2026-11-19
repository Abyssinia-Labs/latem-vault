//! Fetching chunks (files.md, sync): the chunks a file names that aren't here, from the peers
//! that share its collection, those on the local network first, then through the relay.
//!
//! A fetch runs when a file is read, and, for kept collections, when a sync session catches up
//! after a received record named chunks that aren't here. A kept collection whose fetch left
//! chunks no peer had is tried again when a session with a peer catches up, at the earliest 30
//! seconds later, doubling to an hour. Nothing fetches on a timer.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use pinkvault_core::file::{ChunkId, Content, Manifest};
use pinkvault_core::membership::Scope;
use pinkvault_core::{CollectionId, DeviceId, Kind, Placement, Vault};
use pinkvault_keystore::Keys;
use pinkvault_net::chunks::{self, MAX_WANT};
use pinkvault_net::{EndpointAddr, EndpointId, EndpointKey, Node, RelayUrl};
use tokio::sync::broadcast;
use tokio::task::block_in_place;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::api::Event;
use crate::handler::transport_endpoint;

/// The first wait before a kept collection's missing chunks are asked for again, doubling to
/// [`LAST_RETRY`] (files.md, missing chunks).
const FIRST_RETRY: Duration = Duration::from_secs(30);
const LAST_RETRY: Duration = Duration::from_secs(60 * 60);
/// How long connecting to a peer may take before the next one is asked.
const CONNECT: Duration = Duration::from_secs(15);

pub(crate) struct Fetcher {
    node: Arc<Node>,
    vault: Arc<Mutex<Vault<Keys>>>,
    /// The grandfather's relay, if a coordinator is configured.
    relay: Option<RelayUrl>,
    /// What watching apps hear of (service.md, for apps).
    events: broadcast::Sender<Event>,
    state: Mutex<State>,
}

struct State {
    /// Whether every kept collection is to be looked at, as when the service starts.
    look_everywhere: bool,
    /// Kept collections whose last fetch left chunks no peer had: when they may be asked for
    /// again, and the wait after that.
    waiting: HashMap<CollectionId, (Instant, Duration)>,
    /// Kept collections being fetched now.
    running: HashSet<CollectionId>,
}

/// What one fetch did.
struct Fetched {
    stored: usize,
    /// The chunks still not here.
    missing: Vec<ChunkId>,
}

impl Fetcher {
    pub(crate) fn new(
        node: Arc<Node>,
        vault: Arc<Mutex<Vault<Keys>>>,
        relay: Option<RelayUrl>,
        events: broadcast::Sender<Event>,
    ) -> Arc<Self> {
        Arc::new(Self {
            node,
            vault,
            relay,
            events,
            state: Mutex::new(State {
                look_everywhere: true,
                waiting: HashMap::new(),
                running: HashSet::new(),
            }),
        })
    }

    /// Gets the chunks of the file `collection`/`name` that aren't here, whatever the
    /// collection's placement. Returns how many no peer had.
    pub(crate) async fn file(&self, collection: &str, name: &str) -> Result<u64> {
        let (id, epoch, ids, missing) = block_in_place(|| -> Result<_> {
            let mut vault = self.vault.lock().expect("poisoned");
            vault.refresh()?;
            let id = vault.collection(collection)?;
            let entry = vault
                .get(id, name)?
                .filter(|entry| entry.kind == Kind::File)
                .ok_or_else(|| anyhow!("no file {collection}/{name}"))?;
            match Manifest::decode(&entry.value)?.content {
                Content::Inline(_) => Ok((id, 0, Vec::new(), Vec::new())),
                Content::Chunks { epoch, ids } => {
                    let missing = vault.chunks_not_held(&ids)?;
                    Ok((id, epoch, ids, missing))
                }
            }
        })?;
        if missing.is_empty() {
            return Ok(0);
        }
        let fetched = self.fetch(id, epoch, missing).await;
        if fetched.stored > 0 {
            // Room for it, if the collection is on demand, sparing the file just fetched.
            block_in_place(
                || match self.vault.lock().expect("poisoned").trim_cache(&ids) {
                    Ok(0) => {}
                    Ok(dropped) => info!(dropped, "dropped chunks used least lately"),
                    Err(e) => warn!("can't trim the chunk cache: {e:#}"),
                },
            );
            self.emit(vec![collection.to_owned()]);
        }
        Ok(fetched.missing.len() as u64)
    }

    /// A sync session caught up or ended. Kept collections get the chunks that received records
    /// name, and those still waiting for chunks are asked for again once due. Cheap when neither
    /// applies: a flag and a map.
    pub(crate) fn synced(self: &Arc<Self>) {
        let now = Instant::now();
        let (everywhere, due) = {
            let mut state = self.state.lock().expect("poisoned");
            let everywhere = std::mem::take(&mut state.look_everywhere);
            let due: Vec<CollectionId> = state
                .waiting
                .iter()
                .filter(|(_, (at, _))| *at <= now)
                .map(|(collection, _)| *collection)
                .collect();
            (everywhere, due)
        };
        let arrived = self.vault.lock().expect("poisoned").take_files_arrived();
        let collections = if everywhere || arrived {
            self.kept_collections()
        } else {
            due
        };
        for collection in collections {
            self.start(collection);
        }
    }

    /// `collection` became kept: it gets what's missing now.
    pub(crate) fn kept(self: &Arc<Self>, collection: CollectionId) {
        self.start(collection);
    }

    /// Fetches what `collection`'s files are missing in the background, unless that's running.
    fn start(self: &Arc<Self>, collection: CollectionId) {
        if !self
            .state
            .lock()
            .expect("poisoned")
            .running
            .insert(collection)
        {
            return;
        }
        let fetcher = self.clone();
        tokio::spawn(async move {
            let result = fetcher.collection(collection).await;
            let mut state = fetcher.state.lock().expect("poisoned");
            state.running.remove(&collection);
            let missing = match result {
                Ok(0) => {
                    state.waiting.remove(&collection);
                    return;
                }
                Ok(missing) => missing,
                Err(e) => {
                    warn!("fetching chunks failed: {e:#}");
                    0
                }
            };
            let wait = state
                .waiting
                .get(&collection)
                .map_or(FIRST_RETRY, |(_, wait)| *wait);
            state.waiting.insert(
                collection,
                (Instant::now() + wait, (wait * 2).min(LAST_RETRY)),
            );
            if missing > 0 {
                info!(
                    missing,
                    "no device that was asked had these chunks; asking again once one syncs, \
                     in {}s at the earliest",
                    wait.as_secs()
                );
            }
        });
    }

    /// Fetches the chunks a kept collection's files name that aren't here. Returns how many no
    /// peer had.
    async fn collection(&self, collection: CollectionId) -> Result<u64> {
        let Some((name, wanted)) = block_in_place(|| self.wanted(collection))? else {
            return Ok(0);
        };
        let mut missing = 0;
        let mut stored = 0;
        for (epoch, ids) in wanted {
            let fetched = self.fetch(collection, epoch, ids).await;
            stored += fetched.stored;
            missing += fetched.missing.len() as u64;
        }
        if stored > 0 {
            info!(stored, "fetched chunks for {name}");
            self.emit(vec![name]);
        }
        Ok(missing)
    }

    /// A kept collection's name, and the chunks its current files name that aren't here, by
    /// the epoch they're sealed under. `None` if it isn't kept or this device can't read it.
    /// Opens one record per file with chunks missing.
    #[allow(clippy::type_complexity)]
    fn wanted(
        &self,
        collection: CollectionId,
    ) -> Result<Option<(String, Vec<(u32, Vec<ChunkId>)>)>> {
        let mut vault = self.vault.lock().expect("poisoned");
        vault.refresh()?;
        let reads = vault.membership().is_some_and(|membership| {
            matches!(
                membership.scope(vault.device_id(), collection),
                Scope::Read | Scope::Write
            )
        });
        if !reads || vault.placement(collection)? != Placement::Keep {
            return Ok(None);
        }
        let files = vault.missing_chunks(collection)?;
        if files.is_empty() {
            return Ok(None);
        }
        let name = vault
            .collections()?
            .into_iter()
            .find(|info| info.id == collection)
            .map(|info| info.name)
            .ok_or_else(|| anyhow!("no collection {collection}"))?;
        let mut by_epoch: HashMap<u32, Vec<ChunkId>> = HashMap::new();
        for file in files.keys() {
            let Some(entry) = vault.get(collection, file)? else {
                continue;
            };
            if let Content::Chunks { epoch, ids } = Manifest::decode(&entry.value)?.content {
                by_epoch
                    .entry(epoch)
                    .or_default()
                    .extend(vault.chunks_not_held(&ids)?);
            }
        }
        Ok(Some((name, by_epoch.into_iter().collect())))
    }

    /// Asks the peers that read `collection` for `wanted`, sealed under `epoch`, one peer after
    /// another until none are missing: those on the local network first, then through the relay.
    async fn fetch(
        &self,
        collection: CollectionId,
        epoch: u32,
        mut wanted: Vec<ChunkId>,
    ) -> Fetched {
        let (vault_id, peers) = {
            let vault = self.vault.lock().expect("poisoned");
            (vault.vault_id(), readers(&vault, collection))
        };
        let visible = self.node.visible();
        let mut peers: Vec<(DeviceId, EndpointKey)> = peers
            .into_iter()
            .filter(|(_, key)| self.relay.is_some() || visible.contains(key))
            .collect();
        peers.sort_by_key(|(_, key)| !visible.contains(key));
        let mut stored = 0;
        for (device, key) in peers {
            if wanted.is_empty() {
                break;
            }
            let Ok(remote) = EndpointId::from_bytes(&key) else {
                continue;
            };
            let connection = match timeout(
                CONNECT,
                self.node
                    .endpoint()
                    .connect(self.addr(remote), chunks::ALPN),
            )
            .await
            {
                Ok(Ok(connection)) => connection,
                Ok(Err(e)) => {
                    debug!(%device, "can't connect to ask for chunks: {e}");
                    continue;
                }
                Err(_) => {
                    debug!(%device, "connecting to ask for chunks took too long");
                    continue;
                }
            };
            for batch in wanted.chunks(MAX_WANT) {
                let vault = self.vault.clone();
                let keep = |id: &ChunkId, sealed: Vec<u8>| {
                    let result = block_in_place(|| {
                        vault
                            .lock()
                            .expect("poisoned")
                            .receive_chunk(collection, epoch, id, &sealed)
                    });
                    match result {
                        Ok(true) => stored += 1,
                        Ok(false) => {}
                        // The file may have changed since it was asked for.
                        Err(e) => debug!(%device, "didn't keep a chunk: {e}"),
                    }
                };
                if let Err(e) = chunks::want(&connection, vault_id, collection, batch, keep).await {
                    warn!(%device, "asking for chunks failed: {e}");
                    break;
                }
            }
            chunks::close(&connection);
            // Whatever this peer sent, or failed to.
            wanted = match block_in_place(|| {
                self.vault
                    .lock()
                    .expect("poisoned")
                    .chunks_not_held(&wanted)
            }) {
                Ok(left) => left,
                Err(e) => {
                    warn!("can't read the store: {e:#}");
                    break;
                }
            };
        }
        Fetched {
            stored,
            missing: wanted,
        }
    }

    /// The fetched chunks of these collections are here: apps show their files as here.
    fn emit(&self, collections: Vec<String>) {
        let _ = self.events.send(Event {
            what: Event::ENTRIES,
            collections,
        });
    }

    fn addr(&self, peer: EndpointId) -> EndpointAddr {
        match &self.relay {
            Some(url) => EndpointAddr::new(peer).with_relay_url(url.clone()),
            None => peer.into(),
        }
    }

    /// The collections this device reads and keeps, to look for missing chunks in.
    fn kept_collections(&self) -> Vec<CollectionId> {
        let vault = self.vault.lock().expect("poisoned");
        let Some(membership) = vault.membership() else {
            return Vec::new();
        };
        membership
            .collections()
            .filter(|&collection| {
                matches!(
                    membership.scope(vault.device_id(), collection),
                    Scope::Read | Scope::Write
                ) && vault.placement(collection).ok() == Some(Placement::Keep)
            })
            .collect()
    }
}

/// The other members, not revoked, that may read `collection`, with their endpoints. None if
/// this device can't read it.
fn readers(vault: &Vault<Keys>, collection: CollectionId) -> Vec<(DeviceId, EndpointKey)> {
    let Some(membership) = vault.membership() else {
        return Vec::new();
    };
    let reads = |device| {
        matches!(
            membership.scope(device, collection),
            Scope::Read | Scope::Write
        )
    };
    let this = vault.device_id();
    if !reads(this) {
        return Vec::new();
    }
    membership
        .devices()
        .filter(|device| !device.revoked && device.info.id != this && reads(device.info.id))
        .filter_map(|device| {
            Some((
                device.info.id,
                transport_endpoint(&device.info.transport_key)?,
            ))
        })
        .collect()
}
