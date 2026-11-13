//! Chunk requests (files.md, sync): on a connection with ALPN `openvault/chunks/1`, a device asks
//! a peer that shares a collection for chunks its files name. Each request is one stream: the
//! asker sends hello and a want, and the peer answers with each chunk it holds, one message each,
//! then one missing message for the rest.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use openvault_core::file::ChunkId;
use openvault_core::membership::Scope;
use openvault_core::{CollectionId, DeviceId, DeviceKeys, Vault, VaultId};
use openvault_crypto::chunk_id;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::EndpointKey;
use crate::frame::{self, FrameError, Reason};
use crate::sync::blocking;
use crate::wire::Reader;

pub const ALPN: &[u8] = b"openvault/chunks/1";

/// The most chunks one want asks for.
pub const MAX_WANT: usize = 64;
/// How long a connection waits for a request, or a stream for its next message, before it
/// closes (files.md, connections).
pub const IDLE: Duration = Duration::from_secs(60);

const HELLO: u8 = 0x01;
const WANT: u8 = 0x02;
const CHUNK: u8 = 0x03;
const MISSING: u8 = 0x04;
/// Close code for a connection that ended normally.
const DONE: u32 = 0;

/// What answering needs from the device's store. Every call may wait on the database, so they're
/// made from blocking sections.
pub trait ChunkStore: Send + Sync + 'static {
    fn vault_id(&self) -> VaultId;
    /// The member, not revoked, whose transport key is `endpoint`.
    fn member(&self, endpoint: &EndpointKey) -> Option<DeviceId>;
    /// Whether this device and `peer` may both read `collection`.
    fn shares(&self, peer: DeviceId, collection: CollectionId) -> bool;
    /// A chunk this device holds in `collection`, sealed.
    fn sealed_chunk(
        &self,
        collection: CollectionId,
        id: &ChunkId,
    ) -> openvault_core::Result<Option<Vec<u8>>>;
}

#[derive(Debug, thiserror::Error)]
pub enum ChunkError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("can't connect: {0}")]
    Connect(String),
    #[error("{0}")]
    Refused(Reason),
    #[error("the peer stopped answering")]
    Timeout,
}

impl ChunkError {
    /// The reason to send the peer before ending the stream, if it should hear of it.
    fn reason(&self) -> Option<Reason> {
        match self {
            Self::Refused(reason) => Some(*reason),
            Self::Frame(FrameError::Bad(_)) => Some(Reason::BadMessage),
            _ => None,
        }
    }
}

/// Answers a peer's requests on `connection` until `idle` passes without one, or the peer closes
/// it. Returns how many chunks it sent.
pub async fn serve<S: ChunkStore>(
    connection: Connection,
    store: Arc<S>,
    idle: Duration,
) -> Result<usize, ChunkError> {
    let peer = *connection.remote_id().as_bytes();
    let mut sent = 0;
    let result = loop {
        let (mut send, mut recv) = match timeout(idle, connection.accept_bi()).await {
            Err(_) => break Ok(sent),
            // The peer closed it once it had what it asked for.
            Ok(Err(_)) => break Ok(sent),
            Ok(Ok(streams)) => streams,
        };
        match answer(&mut send, &mut recv, &store, &peer, idle).await {
            Ok(count) => {
                sent += count;
                let _ = send.finish();
            }
            Err(error) => {
                if let Some(reason) = error.reason() {
                    frame::send_error(&mut send, reason, &error.to_string()).await;
                }
                break Err(error);
            }
        }
    };
    connection.close(DONE.into(), b"done");
    result
}

/// Answers one stream's want: each chunk held, then one missing message for the rest. A
/// collection the two don't both read is answered as if nothing were held.
async fn answer<S: ChunkStore>(
    send: &mut SendStream,
    recv: &mut RecvStream,
    store: &Arc<S>,
    peer: &EndpointKey,
    idle: Duration,
) -> Result<usize, ChunkError> {
    let (kind, body) = read(recv, idle).await?;
    if kind != HELLO {
        return Err(FrameError::Bad("expected hello").into());
    }
    let mut reader = Reader(&body);
    let vault = VaultId::from_bytes(reader.array()?);
    reader.finish()?;
    if vault != store.vault_id() {
        return Err(ChunkError::Refused(Reason::WrongVault));
    }
    let member = blocking(|| store.member(peer)).ok_or(ChunkError::Refused(Reason::NotAMember))?;
    let (kind, body) = read(recv, idle).await?;
    if kind != WANT {
        return Err(FrameError::Bad("expected want").into());
    }
    let (collection, ids) = parse_ids(&body)?;
    if ids.len() > MAX_WANT {
        return Err(FrameError::Bad("too many ids").into());
    }
    let shared = blocking(|| store.shares(member, collection));
    let mut missing = Vec::new();
    let mut sent = 0;
    for id in ids {
        let sealed = if shared {
            match blocking(|| store.sealed_chunk(collection, &id)) {
                Ok(sealed) => sealed,
                Err(e) => {
                    warn!("can't serve a chunk: {e}");
                    None
                }
            }
        } else {
            None
        };
        match sealed {
            Some(sealed) => {
                let body = [&collection.as_bytes()[..], &id, &sealed].concat();
                frame::write(send, CHUNK, &body).await?;
                sent += 1;
            }
            None => missing.push(id),
        }
    }
    frame::write(send, MISSING, &encode_ids(collection, &missing)).await?;
    Ok(sent)
}

/// Asks the peer on `connection` for `ids` of `collection`, at most [`MAX_WANT`]. `keep` takes
/// each chunk the peer sends, once its id is checked. Returns the ids the peer didn't send.
///
/// A chunk that doesn't match its id, or that wasn't asked for, ends the stream with "bad
/// message" (files.md, bad chunks).
pub async fn want(
    connection: &Connection,
    vault: VaultId,
    collection: CollectionId,
    ids: &[ChunkId],
    mut keep: impl FnMut(&ChunkId, Vec<u8>),
) -> Result<Vec<ChunkId>, ChunkError> {
    assert!(ids.len() <= MAX_WANT, "callers ask for at most MAX_WANT");
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| ChunkError::Connect(e.to_string()))?;
    frame::write(&mut send, HELLO, vault.as_bytes()).await?;
    frame::write(&mut send, WANT, &encode_ids(collection, ids)).await?;
    let mut asked: HashSet<ChunkId> = ids.iter().copied().collect();
    let result: Result<Vec<ChunkId>, ChunkError> = async {
        loop {
            let (kind, body) = read(&mut recv, IDLE).await?;
            match kind {
                CHUNK => {
                    let mut reader = Reader(&body);
                    let (from, id): (CollectionId, ChunkId) =
                        (CollectionId::from_bytes(reader.array()?), reader.array()?);
                    let sealed = reader.0.to_vec();
                    if from != collection || !asked.remove(&id) {
                        return Err(FrameError::Bad("a chunk that wasn't asked for").into());
                    }
                    if chunk_id(&sealed) != id {
                        return Err(FrameError::Bad("a chunk that doesn't match its id").into());
                    }
                    keep(&id, sealed);
                }
                MISSING => {
                    let (from, _) = parse_ids(&body)?;
                    if from != collection {
                        return Err(FrameError::Bad("missing for another collection").into());
                    }
                    // What it didn't send, whatever it listed.
                    return Ok(ids
                        .iter()
                        .filter(|id| asked.contains(*id))
                        .copied()
                        .collect());
                }
                _ => return Err(FrameError::Bad("unexpected message").into()),
            }
        }
    }
    .await;
    match &result {
        Ok(_) => {
            let _ = send.finish();
        }
        Err(error) => {
            debug!("a chunk request failed: {error}");
            if let Some(reason) = error.reason() {
                frame::send_error(&mut send, reason, &error.to_string()).await;
            }
        }
    }
    result
}

/// A vault behind a mutex answers for its chunks. `member` picks up log changes by other
/// processes, as sync's hello does (service.md, the store).
impl<K: DeviceKeys + Send + 'static> ChunkStore for Mutex<Vault<K>> {
    fn vault_id(&self) -> VaultId {
        self.lock().expect("poisoned").vault_id()
    }

    fn member(&self, endpoint: &EndpointKey) -> Option<DeviceId> {
        let mut vault = self.lock().expect("poisoned");
        if let Err(e) = vault.refresh() {
            warn!("can't read the store: {e}");
            return None;
        }
        vault.member_by_endpoint(endpoint)
    }

    fn shares(&self, peer: DeviceId, collection: CollectionId) -> bool {
        let vault = self.lock().expect("poisoned");
        let Some(membership) = vault.membership() else {
            return false;
        };
        let reads = |scope| matches!(scope, Scope::Read | Scope::Write);
        reads(membership.scope(vault.device_id(), collection))
            && reads(membership.scope(peer, collection))
    }

    fn sealed_chunk(
        &self,
        collection: CollectionId,
        id: &ChunkId,
    ) -> openvault_core::Result<Option<Vec<u8>>> {
        self.lock().expect("poisoned").sealed_chunk(collection, id)
    }
}

/// Ends a connection the asker has no more requests for.
pub fn close(connection: &Connection) {
    connection.close(DONE.into(), b"done");
}

/// Reads one message, or fails once `idle` passes without one.
async fn read(recv: &mut RecvStream, idle: Duration) -> Result<(u8, Vec<u8>), ChunkError> {
    match timeout(idle, frame::read(recv)).await {
        Ok(message) => Ok(message?),
        Err(_) => Err(ChunkError::Timeout),
    }
}

/// `collection id (16) ‖ count (u16) ‖ ids`, for a want or a missing message.
fn encode_ids(collection: CollectionId, ids: &[ChunkId]) -> Vec<u8> {
    let mut body = collection.as_bytes().to_vec();
    body.extend_from_slice(&u16::try_from(ids.len()).expect("few ids").to_be_bytes());
    for id in ids {
        body.extend_from_slice(id);
    }
    body
}

fn parse_ids(body: &[u8]) -> Result<(CollectionId, Vec<ChunkId>), FrameError> {
    let mut reader = Reader(body);
    let collection = CollectionId::from_bytes(reader.array()?);
    let count = reader.u16()?;
    let ids = (0..count)
        .map(|_| reader.array())
        .collect::<Result<Vec<ChunkId>, _>>()?;
    reader.finish()?;
    Ok((collection, ids))
}

#[cfg(test)]
mod tests {
    use openvault_core::file::{CHUNK_SIZE, Content, Manifest};
    use openvault_core::sets::{ItemId, SetId};
    use openvault_core::{Kind, SoftwareKeys};

    use super::*;
    use crate::Node;
    use crate::sync::session_tests::{Pair, Store, pair};

    /// Writes a file of a full chunk and a short one in `collection` on the admin, and gives the
    /// joined device its record and the grants, as sync would. Returns its manifest's epoch and
    /// chunk ids.
    fn file_on_admin(p: &Pair, collection: CollectionId, name: &str) -> (u32, Vec<ChunkId>) {
        let mut admin = p.admin.lock().unwrap();
        let pieces = [vec![7; CHUNK_SIZE], b"the end".to_vec()];
        let written: Vec<_> = pieces
            .iter()
            .map(|piece| admin.write_chunk(collection, piece).unwrap())
            .collect();
        let manifest = Manifest {
            size: (CHUNK_SIZE + 7) as u64,
            executable: false,
            mtime: 0,
            content: Content::Chunks {
                epoch: written[0].epoch,
                ids: written.iter().map(|chunk| chunk.id).collect(),
            },
        };
        admin
            .set(collection, name, Kind::File, &manifest.encode())
            .unwrap();
        let mut joined = p.joined.lock().unwrap();
        for set in [SetId::GRANTS, SetId::records(collection)] {
            let ids: Vec<ItemId> = admin.set_ids(set, &[0; 32], None).unwrap();
            for item in admin.set_items(set, &ids).unwrap() {
                let _ = joined.receive(set, &item);
            }
        }
        (written[0].epoch, manifest.chunks().to_vec())
    }

    /// The admin's endpoint answers one connection, until it's closed.
    fn serving(p: &Pair) -> tokio::task::JoinHandle<Result<usize, ChunkError>> {
        let endpoint = p.admin_node.endpoint().clone();
        let store = p.admin.clone();
        tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            serve(connection, store, Duration::from_secs(5)).await
        })
    }

    async fn connect(from: &Node, to: &Node) -> Connection {
        let id = iroh::EndpointId::from_bytes(&to.id()).unwrap();
        from.endpoint().connect(id, ALPN).await.unwrap()
    }

    /// Keeps what the peer sends in `store`, as the service does.
    fn keeper(
        store: &Arc<Store>,
        collection: CollectionId,
        epoch: u32,
    ) -> impl FnMut(&ChunkId, Vec<u8>) {
        let store = store.clone();
        move |id, sealed| {
            store
                .lock()
                .unwrap()
                .receive_chunk(collection, epoch, id, &sealed)
                .unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_gets_the_chunks_its_files_name() {
        let p = pair(0).await;
        let (epoch, ids) = file_on_admin(&p, p.latem, "release/app.aab");
        assert_eq!(p.joined.lock().unwrap().chunks_not_held(&ids).unwrap(), ids);
        let served = serving(&p);
        let connection = connect(&p.joined_node, &p.admin_node).await;
        let vault = p.joined.lock().unwrap().vault_id();
        let unknown = [9; 32];
        let missing = want(
            &connection,
            vault,
            p.latem,
            &[ids[0], unknown, ids[1]],
            keeper(&p.joined, p.latem, epoch),
        )
        .await
        .unwrap();
        assert_eq!(missing, [unknown]);
        // A second request on the same connection: nothing left to send.
        let missing = want(&connection, vault, p.latem, &[unknown], |_, _| {
            panic!("nothing to send")
        })
        .await
        .unwrap();
        assert_eq!(missing, [unknown]);
        close(&connection);
        assert_eq!(served.await.unwrap().unwrap(), 2);

        let mut joined = p.joined.lock().unwrap();
        assert!(joined.chunks_not_held(&ids).unwrap().is_empty());
        assert_eq!(
            &joined.read_chunk(p.latem, epoch, &ids[1]).unwrap()[..],
            b"the end"
        );
    }

    /// Chunks of a collection the asker can't read are answered as missing, and a device that
    /// isn't a member gets nothing at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn chunks_go_only_to_members_that_read_the_collection() {
        let p = pair(0).await;
        let ssh = p.admin.lock().unwrap().collection("ssh").unwrap();
        let (_, ids) = file_on_admin(&p, ssh, "id_ed25519");
        let served = serving(&p);
        let connection = connect(&p.joined_node, &p.admin_node).await;
        let vault = p.joined.lock().unwrap().vault_id();
        let missing = want(&connection, vault, ssh, &ids, |_, _| panic!("not shared"))
            .await
            .unwrap();
        assert_eq!(missing, ids);
        close(&connection);
        assert_eq!(served.await.unwrap().unwrap(), 0);

        let stranger = SoftwareKeys::generate();
        let (stranger, _) = Node::start(
            &openvault_core::transport_seed(&stranger),
            crate::test_options(),
        )
        .await
        .unwrap();
        let served = serving(&p);
        let connection = connect(&stranger, &p.admin_node).await;
        let result = want(&connection, vault, ssh, &ids, |_, _| panic!("not a member")).await;
        assert!(
            matches!(
                result,
                Err(ChunkError::Frame(FrameError::Peer {
                    reason: Reason::NotAMember,
                    ..
                }))
            ),
            "{result:?}"
        );
        assert!(matches!(
            served.await.unwrap(),
            Err(ChunkError::Refused(Reason::NotAMember))
        ));
    }

    /// A chunk that doesn't match the id it comes with ends the request (files.md, bad chunks).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_chunk_that_doesnt_match_its_id_is_refused() {
        let p = pair(0).await;
        let endpoint = p.admin_node.endpoint().clone();
        let latem = p.latem;
        let lying = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            frame::read(&mut recv).await.unwrap();
            let (_, body) = frame::read(&mut recv).await.unwrap();
            let (_, ids) = parse_ids(&body).unwrap();
            let body = [&latem.as_bytes()[..], &ids[0], b"not the chunk"].concat();
            frame::write(&mut send, CHUNK, &body).await.unwrap();
            frame::read(&mut recv).await
        });
        let connection = connect(&p.joined_node, &p.admin_node).await;
        let vault = p.joined.lock().unwrap().vault_id();
        let result = want(&connection, vault, latem, &[[1; 32]], |_, _| {
            panic!("a bad chunk is dropped")
        })
        .await;
        assert!(
            matches!(result, Err(ChunkError::Frame(FrameError::Bad(_)))),
            "{result:?}"
        );
        assert!(matches!(
            lying.await.unwrap(),
            Err(FrameError::Peer {
                reason: Reason::BadMessage,
                ..
            })
        ));
    }
}
