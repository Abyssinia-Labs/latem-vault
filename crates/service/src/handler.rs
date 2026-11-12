//! What each request does to the vault. The service runs it for requests on its socket, and the
//! CLI runs it in-process when no service is running, so a command behaves the same either way.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context as _, Result, anyhow, bail};
use openvault_core::join::JoinRequest;
use openvault_core::membership::{AdminKey as AdminKeyTrait, Change, LogEntry, Scope};
use openvault_core::{Approval, CollectionId, DeviceId, Kind, Revocation, Vault, names};
use openvault_crypto::RecoveryKey;
use openvault_keystore::{AdminKey, Keys};
use openvault_net::EndpointKey;
use zeroize::Zeroizing;

use crate::api::{
    ChunkData, CollectionSummary, DeviceSummary, EntryDetail, ErrorCode, Item, Listed, LogLine,
    Request, Response, Signer, Value, VaultInfo,
};

/// The most log entries one log request returns (service.md, for apps).
const MAX_LOG_LINES: u16 = 256;

/// What a request runs against.
pub struct Context<'a> {
    pub vault: &'a mut Vault<Keys>,
    /// Where this device's admin key file would be.
    pub admin_key: &'a Path,
    /// The OpenVault endpoints mDNS can see; `None` without the service.
    pub visible: Option<&'a BTreeSet<EndpointKey>>,
}

/// A failure that the CLI answers by asking for the recovery phrase and trying again.
#[derive(Debug, thiserror::Error)]
#[error("{0} needs an admin signature, and this device has no admin key")]
struct RecoveryPhraseNeeded(&'static str);

pub fn handle(cx: &mut Context, request: Request) -> Response {
    run(cx, request).unwrap_or_else(error_response)
}

/// The error response for `error`: "recovery phrase needed" when it is that, so the CLI and apps
/// ask for the phrase and try again.
pub fn error_response(error: anyhow::Error) -> Response {
    if needs_recovery_phrase(&error) {
        Response::Error {
            code: ErrorCode::RecoveryPhraseNeeded,
            message: error.to_string(),
        }
    } else {
        Response::error(format!("{error:#}"))
    }
}

/// Whether `error` means the recovery phrase is needed, for a caller that asks for it and tries
/// again.
pub fn needs_recovery_phrase(error: &anyhow::Error) -> bool {
    error.is::<RecoveryPhraseNeeded>()
}

/// Approves a join with `scopes`, signed like revoke: with this device's admin key, which asks
/// for Touch ID, or with the recovery phrase (join.md, approval).
pub fn approve_join(
    vault: &mut Vault<Keys>,
    admin_key: &Path,
    request: &JoinRequest,
    scopes: &[(String, Scope)],
    recovery_phrase: Option<&str>,
) -> Result<Approval> {
    if vault.membership().is_none() {
        bail!("this vault has no membership log yet; creating a collection starts it");
    }
    let mut collections: Vec<(CollectionId, Scope)> = Vec::with_capacity(scopes.len());
    for (name, scope) in scopes {
        let id = vault.collection(name)?;
        if collections.iter().any(|(other, _)| *other == id) {
            bail!("{name} is given more than one scope");
        }
        collections.push((id, *scope));
    }
    as_admin(
        vault,
        admin_key,
        recovery_phrase,
        "approving a device",
        format!("add {} to your vault", request.name.name),
        |vault, admin| vault.approve_join(request, &collections, &admin),
    )
}

fn run(cx: &mut Context, request: Request) -> Result<Response> {
    let vault = &mut *cx.vault;
    Ok(match request {
        Request::Collections => Response::Names(
            vault
                .collections()?
                .into_iter()
                .map(|collection| collection.name)
                .collect(),
        ),
        Request::CreateCollection {
            name,
            recovery_phrase,
        } => {
            create_collection(
                vault,
                cx.admin_key,
                &name,
                recovery_phrase.as_ref().map(|phrase| phrase.as_str()),
            )?;
            Response::Done
        }
        Request::Get { collection, name } => {
            let id = vault.collection(&collection)?;
            Response::Entry(vault.get(id, &name)?.map(|entry| Value {
                kind: entry.kind,
                value: entry.value,
            }))
        }
        Request::Set {
            collection,
            entries,
        } => {
            let id = vault.collection(&collection)?;
            vault.set_all(
                id,
                entries
                    .iter()
                    .map(|item| (item.name.as_str(), item.kind, &item.value[..])),
            )?;
            sweep_if_dropped(vault);
            Response::Done
        }
        Request::Delete { collection, name } => {
            let id = vault.collection(&collection)?;
            let deleted = vault.delete(id, &name)?;
            sweep_if_dropped(vault);
            Response::Deleted(deleted)
        }
        Request::List { collection } => {
            let id = vault.collection(&collection)?;
            let listed = vault.list(id)?;
            // Only a collection with files asks which chunks are here.
            let missing = if listed.iter().any(|info| info.kind == Kind::File) {
                vault.missing_chunks(id)?
            } else {
                HashMap::new()
            };
            Response::Listing(
                listed
                    .into_iter()
                    .map(|info| Listed {
                        missing: missing
                            .get(&info.name)
                            .map_or(0, |&n| u32::try_from(n).unwrap_or(u32::MAX)),
                        name: info.name,
                        kind: info.kind,
                        size: info.size,
                    })
                    .collect(),
            )
        }
        Request::WriteChunk { collection, data } => {
            let id = vault.collection(&collection)?;
            let written = vault.write_chunk(id, &data.0)?;
            Response::ChunkWritten {
                id: written.id,
                epoch: written.epoch,
            }
        }
        Request::ReadChunk {
            collection,
            epoch,
            id,
        } => {
            let collection = vault.collection(&collection)?;
            Response::Chunk(ChunkData(vault.read_chunk(collection, epoch, &id)?))
        }
        Request::Placement { collection, set } => {
            let id = vault.collection(&collection)?;
            if let Some(placement) = set {
                vault.set_placement(id, placement)?;
            }
            Response::Placement(vault.placement(id)?)
        }
        // Only the service has the endpoint to fetch with, so here they're only counted.
        Request::Fetch { collection, name } => {
            let id = vault.collection(&collection)?;
            let entry = vault
                .get(id, &name)?
                .filter(|entry| entry.kind == Kind::File)
                .ok_or_else(|| anyhow!("no file {collection}/{name}"))?;
            let missing = match openvault_core::file::Manifest::decode(&entry.value)?.content {
                openvault_core::file::Content::Inline(_) => 0,
                openvault_core::file::Content::Chunks { ids, .. } => {
                    vault.chunks_not_held(&ids)?.len() as u64
                }
            };
            Response::Fetched { missing }
        }
        Request::Folder { collection, folder } => {
            let id = vault.collection(&collection)?;
            Response::Entries(
                vault
                    .entries_in(id, &folder)?
                    .into_iter()
                    .map(|entry| Item {
                        name: entry.name,
                        kind: entry.kind,
                        // A manifest can be up to 1 MiB, so a folder's would soon outgrow a
                        // message: `run` gets each file's on its own.
                        value: if entry.kind == Kind::File {
                            Zeroizing::new(Vec::new())
                        } else {
                            entry.value
                        },
                    })
                    .collect(),
            )
        }
        Request::Devices => Response::Devices(devices(vault, cx.visible)),
        // The service reloaded before handling it; nothing else to do here.
        Request::Changed => Response::Done,
        Request::Review { device } => Response::Review(vault.review_revocation(device)?),
        Request::Revoke {
            device,
            recovery_phrase,
        } => {
            let name = device_name(vault, device);
            let revocation = as_admin(
                vault,
                cx.admin_key,
                recovery_phrase.as_deref().map(String::as_str),
                "revoking a device",
                format!("remove {name} from your vault"),
                |vault, admin| vault.revoke_device(device, &admin),
            )?;
            revoked(vault, &revocation)?
        }
        Request::SetScope {
            device,
            collection,
            scope,
            recovery_phrase,
        } => {
            let id = vault.collection(&collection)?;
            let name = device_name(vault, device);
            // Checked before asking for Touch ID or 24 words.
            if vault
                .membership()
                .is_some_and(|m| m.scope(device, id) == scope)
            {
                bail!("{name} already has that scope on {collection}");
            }
            let change = as_admin(
                vault,
                cx.admin_key,
                recovery_phrase.as_deref().map(String::as_str),
                "changing a scope",
                format!("change what {name} may do with {collection}"),
                |vault, admin| vault.set_scope(device, id, scope, &admin),
            )?;
            Response::ScopeSet {
                rotated: change.rotated,
                granted: u32::try_from(change.granted).unwrap_or(u32::MAX),
                carried: u32::try_from(change.carried).unwrap_or(u32::MAX),
            }
        }
        Request::Vault => Response::Vault(VaultInfo {
            vault: vault.vault_id(),
            device: vault.device_id(),
            recovery: openvault_crypto::hash::hash(vault.recovery_key().as_bytes())[..4]
                .try_into()
                .expect("took 4 bytes"),
            log_head: vault.membership().map_or(0, |m| m.head().0),
            admin: listed_admin_key(vault, cx.admin_key)?.is_some(),
        }),
        Request::CollectionSummaries => Response::CollectionSummaries(summaries(vault)?),
        Request::EntryDetails { collection } => {
            let id = vault.collection(&collection)?;
            let names: Vec<String> = vault.list(id)?.into_iter().map(|e| e.name).collect();
            let mut details = Vec::with_capacity(names.len());
            for name in names {
                let Some(entry) = vault.get(id, &name)? else {
                    continue;
                };
                details.push(EntryDetail {
                    name: entry.name,
                    kind: entry.kind,
                    set_by: entry.version.device,
                    key: entry.epoch,
                    // Lists never hold a secret's value (service.md, for apps).
                    value: if entry.kind == Kind::Var {
                        entry.value
                    } else {
                        Zeroizing::new(Vec::new())
                    },
                });
            }
            Response::EntryDetails(details)
        }
        Request::Log { from, max } => Response::Log(log_lines(
            vault,
            cx.admin_key,
            from,
            max.min(MAX_LOG_LINES),
        )?),
        Request::SetScopes {
            device,
            changes,
            recovery_phrase,
        } => {
            let name = device_name(vault, device);
            let mut ids: Vec<(CollectionId, Scope, &str)> = Vec::with_capacity(changes.len());
            for (collection, scope) in &changes {
                let id = vault.collection(collection)?;
                if ids.iter().any(|(other, ..)| *other == id) {
                    bail!("{collection} is given more than one scope");
                }
                // Changes to the scope the device already has are skipped.
                if vault
                    .membership()
                    .is_none_or(|m| m.scope(device, id) != *scope)
                {
                    ids.push((id, *scope, collection.as_str()));
                }
            }
            // Checked before asking for Touch ID or 24 words.
            if ids.is_empty() {
                bail!("{name} already has those scopes");
            }
            let collections = ids
                .iter()
                .map(|(.., collection)| *collection)
                .collect::<Vec<_>>()
                .join(", ");
            let changed = as_admin(
                vault,
                cx.admin_key,
                recovery_phrase.as_deref().map(String::as_str),
                "changing a scope",
                format!("change what {name} may do with {collections}"),
                |vault, admin| {
                    ids.iter()
                        .map(|(id, scope, _)| vault.set_scope(device, *id, *scope, &admin))
                        .collect::<openvault_core::Result<Vec<_>>>()
                },
            )?;
            let mut rotated = Vec::new();
            let (mut granted, mut carried) = (0usize, 0usize);
            for ((.., collection), change) in ids.iter().zip(&changed) {
                if change.rotated {
                    rotated.push((*collection).to_owned());
                }
                granted += change.granted;
                carried += change.carried;
            }
            Response::ScopesSet {
                rotated,
                granted: u32::try_from(granted).unwrap_or(u32::MAX),
                carried: u32::try_from(carried).unwrap_or(u32::MAX),
            }
        }
        // The service answers these before a request gets here.
        Request::Status
        | Request::Watch
        | Request::Peers
        | Request::Joiners
        | Request::CheckCode { .. }
        | Request::Approve { .. }
        | Request::Refuse { .. } => bail!("only a running service answers that"),
    })
}

/// Sweeps chunks no current version names (files.md, dropping chunks) after a write that left
/// some unreferenced: one batch, since the service sweeps the rest when it starts. A failure is
/// logged, since the write itself went through.
fn sweep_if_dropped(vault: &mut Vault<Keys>) {
    if !vault.chunks_dropped() {
        return;
    }
    match vault.sweep_chunks() {
        Ok(swept) if swept.deleted > 0 => {
            tracing::info!(deleted = swept.deleted, more = swept.more, "swept chunks");
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("sweeping chunks failed: {e:#}"),
    }
}

/// Every collection on this device, with its counts, key and the devices with a scope on it.
fn summaries(vault: &Vault<Keys>) -> Result<Vec<CollectionSummary>> {
    let mut summaries = Vec::new();
    for collection in vault.collections()? {
        let entries = vault.list(collection.id)?;
        let count = |kind| {
            let n = entries.iter().filter(|entry| entry.kind == kind).count();
            u32::try_from(n).unwrap_or(u32::MAX)
        };
        let membership = vault.membership();
        let devices = membership
            .map(|m| {
                m.devices()
                    .filter(|device| !device.revoked)
                    .map(|device| (device.info.id, m.scope(device.info.id, collection.id)))
                    .filter(|(_, scope)| *scope != Scope::None)
                    .collect()
            })
            .unwrap_or_default();
        summaries.push(CollectionSummary {
            secrets: count(Kind::Secret),
            variables: count(Kind::Var),
            files: count(Kind::File),
            key: membership.and_then(|m| m.epoch(collection.id)).unwrap_or(0),
            devices,
            name: collection.name,
        });
    }
    Ok(summaries)
}

/// Up to `max` log entries from seq `from`, as an app shows them.
fn log_lines(vault: &Vault<Keys>, admin_key: &Path, from: u64, max: u16) -> Result<Vec<LogLine>> {
    let entries = vault.log_range(from, usize::from(max))?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    // The recovery key's admin key is the first one genesis lists (membership.md).
    let recovery_admin = match vault.log_range(0, 1)?.first().map(LogEntry::change) {
        Some(Change::Genesis { admins, .. }) => admins.first().cloned(),
        _ => None,
    };
    let this_admin = match AdminKey::load(admin_key) {
        Ok(key) => Some(key.verifying_key()),
        Err(openvault_keystore::Error::NotFound(_)) => None,
        Err(e) => return Err(e).context("can't load this device's admin key"),
    };
    let names = vault.collections()?;
    let collection_name = |id: &CollectionId| {
        names
            .iter()
            .find(|collection| collection.id == *id)
            .map_or_else(|| id.to_string(), |collection| collection.name.clone())
    };
    Ok(entries
        .iter()
        .map(|entry| {
            let mut line = LogLine {
                seq: entry.seq(),
                hash: entry.hash(),
                change: entry.change().code(),
                device: DeviceId::from_bytes([0; 16]),
                collection: String::new(),
                scope: Scope::None,
                key: 0,
                signer: if Some(entry.signer()) == recovery_admin.as_ref() {
                    Signer::Recovery
                } else if Some(entry.signer()) == this_admin.as_ref() {
                    Signer::ThisDevice
                } else {
                    Signer::OtherAdmin
                },
            };
            match entry.change() {
                Change::AddDevice(info) => line.device = info.id,
                Change::SetScope {
                    device,
                    collection,
                    scope,
                } => {
                    line.device = *device;
                    line.collection = collection_name(collection);
                    line.scope = *scope;
                }
                Change::RevokeDevice(device) => line.device = *device,
                Change::RotateEpoch { collection, epoch } => {
                    line.collection = collection_name(collection);
                    line.key = *epoch;
                }
                Change::Genesis { .. } | Change::AddAdmin(_) | Change::RemoveAdmin(_) => {}
            }
            line
        })
        .collect())
}

/// Runs `f` with an admin signature: this device's admin key when it has one, which asks for
/// Touch ID with `reason`, and otherwise the recovery key from `recovery_phrase`. Without a
/// phrase it fails with [`RecoveryPhraseNeeded`] for `action`.
fn as_admin<T>(
    vault: &mut Vault<Keys>,
    admin_key: &Path,
    recovery_phrase: Option<&str>,
    action: &'static str,
    reason: String,
    f: impl FnOnce(&mut Vault<Keys>, &dyn AdminKeyTrait) -> openvault_core::Result<T>,
) -> Result<T> {
    if let Some(admin) = listed_admin_key(vault, admin_key)? {
        return Ok(f(vault, &admin.with_reason(reason))?);
    }
    let phrase = recovery_phrase.ok_or(RecoveryPhraseNeeded(action))?;
    let recovery = RecoveryKey::from_phrase(phrase)?;
    if !vault.is_recovery_key(&recovery) {
        bail!("that recovery phrase belongs to another vault");
    }
    Ok(f(vault, &recovery.admin_signing_key())?)
}

/// A device's name, or its id if the name doesn't open.
fn device_name(vault: &Vault<Keys>, device: DeviceId) -> String {
    vault
        .device_name(device)
        .ok()
        .flatten()
        .map_or_else(|| device.to_string(), |name| name.name)
}

/// The response to a revocation, with the rotated collections by name.
fn revoked(vault: &Vault<Keys>, revocation: &Revocation) -> Result<Response> {
    let names: Vec<_> = vault.collections()?;
    let rotated = revocation
        .rotated
        .iter()
        .map(|id| {
            names
                .iter()
                .find(|collection| collection.id == *id)
                .map_or_else(|| id.to_string(), |collection| collection.name.clone())
        })
        .collect();
    Ok(Response::Revoked {
        rotated,
        carried: u32::try_from(revocation.carried).unwrap_or(u32::MAX),
    })
}

/// Signs with this device's admin key when it has one, which asks for Touch ID, and with the
/// recovery key otherwise. A vault from before the membership log starts it first.
fn create_collection(
    vault: &mut Vault<Keys>,
    admin_key: &Path,
    name: &str,
    recovery_phrase: Option<&str>,
) -> Result<()> {
    names::check_collection(name)?;
    // Checked before asking for Touch ID or 24 words.
    if vault.collection(name).is_ok() {
        bail!("collection {name} already exists");
    }
    if let Some(admin) = listed_admin_key(vault, admin_key)? {
        let admin = admin.with_reason(format!("create the collection {name}"));
        vault.create_collection(name, &admin)?;
        return Ok(());
    }
    let phrase = recovery_phrase.ok_or(RecoveryPhraseNeeded("creating a collection"))?;
    let recovery = RecoveryKey::from_phrase(phrase)?;
    if !vault.is_recovery_key(&recovery) {
        bail!("that recovery phrase belongs to another vault");
    }
    if vault.membership().is_none() {
        vault.start_log(&recovery, &crate::default_device_name())?;
    }
    vault.create_collection(name, &recovery.admin_signing_key())?;
    Ok(())
}

/// This device's admin key, if it has one and the vault lists it as an admin.
fn listed_admin_key(vault: &Vault<Keys>, path: &Path) -> Result<Option<AdminKey>> {
    use openvault_core::membership::AdminKey as _;

    let key = match AdminKey::load(path) {
        Ok(key) => key,
        Err(openvault_keystore::Error::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e).context("can't load this device's admin key"),
    };
    let listed = vault
        .membership()
        .is_some_and(|m| m.admins().contains(&key.verifying_key()));
    Ok(listed.then_some(key))
}

/// The log's devices, this one first, then by name.
fn devices(vault: &Vault<Keys>, visible: Option<&BTreeSet<EndpointKey>>) -> Vec<DeviceSummary> {
    let Some(membership) = vault.membership() else {
        return Vec::new();
    };
    let mut devices: Vec<DeviceSummary> = membership
        .devices()
        .map(|device| {
            let transport = transport_endpoint(&device.info.transport_key);
            DeviceSummary {
                id: device.info.id,
                this: device.info.id == vault.device_id(),
                revoked: device.revoked,
                visible: visible.is_some_and(|v| transport.is_some_and(|key| v.contains(&key))),
                hardware: !device.info.verifying_key.is_ed25519(),
                // A name that doesn't open is shown as the device id (membership.md).
                name: vault
                    .device_name(device.info.id)
                    .ok()
                    .flatten()
                    .map(|name| (name.platform, name.name)),
            }
        })
        .collect();
    devices.sort_by(|a, b| {
        b.this.cmp(&a.this).then_with(|| {
            a.name
                .as_ref()
                .map(|n| &n.1)
                .cmp(&b.name.as_ref().map(|n| &n.1))
        })
    });
    devices
}

/// The endpoint id a transport key gives: its 32 Ed25519 key bytes, after the algorithm byte.
pub(crate) fn transport_endpoint(key: &openvault_crypto::VerifyingKey) -> Option<EndpointKey> {
    key.is_ed25519()
        .then(|| key.as_bytes()[1..].try_into().ok())
        .flatten()
}

/// The error message for a response that should have been something else.
pub fn unexpected(response: &Response) -> anyhow::Error {
    match response {
        Response::Error { message, .. } => anyhow!("{message}"),
        other => anyhow!("unexpected response from the service: {other:?}"),
    }
}
