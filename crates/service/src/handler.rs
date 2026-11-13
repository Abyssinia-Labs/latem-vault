//! What each request does to the vault. The service runs it for requests on its socket, and the
//! CLI runs it in-process when no service is running, so a command behaves the same either way.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Mutex;

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
    /// This device's admin key, if [`approve_first`] already asked for it for this request.
    /// Without one, a request an admin signs loads the key from `admin_key`, and its first
    /// signature asks.
    pub admin: Option<&'a dyn AdminKeyTrait>,
    /// The OpenVault endpoints mDNS can see; `None` without the service.
    pub visible: Option<&'a BTreeSet<EndpointKey>>,
}

/// An admin key that asks the user before it signs, as this device's does with Touch ID
/// (keystore.md, admin key).
pub trait Asks: AdminKeyTrait {
    /// Asks now, so the signatures that follow don't.
    fn ask(&self) -> Result<()>;
}

impl Asks for AdminKey {
    fn ask(&self) -> Result<()> {
        Ok(self.authenticate()?)
    }
}

/// For a request this device's admin key signs: asks for the key's approval before the vault is
/// locked, so sync sessions and other requests go on while the Touch ID dialog is open (service.md,
/// asking for Touch ID). `reason` runs the checks that come before asking, so a request that would
/// fail asks for nothing, and says what the dialog shows; `None` means no admin signs the request.
/// `key` is this device's admin key with that reason, if the vault lists one. Returns the key,
/// approved, for [`Context::admin`]; `None` leaves the request to ask as it signs, or to use the
/// recovery phrase.
pub fn approve_first<K: Asks>(
    vault: &Mutex<Vault<Keys>>,
    reason: impl FnOnce(&Vault<Keys>) -> Result<Option<String>>,
    key: impl FnOnce(&Vault<Keys>, String) -> Result<Option<K>>,
) -> Result<Option<K>> {
    let key = {
        let mut vault = vault.lock().expect("poisoned");
        vault.refresh()?;
        let Some(reason) = reason(&vault)? else {
            return Ok(None);
        };
        let Some(key) = key(&vault, reason)? else {
            return Ok(None);
        };
        key
    };
    key.ask()?;
    Ok(Some(key))
}

/// This device's admin key, if the vault lists it, with `reason` for its dialog: the `key` for
/// [`approve_first`].
pub fn admin_key_for(
    path: &Path,
) -> impl FnOnce(&Vault<Keys>, String) -> Result<Option<AdminKey>> + '_ {
    move |vault, reason| Ok(listed_admin_key(vault, path)?.map(|key| key.with_reason(reason)))
}

/// Whether an admin signs `request`, so [`approve_first`] has something to ask. The same requests
/// as [`admin_reason`].
pub fn signed_by_admin(request: &Request) -> bool {
    matches!(
        request,
        Request::CreateCollection { .. }
            | Request::Revoke { .. }
            | Request::SetScope { .. }
            | Request::SetScopes { .. }
    )
}

/// What the dialog says for `request` if an admin signs it, after the checks that come before
/// asking: the `reason` for [`approve_first`].
pub fn admin_reason(vault: &Vault<Keys>, request: &Request) -> Result<Option<String>> {
    Ok(Some(match request {
        Request::CreateCollection { name, .. } => new_collection(vault, name)?,
        Request::Revoke { device, .. } => revoking(vault, *device),
        Request::SetScope {
            device,
            collection,
            scope,
            ..
        } => scope_change(vault, *device, collection, *scope)?.1,
        Request::SetScopes {
            device, changes, ..
        } => scope_changes(vault, *device, changes)?.1,
        _ => return Ok(None),
    }))
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
/// `approved` is this device's admin key if [`approve_first`] already asked for it.
pub fn approve_join(
    vault: &mut Vault<Keys>,
    admin_key: &Path,
    approved: Option<&dyn AdminKeyTrait>,
    request: &JoinRequest,
    scopes: &[(String, Scope)],
    recovery_phrase: Option<&str>,
) -> Result<Approval> {
    let (collections, reason) = joining(vault, request, scopes)?;
    as_admin(
        vault,
        admin_key,
        approved,
        recovery_phrase,
        "approving a device",
        reason,
        |vault, admin| vault.approve_join(request, &collections, &admin),
    )
}

/// The collections a join is approved with, and what the dialog says, after the checks that come
/// before asking.
pub fn joining(
    vault: &Vault<Keys>,
    request: &JoinRequest,
    scopes: &[(String, Scope)],
) -> Result<(Vec<(CollectionId, Scope)>, String)> {
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
    Ok((
        collections,
        format!("add {} to your vault", request.name.name),
    ))
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
                cx.admin,
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
            let reason = revoking(vault, device);
            let revocation = as_admin(
                vault,
                cx.admin_key,
                cx.admin,
                recovery_phrase.as_deref().map(String::as_str),
                "revoking a device",
                reason,
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
            let (id, reason) = scope_change(vault, device, &collection, scope)?;
            let change = as_admin(
                vault,
                cx.admin_key,
                cx.admin,
                recovery_phrase.as_deref().map(String::as_str),
                "changing a scope",
                reason,
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
            let (ids, reason) = scope_changes(vault, device, &changes)?;
            let changed = as_admin(
                vault,
                cx.admin_key,
                cx.admin,
                recovery_phrase.as_deref().map(String::as_str),
                "changing a scope",
                reason,
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

/// Runs `f` with an admin signature: this device's admin key when it has one, which is
/// `approved` if [`approve_first`] asked already and otherwise asks for Touch ID with `reason`,
/// and the recovery key from `recovery_phrase` when it has none. Without a phrase it fails with
/// [`RecoveryPhraseNeeded`] for `action`.
fn as_admin<T>(
    vault: &mut Vault<Keys>,
    admin_key: &Path,
    approved: Option<&dyn AdminKeyTrait>,
    recovery_phrase: Option<&str>,
    action: &'static str,
    reason: String,
    f: impl FnOnce(&mut Vault<Keys>, &dyn AdminKeyTrait) -> openvault_core::Result<T>,
) -> Result<T> {
    // Listed when it was asked for; checked again, since the log may have changed since.
    if let Some(admin) = approved.filter(|admin| is_admin(vault, admin)) {
        return Ok(f(vault, admin)?);
    }
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

/// Signs with this device's admin key when it has one, `approved` or asking for Touch ID as
/// [`as_admin`] does, and with the recovery key otherwise. A vault from before the membership log
/// starts it first.
fn create_collection(
    vault: &mut Vault<Keys>,
    admin_key: &Path,
    approved: Option<&dyn AdminKeyTrait>,
    name: &str,
    recovery_phrase: Option<&str>,
) -> Result<()> {
    let reason = new_collection(vault, name)?;
    if let Some(admin) = approved.filter(|admin| is_admin(vault, admin)) {
        vault.create_collection(name, &admin)?;
        return Ok(());
    }
    if let Some(admin) = listed_admin_key(vault, admin_key)? {
        vault.create_collection(name, &admin.with_reason(reason))?;
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
    let key = match AdminKey::load(path) {
        Ok(key) => key,
        Err(openvault_keystore::Error::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e).context("can't load this device's admin key"),
    };
    Ok(is_admin(vault, &key).then_some(key))
}

/// Whether the vault lists `key` as an admin.
fn is_admin(vault: &Vault<Keys>, key: &dyn AdminKeyTrait) -> bool {
    vault
        .membership()
        .is_some_and(|m| m.admins().contains(&key.verifying_key()))
}

/// What the dialog says for creating the collection `name`, after the checks that come before
/// asking for Touch ID or 24 words.
fn new_collection(vault: &Vault<Keys>, name: &str) -> Result<String> {
    names::check_collection(name)?;
    if vault.collection(name).is_ok() {
        bail!("collection {name} already exists");
    }
    Ok(format!("create the collection {name}"))
}

/// What the dialog says for revoking `device`.
fn revoking(vault: &Vault<Keys>, device: DeviceId) -> String {
    format!("remove {} from your vault", device_name(vault, device))
}

/// The collection a scope change is for and what the dialog says, after the checks that come
/// before asking for Touch ID or 24 words.
fn scope_change(
    vault: &Vault<Keys>,
    device: DeviceId,
    collection: &str,
    scope: Scope,
) -> Result<(CollectionId, String)> {
    let id = vault.collection(collection)?;
    let name = device_name(vault, device);
    if vault
        .membership()
        .is_some_and(|m| m.scope(device, id) == scope)
    {
        bail!("{name} already has that scope on {collection}");
    }
    Ok((id, format!("change what {name} may do with {collection}")))
}

/// A scope change to make: the collection, the new scope, and the collection's name.
type ScopeChange<'c> = (CollectionId, Scope, &'c str);

/// The scope changes to make and what the dialog says, after the checks that come before asking
/// for Touch ID or 24 words. Changes to the scope the device already has are left out.
fn scope_changes<'c>(
    vault: &Vault<Keys>,
    device: DeviceId,
    changes: &'c [(String, Scope)],
) -> Result<(Vec<ScopeChange<'c>>, String)> {
    let name = device_name(vault, device);
    let mut ids: Vec<ScopeChange> = Vec::with_capacity(changes.len());
    for (collection, scope) in changes {
        let id = vault.collection(collection)?;
        if ids.iter().any(|(other, ..)| *other == id) {
            bail!("{collection} is given more than one scope");
        }
        if vault
            .membership()
            .is_none_or(|m| m.scope(device, id) != *scope)
        {
            ids.push((id, *scope, collection.as_str()));
        }
    }
    if ids.is_empty() {
        bail!("{name} already has those scopes");
    }
    let collections = ids
        .iter()
        .map(|(.., collection)| *collection)
        .collect::<Vec<_>>()
        .join(", ");
    Ok((ids, format!("change what {name} may do with {collections}")))
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use openvault_crypto::{Signature, SignatureContext, SigningKey, VerifyingKey};
    use openvault_keystore::Backend;

    use super::*;

    /// An admin key that asks like the Secure Enclave's: `ask`, or else its first signature, waits
    /// for the user, who here is the test.
    struct Asking {
        key: SigningKey,
        approved: AtomicBool,
        prompts: AtomicUsize,
        /// Told when the key starts asking.
        asking: Mutex<mpsc::Sender<()>>,
        /// The user's answer.
        answer: Mutex<mpsc::Receiver<()>>,
    }

    impl Asking {
        fn wait_for_user(&self) {
            if !self.approved.load(Ordering::SeqCst) {
                self.prompts.fetch_add(1, Ordering::SeqCst);
                self.asking.lock().unwrap().send(()).unwrap();
                self.answer.lock().unwrap().recv().unwrap();
                self.approved.store(true, Ordering::SeqCst);
            }
        }
    }

    impl AdminKeyTrait for Asking {
        fn verifying_key(&self) -> VerifyingKey {
            self.key.verifying_key()
        }

        fn sign(
            &self,
            context: SignatureContext,
            message: &[u8],
        ) -> openvault_core::Result<Signature> {
            self.wait_for_user();
            Ok(self.key.sign(context, message))
        }
    }

    impl Asks for Asking {
        fn ask(&self) -> Result<()> {
            self.wait_for_user();
            Ok(())
        }
    }

    impl Asks for &Asking {
        fn ask(&self) -> Result<()> {
            (**self).ask()
        }
    }

    struct Setup {
        _dir: tempfile::TempDir,
        vault: Arc<Mutex<Vault<Keys>>>,
        admin_key: std::path::PathBuf,
        key: Asking,
        asking: mpsc::Receiver<()>,
        answer: mpsc::Sender<()>,
        recovery: RecoveryKey,
    }

    /// A vault whose admins are the recovery key and an [`Asking`] key.
    fn setup() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let keys = Keys::create(&dir.path().join("keys"), Backend::Software).unwrap();
        let key = SigningKey::generate_p256();
        let recovery = RecoveryKey::generate();
        let vault = Vault::create(
            &dir.path().join("vault"),
            keys,
            &recovery,
            "Mac",
            Some(key.verifying_key()),
        )
        .unwrap();
        let (tell, asking) = mpsc::channel();
        let (answer, answers) = mpsc::channel();
        Setup {
            admin_key: dir.path().join("no admin key file"),
            _dir: dir,
            vault: Arc::new(Mutex::new(vault)),
            key: Asking {
                key,
                approved: AtomicBool::new(false),
                prompts: AtomicUsize::new(0),
                asking: Mutex::new(tell),
                answer: Mutex::new(answers),
            },
            asking,
            answer,
            recovery,
        }
    }

    /// Runs `request` as the service does (server.rs, `answer`), with `key` as this device's
    /// admin key.
    fn answer(
        vault: &Mutex<Vault<Keys>>,
        admin_key: &Path,
        key: Asking,
        request: Request,
    ) -> (Response, Asking) {
        let approved = match approve_first(
            vault,
            |vault| admin_reason(vault, &request),
            |_, _| Ok(Some(key)),
        ) {
            Ok(approved) => approved.expect("an admin signs it"),
            Err(error) => panic!("{error:#}"),
        };
        let mut vault = vault.lock().unwrap();
        let response = handle(
            &mut Context {
                vault: &mut vault,
                admin_key,
                admin: Some(&approved),
                visible: None,
            },
            request,
        );
        (response, approved)
    }

    #[test]
    fn touch_id_is_asked_for_with_the_vault_unlocked() {
        let s = setup();
        let request = Request::CreateCollection {
            name: "documents".to_owned(),
            recovery_phrase: None,
        };
        let running = {
            let vault = s.vault.clone();
            let admin_key = s.admin_key.clone();
            std::thread::spawn(move || answer(&vault, &admin_key, s.key, request))
        };
        s.asking
            .recv_timeout(Duration::from_secs(10))
            .expect("asks for Touch ID");

        // While the dialog is open, sync sessions and other requests still get the vault.
        let mut vault = s
            .vault
            .try_lock()
            .expect("the vault is unlocked while Touch ID asks");
        let listed = handle(
            &mut Context {
                vault: &mut vault,
                admin_key: &s.admin_key,
                admin: None,
                visible: None,
            },
            Request::Collections,
        );
        assert!(matches!(listed, Response::Names(names) if names.is_empty()));
        drop(vault);

        s.answer.send(()).unwrap();
        let (response, key) = running.join().unwrap();
        assert!(matches!(response, Response::Done), "{response:?}");
        assert_eq!(key.prompts.load(Ordering::SeqCst), 1, "asked once");
        assert!(s.vault.lock().unwrap().collection("documents").is_ok());
    }

    #[test]
    fn a_request_that_fails_its_checks_asks_for_nothing() {
        let s = setup();
        s.vault
            .lock()
            .unwrap()
            .create_collection("documents", &s.recovery.admin_signing_key())
            .unwrap();
        let request = Request::CreateCollection {
            name: "documents".to_owned(),
            recovery_phrase: None,
        };
        let Err(error) = approve_first(
            &s.vault,
            |vault| admin_reason(vault, &request),
            |_, _| Ok(Some(&s.key)),
        ) else {
            panic!("a collection that exists is created again");
        };
        assert_eq!(error.to_string(), "collection documents already exists");
        assert_eq!(s.key.prompts.load(Ordering::SeqCst), 0);
        assert!(s.asking.try_recv().is_err());
    }
}
