//! What each request does to the vault. The service runs it for requests on its socket, and the
//! CLI runs it in-process when no service is running, so a command behaves the same either way.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context as _, Result, anyhow, bail};
use openvault_core::{DeviceId, Vault, names};
use openvault_crypto::RecoveryKey;
use openvault_keystore::{AdminKey, Keys};
use openvault_net::EndpointKey;

use crate::api::{DeviceSummary, ErrorCode, Item, Listed, Request, Response, Value};

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
    match run(cx, request) {
        Ok(response) => response,
        Err(error) if error.is::<RecoveryPhraseNeeded>() => Response::Error {
            code: ErrorCode::RecoveryPhraseNeeded,
            message: error.to_string(),
        },
        Err(error) => Response::error(format!("{error:#}")),
    }
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
            Response::Done
        }
        Request::Delete { collection, name } => {
            let id = vault.collection(&collection)?;
            Response::Deleted(vault.delete(id, &name)?)
        }
        Request::List { collection } => {
            let id = vault.collection(&collection)?;
            Response::Listing(
                vault
                    .list(id)?
                    .into_iter()
                    .map(|info| Listed {
                        name: info.name,
                        kind: info.kind,
                    })
                    .collect(),
            )
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
                        value: entry.value,
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
        } => revoke(
            vault,
            cx.admin_key,
            device,
            recovery_phrase.as_ref().map(|phrase| phrase.as_str()),
        )?,
    })
}

/// Signs with this device's admin key when it has one, which asks for Touch ID, and with the
/// recovery key otherwise.
fn revoke(
    vault: &mut Vault<Keys>,
    admin_key: &Path,
    device: DeviceId,
    recovery_phrase: Option<&str>,
) -> Result<Response> {
    let revocation = if let Some(admin) = listed_admin_key(vault, admin_key)? {
        let name = vault
            .device_name(device)
            .ok()
            .flatten()
            .map_or_else(|| device.to_string(), |name| name.name);
        let admin = admin.with_reason(format!("remove {name} from your vault"));
        vault.revoke_device(device, &admin)?
    } else {
        let phrase = recovery_phrase.ok_or(RecoveryPhraseNeeded("revoking a device"))?;
        let recovery = RecoveryKey::from_phrase(phrase)?;
        if !vault.is_recovery_key(&recovery) {
            bail!("that recovery phrase belongs to another vault");
        }
        vault.revoke_device(device, &recovery.admin_signing_key())?
    };
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
