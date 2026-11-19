//! A grandfather on this machine with two of a vault's devices (coordinator.md): the coordinator
//! takes the log from a device and keeps it checked, the relay then admits the members and
//! refuses everyone else, and the devices sync through it with no direct paths.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{Endpoint, Watcher as _};
use n0_future::StreamExt as _;
use pinkvault_core::join::JoinRequest;
use pinkvault_core::membership::{DeviceName, Scope};
use pinkvault_core::{CollectionId, DeviceId, Kind, SoftwareKeys, Vault, VaultId, transport_seed};
use pinkvault_crypto::RecoveryKey;
use pinkvault_grandfather::{Certificate, Config, Grandfather, Listen};
use pinkvault_net::coord::{self, Address};
use pinkvault_net::frame::Reason;
use pinkvault_net::sync::{self, Role, SyncError};
use pinkvault_net::{CaTlsConfig, EndpointAddr, Options, Relay, RelayUrl};
use tokio::sync::mpsc;

type Store = Mutex<Vault<SoftwareKeys>>;

const WAIT: Duration = Duration::from_secs(20);

struct Vaults {
    dir: tempfile::TempDir,
    recovery: RecoveryKey,
    admin: Arc<Store>,
    admin_seed: [u8; 32],
    joined: Arc<Store>,
    joined_seed: [u8; 32],
    joined_id: DeviceId,
    latem: CollectionId,
}

/// An admin vault with `latem` holding `entries` secrets, and a device that joined it with read
/// on `latem`.
fn vaults(entries: usize) -> Vaults {
    let dir = tempfile::tempdir().unwrap();
    let recovery = RecoveryKey::generate();
    let admin_keys = SoftwareKeys::generate();
    let admin_seed = transport_seed(&admin_keys);
    let mut admin = Vault::create(
        &dir.path().join("admin.db"),
        admin_keys,
        &recovery,
        "Mini",
        None,
    )
    .unwrap();
    let latem = admin
        .create_collection("latem", &recovery.admin_signing_key())
        .unwrap();
    for i in 0..entries {
        admin
            .set(
                latem,
                &format!("prod/KEY_{i}"),
                Kind::Secret,
                format!("value {i}").as_bytes(),
            )
            .unwrap();
    }
    let joiner_keys = SoftwareKeys::generate();
    let joined_seed = transport_seed(&joiner_keys);
    let joined_id = DeviceId::random();
    let name = DeviceName {
        platform: "macos".into(),
        name: "MacBook".into(),
    };
    let request = JoinRequest::sign(&[1; 32], joined_id, &joiner_keys, name.clone()).unwrap();
    let approval = admin
        .approve_join(
            &request,
            &[(latem, Scope::Read)],
            &recovery.admin_signing_key(),
        )
        .unwrap();
    let head = admin.membership().unwrap().head();
    let joined = Vault::join(
        &dir.path().join("joined.db"),
        joiner_keys,
        joined_id,
        &name,
        head,
        &approval.log,
        &approval.grants,
    )
    .unwrap();
    Vaults {
        dir,
        recovery,
        admin: Arc::new(Mutex::new(admin)),
        admin_seed: *admin_seed,
        joined: Arc::new(Mutex::new(joined)),
        joined_seed: *joined_seed,
        joined_id,
        latem,
    }
}

/// A grandfather for `vault` on loopback, with a self-signed certificate. Returns it with the
/// relay devices are to use, trusting that certificate.
async fn grandfather(dir: &std::path::Path, vault: Option<VaultId>) -> (Grandfather, Relay) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let loopback = ([127, 0, 0, 1], 0).into();
    let grandfather = Grandfather::start(Config {
        data: dir.join("grandfather"),
        vault,
        hostname: "127.0.0.1".into(),
        port: 443,
        certificate: Certificate::Files {
            cert: cert_path,
            key: key_path,
        },
        listen: Listen {
            https: loopback,
            coordinator: vec![loopback],
        },
    })
    .await
    .unwrap();
    let url: RelayUrl = format!("https://{}", grandfather.https_addr().unwrap())
        .parse()
        .unwrap();
    let relay = Relay {
        url,
        roots: CaTlsConfig::custom_roots([cert.cert.der().clone()]),
    };
    (grandfather, relay)
}

/// The coordinator's address as devices would have it, with the port it listens on.
fn coordinator(grandfather: &Grandfather) -> Address {
    Address {
        port: grandfather.coordinator_addrs()[0].port(),
        ..grandfather.address().clone()
    }
}

/// An endpoint with direct paths, as a device's service has, for talking to the coordinator.
async fn direct(seed: &[u8; 32]) -> Endpoint {
    pinkvault_net::builder(seed, &Options::default())
        .unwrap()
        .bind()
        .await
        .unwrap()
}

/// An endpoint that can only use `relay`.
async fn relay_only(seed: &[u8; 32], relay: &Relay) -> Endpoint {
    let options = Options {
        alpns: vec![sync::ALPN.to_vec()],
        relay: Some(relay.clone()),
        ..Options::default()
    };
    pinkvault_net::builder(seed, &options)
        .unwrap()
        .clear_ip_transports()
        .bind()
        .await
        .unwrap()
}

/// One exchange between a device and the coordinator, as its service has at start, when its log
/// changes and every 15 minutes.
async fn exchange(
    endpoint: &Endpoint,
    address: &Address,
    store: &Arc<Store>,
) -> Result<(), SyncError> {
    let connection = coord::connect(endpoint, address).await?;
    tokio::time::timeout(WAIT, coord::exchange(connection, store.clone(), || {}))
        .await
        .expect("an exchange ends")
}

fn head(store: &Store) -> u64 {
    store.lock().unwrap().membership().unwrap().head().0
}

#[tokio::test(flavor = "multi_thread")]
async fn members_sync_through_the_relay_and_strangers_are_refused() {
    let v = vaults(3);
    let vault = v.admin.lock().unwrap().vault_id();
    let (grandfather, relay) = grandfather(v.dir.path(), Some(vault)).await;
    assert_eq!(grandfather.log_head(), None);

    // Before the coordinator has the log, the relay knows no members.
    let early = relay_only(&v.joined_seed, &relay).await;
    let refused = tokio::time::timeout(WAIT, async {
        let mut statuses = early.home_relay_status().stream();
        while let Some(statuses) = statuses.next().await {
            if statuses.iter().any(|s| s.auth_denied_reason().is_some()) {
                return;
            }
        }
    })
    .await;
    assert!(refused.is_ok(), "the relay admitted a device it can't know");
    early.close().await;

    // The admin gives the coordinator the log.
    let admin_direct = direct(&v.admin_seed).await;
    exchange(&admin_direct, &coordinator(&grandfather), &v.admin)
        .await
        .unwrap();
    assert_eq!(grandfather.log_head(), Some(head(&v.admin)));
    admin_direct.close().await;

    // Now both members get in, and sync with no direct path between them.
    let admin = relay_only(&v.admin_seed, &relay).await;
    let joined = relay_only(&v.joined_seed, &relay).await;
    for endpoint in [&admin, &joined] {
        tokio::time::timeout(WAIT, endpoint.online())
            .await
            .expect("a member reaches the relay");
    }
    let accepting = {
        let joined = joined.clone();
        let store = v.joined.clone();
        tokio::spawn(async move {
            let connection: Connection = joined.accept().await.unwrap().await.unwrap();
            let (_tx, rx) = mpsc::channel(1);
            sync::run(
                connection,
                Role::Accepter,
                store,
                rx,
                Duration::from_secs(2),
                |_| {},
            )
            .await
        })
    };
    let to_joined = EndpointAddr::new(joined.id()).with_relay_url(relay.url.clone());
    let connection = tokio::time::timeout(WAIT, admin.connect(to_joined, sync::ALPN))
        .await
        .unwrap()
        .unwrap();
    let (_tx, rx) = mpsc::channel(1);
    let opened = sync::run(
        connection,
        Role::Opener,
        v.admin.clone(),
        rx,
        Duration::from_secs(2),
        |_| {},
    )
    .await
    .unwrap();
    let accepted = accepting.await.unwrap().unwrap();
    assert_eq!(opened.dropped + accepted.dropped, 0);
    let entry = v
        .joined
        .lock()
        .unwrap()
        .get(v.latem, "prod/KEY_2")
        .unwrap()
        .unwrap();
    assert_eq!(&entry.value[..], b"value 2");

    // A stranger is refused.
    let stranger = relay_only(&[9; 32], &relay).await;
    let refused = tokio::time::timeout(WAIT, async {
        let mut statuses = stranger.home_relay_status().stream();
        while let Some(statuses) = statuses.next().await {
            if statuses.iter().any(|s| s.auth_denied_reason().is_some()) {
                return;
            }
        }
    })
    .await;
    assert!(refused.is_ok(), "the relay admitted a stranger");

    for endpoint in [admin, joined, stranger] {
        endpoint.close().await;
    }
    grandfather.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_coordinator_keeps_a_checked_log_for_devices_that_are_behind() {
    let v = vaults(0);
    let vault = v.admin.lock().unwrap().vault_id();
    let (grandfather, _relay) = grandfather(v.dir.path(), Some(vault)).await;
    let address = coordinator(&grandfather);

    // The admin gives the coordinator the log, and later a new collection; each exchange ends
    // once the coordinator has what the admin has.
    let admin_direct = direct(&v.admin_seed).await;
    exchange(&admin_direct, &address, &v.admin).await.unwrap();
    assert_eq!(grandfather.log_head(), Some(head(&v.admin)));
    v.admin
        .lock()
        .unwrap()
        .create_collection("ssh", &v.recovery.admin_signing_key())
        .unwrap();
    exchange(&admin_direct, &address, &v.admin).await.unwrap();
    let expected = head(&v.admin);
    assert_eq!(grandfather.log_head(), Some(expected));

    // The joined device is behind, and catches up from the coordinator alone. A second exchange
    // finds the logs level at once.
    assert!(head(&v.joined) < expected);
    let joined_direct = direct(&v.joined_seed).await;
    exchange(&joined_direct, &address, &v.joined).await.unwrap();
    assert_eq!(head(&v.joined), expected);
    exchange(&joined_direct, &address, &v.joined).await.unwrap();

    // Another vault's device is refused.
    let other = vaults(0);
    let other_direct = direct(&other.admin_seed).await;
    assert!(matches!(
        exchange(&other_direct, &address, &other.admin).await,
        Err(SyncError::Refused(Reason::WrongVault))
    ));

    // Once revoked, the joined device is refused too, although its own log doesn't say so yet.
    v.admin
        .lock()
        .unwrap()
        .revoke_device(v.joined_id, &v.recovery.admin_signing_key())
        .unwrap();
    exchange(&admin_direct, &address, &v.admin).await.unwrap();
    let revoked = head(&v.admin);
    assert_eq!(grandfather.log_head(), Some(revoked));
    assert!(matches!(
        exchange(&joined_direct, &address, &v.joined).await,
        Err(SyncError::Refused(Reason::NotAMember))
    ));
    for endpoint in [admin_direct, joined_direct, other_direct] {
        endpoint.close().await;
    }

    // The copy lasts across a restart, and stays the vault's.
    let data = v.dir.path().to_owned();
    grandfather.shutdown().await;
    let (restarted, _) = self::grandfather(&data, None).await;
    assert_eq!(restarted.log_head(), Some(revoked));
    assert_eq!(restarted.vault(), vault);
    restarted.shutdown().await;
    let other_vault = Grandfather::start(Config {
        data: data.join("grandfather"),
        vault: Some(VaultId::random()),
        hostname: "127.0.0.1".into(),
        port: 443,
        certificate: Certificate::Files {
            cert: data.join("cert.pem"),
            key: data.join("key.pem"),
        },
        listen: Listen {
            https: ([127, 0, 0, 1], 0).into(),
            coordinator: vec![([127, 0, 0, 1], 0).into()],
        },
    })
    .await;
    assert!(other_vault.is_err(), "a coordinator keeps its vault");
}
