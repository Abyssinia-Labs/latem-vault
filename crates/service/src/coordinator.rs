//! The device's exchanges with its coordinator (coordinator.md, devices): one when the service
//! starts, one whenever this device's log changes, and one every [`CHECK`] to hear of entries it
//! doesn't have. Each brings the logs level and closes. After a failure the next comes 30 seconds
//! later, doubling up to an hour.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use openvault_core::Vault;
use openvault_keystore::Keys;
use openvault_net::Node;
use openvault_net::coord::{self, Address};
use openvault_net::frame::Reason;
use openvault_net::sync::{Notice, SyncError};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::engine::Engine;

/// How often a device asks the coordinator for entries, when its own log hasn't changed.
const CHECK: Duration = Duration::from_secs(15 * 60);
/// The first retry after an exchange fails, doubling to [`LAST_RETRY`], as for sync.
const FIRST_RETRY: Duration = Duration::from_secs(30);
const LAST_RETRY: Duration = Duration::from_secs(60 * 60);

/// Exchanges with the coordinator at `address` until the service stops, or until the coordinator
/// says this device isn't a member, which also takes the relay away.
pub(crate) async fn keep(
    address: Address,
    node: Arc<Node>,
    vault: Arc<Mutex<Vault<Keys>>>,
    engine: Arc<Engine>,
) {
    let (sender, mut notices) = mpsc::channel(8);
    engine.set_coordinator(sender);
    let mut next = Instant::now();
    let mut retry = FIRST_RETRY;
    let mut failing = false;
    let mut reached = false;
    loop {
        // A change here starts an exchange at once, unless exchanges are failing.
        tokio::select! {
            () = tokio::time::sleep_until(next) => {}
            notice = notices.recv(), if !failing => match notice {
                Some(Notice::Log) => {}
                Some(Notice::Changed(_)) => continue,
                None => return,
            },
        }
        // One exchange covers every change so far.
        while notices.try_recv().is_ok() {}
        let result = match coord::connect(node.endpoint(), &address).await {
            Ok(connection) => {
                coord::exchange(connection, vault.clone(), || engine.log_grew()).await
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => {
                if reached {
                    debug!("level with the coordinator at {}", address.hostname);
                } else {
                    info!("level with the coordinator at {}", address.hostname);
                }
                (reached, failing, retry) = (true, false, FIRST_RETRY);
                next = Instant::now() + CHECK;
            }
            Err(SyncError::Refused(Reason::NotAMember)) => {
                warn!(
                    "the coordinator says this device isn't a member; leaving the relay until \
                     the service starts again"
                );
                node.endpoint().remove_relay(&address.relay_url()).await;
                return;
            }
            Err(e) => {
                warn!(
                    "the coordinator at {}: {e}; trying again in {}s",
                    address.hostname,
                    retry.as_secs()
                );
                (reached, failing) = (false, true);
                next = Instant::now() + retry;
                retry = (retry * 2).min(LAST_RETRY);
            }
        }
    }
}
