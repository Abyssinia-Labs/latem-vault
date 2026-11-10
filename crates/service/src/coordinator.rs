//! The device's connection to its coordinator (coordinator.md, devices): open while the service
//! runs, and opened again after a failure, 30 seconds later, doubling up to an hour.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use openvault_core::Vault;
use openvault_keystore::Keys;
use openvault_net::Node;
use openvault_net::coord::{self, Address};
use openvault_net::frame::Reason;
use openvault_net::sync::SyncError;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::engine::Engine;

/// The first retry after the connection fails, doubling to [`LAST_RETRY`], as for sync.
const FIRST_RETRY: Duration = Duration::from_secs(30);
const LAST_RETRY: Duration = Duration::from_secs(60 * 60);
/// A connection that lasted this long starts the retries over.
const SETTLED: Duration = Duration::from_secs(10 * 60);

/// Keeps a connection to the coordinator at `address` until the service stops, or until the
/// coordinator says this device isn't a member, which also takes the relay away.
pub(crate) async fn keep(
    address: Address,
    node: Arc<Node>,
    vault: Arc<Mutex<Vault<Keys>>>,
    engine: Arc<Engine>,
) {
    let (sender, mut notices) = mpsc::channel(8);
    engine.set_coordinator(sender);
    let mut delay = FIRST_RETRY;
    loop {
        // What the log did while there was no connection, the next hello says anyway.
        while notices.try_recv().is_ok() {}
        let started = Instant::now();
        let result = match coord::connect(node.endpoint(), &address).await {
            Ok(connection) => {
                info!("connected to the coordinator at {}", address.hostname);
                coord::run(connection, vault.clone(), &mut notices, || {
                    engine.log_changed();
                })
                .await
            }
            Err(e) => Err(e),
        };
        if started.elapsed() >= SETTLED {
            delay = FIRST_RETRY;
        }
        match result {
            Err(SyncError::Refused(Reason::NotAMember)) => {
                warn!(
                    "the coordinator says this device isn't a member; leaving the relay until \
                     the service starts again"
                );
                node.endpoint().remove_relay(&address.relay_url()).await;
                return;
            }
            Err(e) => warn!(
                "the coordinator at {}: {e}; trying again in {}s",
                address.hostname,
                delay.as_secs()
            ),
            Ok(()) => return,
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(LAST_RETRY);
    }
}
