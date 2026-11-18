//! A node starts mDNS again when it stops (service.md, discovery).
//!
//! In a file of its own because a stop is for every node in the process: in the library's tests
//! it would restart the nodes of `endpoints_find_each_other` too.

use std::time::Duration;

use latem_vault_net::{Event, Node, Options, discovery_stops, discovery_watch};
use tokio::sync::mpsc;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Options under an mDNS service name for this test process alone, so its nodes meet only each
/// other, and no real device on the network sees them (service.md, finding devices).
fn options() -> Options {
    Options {
        mdns_service: format!("ovt-{:x}", std::process::id()),
        ..Options::default()
    }
}

/// Waits for `expected`, skipping other events: other tests' endpoints share the network.
async fn until(events: &mut mpsc::Receiver<Event>, expected: Event, wait: Duration) {
    tokio::time::timeout(wait, async {
        while events.recv().await != Some(expected) {}
    })
    .await
    .unwrap_or_else(|_| panic!("no {expected:?}"));
}

/// Two nodes find each other; swarm-discovery's guardian says it stopped, as it does when a
/// receiver's socket fails; both forget the other and find it again with a new mDNS. Needs a
/// network interface that carries multicast.
#[tokio::test(flavor = "multi_thread")]
async fn discovery_starts_again_after_it_stops() {
    tracing_subscriber::registry()
        .with(discovery_watch())
        .init();
    let (a, mut a_events) = Node::start(&[1; 32], options()).await.unwrap();
    let (b, mut b_events) = Node::start(&[2; 32], options()).await.unwrap();
    until(
        &mut a_events,
        Event::Visible(b.id()),
        Duration::from_secs(30),
    )
    .await;
    until(
        &mut b_events,
        Event::Visible(a.id()),
        Duration::from_secs(30),
    )
    .await;

    // The guardian's other warnings don't stop it, and other actors' warnings aren't its.
    let before = discovery_stops();
    tracing::warn!(target: "swarm_discovery::guardian", "Failed to add interface {}: {}", "192.0.2.1", "test");
    tracing::warn!(target: "swarm_discovery::sender", "actor {} stopped", 1);
    tracing::info!(target: "swarm_discovery::guardian", "actor {} stopped", 1);
    assert_eq!(discovery_stops(), before);

    // Its words when a receiver's socket fails, as swarm-discovery 0.6.5 logs them.
    tracing::warn!(
        target: "swarm_discovery::guardian",
        "actor {:?} ({}) failed: {}",
        "ActoId(3)",
        "receiver_v4(swarm-discovery/3)",
        "Could not receive from the socket"
    );
    assert_eq!(discovery_stops(), before + 1);

    until(&mut a_events, Event::Gone(b.id()), Duration::from_secs(5)).await;
    assert!(!a.visible().contains(&b.id()));
    // The first wait is 5 seconds, then a query goes out within one cadence.
    until(
        &mut a_events,
        Event::Visible(b.id()),
        Duration::from_secs(60),
    )
    .await;
    until(
        &mut b_events,
        Event::Visible(a.id()),
        Duration::from_secs(60),
    )
    .await;
    assert!(a.visible().contains(&b.id()));
    // The new mDNS took the stopped one's place rather than joining it.
    assert_eq!(a.endpoint().address_lookup().unwrap().len(), 1);

    a.close().await;
    b.close().await;
}
