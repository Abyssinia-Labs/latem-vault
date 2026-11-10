//! Noticing when mDNS discovery stops (`docs/spec/service.md`, discovery).
//!
//! swarm-discovery runs mDNS as a guardian actor with a sender, an updater and a receiver per
//! socket under it. When any of them ends, as a receiver does when its socket returns an error,
//! the guardian logs one warning and stops, and the others stop with it: the endpoint neither
//! announces itself nor hears anyone from then on. Nothing in iroh-mdns-address-lookup's API
//! says so, and the lookup keeps answering with what it last knew. The warning is the only sign,
//! so this layer counts each one, and a [`Node`](crate::Node) starts discovery again when the
//! count changes.

use std::fmt;
use std::sync::LazyLock;

use tokio::sync::watch;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Where swarm-discovery's guardian logs.
const GUARDIAN: &str = "swarm_discovery::guardian";

/// How the guardian's warning that it stopped begins: "actor {id} ({name}) stopped", "failed:
/// {error}" or "aborted: {error}". Its other warnings, about adding an interface, don't stop it.
const STOPPED: &str = "actor ";

/// How many times mDNS discovery has stopped in this process.
static STOPS: LazyLock<watch::Sender<u64>> = LazyLock::new(|| watch::channel(0).0);

/// A tracing layer that tells this process's [`Node`](crate::Node)s when mDNS discovery stops,
/// so they can start it again. A process that keeps a node for long, as `openvault service`
/// does, adds it to its subscriber. It has a filter of its own, so it sees the guardian's
/// warnings whatever the other layers leave out, and asks for nothing else.
pub fn discovery_watch<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    Watch.with_filter(Targets::new().with_target(GUARDIAN, Level::WARN))
}

/// How many times the [`discovery_watch`] layer has seen mDNS discovery stop in this process.
pub fn discovery_stops() -> u64 {
    *STOPS.borrow()
}

/// Changes each time discovery stops.
pub(crate) fn stops() -> watch::Receiver<u64> {
    STOPS.subscribe()
}

struct Watch;

impl<S: Subscriber> Layer<S> for Watch {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let metadata = event.metadata();
        if metadata.target() != GUARDIAN || *metadata.level() != Level::WARN {
            return;
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        if message.0.starts_with(STOPPED) {
            STOPS.send_modify(|stops| *stops += 1);
        }
    }
}

/// An event's message, as it was formatted.
struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}
