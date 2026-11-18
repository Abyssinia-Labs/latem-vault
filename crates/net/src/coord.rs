//! The device's side of the coordinator protocol (coordinator.md): on one stream of a connection
//! with ALPN `frozen::ALPN_COORD`, a device and the grandfather's coordinator exchange hellos and
//! bring their logs level, and the device closes the connection. It connects when its log grows,
//! and now and then to hear of entries it doesn't have.

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use latem_vault_crypto::hash::Hash;

use crate::EndpointKey;
use crate::frame::{self, FrameError, Reason};
use crate::sync::{SyncError, SyncStore, blocking};
use crate::wire::{self, HELLO, LOG_BATCH, LOG_ENTRIES, LOG_REQUEST};

/// Frozen in [`latem_vault_crypto::frozen`]: it never changes, whatever the product is called.
pub const ALPN: &[u8] = latem_vault_crypto::frozen::ALPN_COORD;

/// The port a grandfather's address means when it names none: TCP for the relay's HTTPS, UDP
/// for the coordinator.
pub const DEFAULT_PORT: u16 = 443;

/// The head hash in the hello of a coordinator that has no log yet.
pub const NO_LOG: Hash = [0; 32];

/// How long a device waits for the coordinator's next message before giving up on an exchange.
pub const QUIET: Duration = Duration::from_secs(30);

/// The most log entries a device takes from the coordinator before the logs are level again.
const MAX_LOG: usize = 4096;

/// A grandfather's address: `ov1:<endpoint id in hex>@<hostname>[:<port>]`
/// (coordinator.md, running the grandfather).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// The coordinator's endpoint id.
    pub endpoint: EndpointKey,
    pub hostname: String,
    pub port: u16,
}

#[derive(Debug, thiserror::Error)]
#[error("not a grandfather's address ({0}); one looks like ov1:<endpoint id>@<hostname>[:<port>]")]
pub struct BadAddress(&'static str);

impl Address {
    /// The relay's url: HTTPS on the address's hostname and port.
    pub fn relay_url(&self) -> RelayUrl {
        format!("https://{}:{}/", self.hostname, self.port)
            .parse()
            .expect("a checked hostname makes a url")
    }

    /// Where the coordinator listens: the hostname's addresses now, on the address's port.
    pub async fn resolve(&self) -> std::io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((self.hostname.as_str(), self.port))
            .await?
            .collect())
    }
}

impl FromStr for Address {
    type Err = BadAddress;

    fn from_str(s: &str) -> Result<Self, BadAddress> {
        let rest = s
            .trim()
            .strip_prefix("ov1:")
            .ok_or(BadAddress("it doesn't start with ov1:"))?;
        let (id, host) = rest.split_once('@').ok_or(BadAddress("there's no @"))?;
        let endpoint = parse_hex(id).ok_or(BadAddress("the endpoint id isn't 64 hex digits"))?;
        let (hostname, port) = match host.rsplit_once(':') {
            Some((hostname, port)) => (
                hostname,
                port.parse()
                    .ok()
                    .filter(|&port| port != 0)
                    .ok_or(BadAddress("the port isn't a number from 1 to 65535"))?,
            ),
            None => (host, DEFAULT_PORT),
        };
        if !is_hostname(hostname) {
            return Err(BadAddress("the hostname isn't one"));
        }
        Ok(Self {
            endpoint,
            hostname: hostname.to_ascii_lowercase(),
            port,
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ov1:")?;
        for byte in self.endpoint {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "@{}", self.hostname)?;
        if self.port != DEFAULT_PORT {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

fn parse_hex(hex: &str) -> Option<EndpointKey> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut key = [0; 32];
    for (byte, pair) in key.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(key)
}

/// A DNS name: dot-separated labels of letters, digits and hyphens, 253 characters at most.
pub fn is_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Connects `endpoint` to the coordinator at `address`, directly: the relay admits only members,
/// and the coordinator is how it learns them (coordinator.md, coordinator).
pub async fn connect(endpoint: &Endpoint, address: &Address) -> Result<Connection, SyncError> {
    let id = EndpointId::from_bytes(&address.endpoint)
        .map_err(|_| SyncError::Connect("the address's endpoint id isn't a key".into()))?;
    let addrs = address
        .resolve()
        .await
        .map_err(|e| SyncError::Connect(format!("can't look up {}: {e}", address.hostname)))?;
    let addr = EndpointAddr::from_parts(id, addrs.into_iter().map(TransportAddr::Ip));
    endpoint
        .connect(addr, ALPN)
        .await
        .map_err(|e| SyncError::Connect(e.to_string()))
}

/// Brings this device's log and the coordinator's level on `connection`, then closes it
/// (coordinator.md, devices). The coordinator says hello first, and again once the logs are level
/// and it has checked this device is a member: that second hello ends the exchange. `grew` is
/// called when entries from the coordinator grow this device's log.
pub async fn exchange<S: SyncStore>(
    connection: Connection,
    store: Arc<S>,
    grew: impl Fn(),
) -> Result<(), SyncError> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| SyncError::Connect(e.to_string()))?;
    let result = drive(&mut send, recv, &*store, &grew).await;
    if let Err(error) = &result
        && let Some(reason) = error.reason()
    {
        frame::send_error(&mut send, reason, &error.to_string()).await;
    }
    connection.close(0u32.into(), b"done");
    result
}

async fn drive<S: SyncStore>(
    send: &mut SendStream,
    mut recv: RecvStream,
    store: &S,
    grew: &impl Fn(),
) -> Result<(), SyncError> {
    let (vault, ..) = blocking(|| store.hello())?;
    send_hello(send, store).await?;
    let mut coordinator_head = None;
    let mut hellos = 0;
    let mut requested = false;
    let mut received = 0;
    loop {
        let (kind, body) = match tokio::time::timeout(QUIET, frame::read(&mut recv)).await {
            Ok(Ok(message)) => message,
            Ok(Err(FrameError::Peer { reason, .. })) => return Err(SyncError::Refused(reason)),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(FrameError::Bad("the coordinator stopped answering").into()),
        };
        // Its first hello comes before it has read this device's, so only a later one can say
        // the logs are level.
        let mut answered = false;
        match kind {
            HELLO => {
                let (theirs, seq, hash) = wire::parse_hello(&body)?;
                if theirs != vault {
                    return Err(SyncError::Refused(Reason::WrongVault));
                }
                coordinator_head = Some((seq, hash));
                hellos += 1;
                answered = hellos > 1;
            }
            // The coordinator isn't a member, but it's the endpoint this device was told to use,
            // and the log isn't secret from it (coordinator.md, logs).
            LOG_REQUEST => {
                let (from, max) = wire::parse_log_request(&body)?;
                let entries = blocking(|| store.log_from(from, max.min(LOG_BATCH)))?;
                frame::write(send, LOG_ENTRIES, &wire::log_entries(&entries)).await?;
                continue;
            }
            LOG_ENTRIES => {
                requested = false;
                let entries = wire::parse_log_entries(&body)?;
                if entries.is_empty() {
                    return Err(FrameError::Bad("no log entries").into());
                }
                received += entries.len();
                if received > MAX_LOG {
                    return Err(FrameError::Bad("too many log entries").into());
                }
                if blocking(|| store.append_log(&entries))? > 0 {
                    grew();
                }
            }
            _ => return Err(FrameError::Bad("unexpected message").into()),
        }
        let Some((seq, hash)) = coordinator_head else {
            continue;
        };
        if hash == NO_LOG && seq == 0 {
            // It has no log yet, and asks for this device's.
            continue;
        }
        let (_, mine, my_hash) = blocking(|| store.hello())?;
        if seq > mine {
            if !requested {
                let max = LOG_BATCH.min(u16::try_from(seq - mine).unwrap_or(LOG_BATCH));
                frame::write(send, LOG_REQUEST, &wire::log_request(mine + 1, max)).await?;
                requested = true;
            }
        } else if seq == mine {
            if hash != my_hash {
                return Err(SyncError::Store(latem_vault_core::Error::Fork));
            }
            if answered {
                return Ok(());
            }
            if kind == LOG_ENTRIES {
                // Caught up: the coordinator's next hello answers this one.
                send_hello(send, store).await?;
            }
        } else if answered {
            // This device's log grew during the exchange: the coordinator asks for the rest.
            send_hello(send, store).await?;
        }
    }
}

async fn send_hello<S: SyncStore>(send: &mut SendStream, store: &S) -> Result<(), SyncError> {
    let (vault, seq, hash) = blocking(|| store.hello())?;
    frame::write(send, HELLO, &wire::hello(vault, seq, &hash)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip_and_are_checked() {
        let id = "ab".repeat(32);
        let address: Address = format!("ov1:{id}@Vault.Example.com").parse().unwrap();
        assert_eq!(address.endpoint, [0xab; 32]);
        assert_eq!(address.hostname, "vault.example.com");
        assert_eq!(address.port, 443);
        assert_eq!(address.to_string(), format!("ov1:{id}@vault.example.com"));
        assert_eq!(
            address.relay_url().to_string(),
            "https://vault.example.com/"
        );

        let other: Address = format!(" ov1:{id}@localhost:8443\n").parse().unwrap();
        assert_eq!(other.port, 8443);
        assert_eq!(other.to_string(), format!("ov1:{id}@localhost:8443"));
        assert_eq!(other.relay_url().to_string(), "https://localhost:8443/");

        for bad in [
            format!("{id}@vault.example.com"),
            format!("ov1:{id}"),
            format!("ov1:{}@vault.example.com", "ab".repeat(31)),
            format!("ov1:{}@vault.example.com", "zz".repeat(32)),
            format!("ov1:{id}@vault.example.com:0"),
            format!("ov1:{id}@vault.example.com:70000"),
            format!("ov1:{id}@vault..example.com"),
            format!("ov1:{id}@vault_example.com"),
            format!("ov1:{id}@-vault.example.com"),
            format!("ov1:{id}@"),
        ] {
            assert!(bad.parse::<Address>().is_err(), "{bad}");
        }
    }
}
