//! The PinkVault service (`docs/spec/service.md`): the one process on a device that holds the
//! vault open. It runs the device's iroh endpoint and answers the CLI on a local socket.
//!
//! [`handler`] is what each request does. The service runs it for requests on its socket, and
//! the CLI runs it in-process when no service is running.

pub mod api;
#[cfg(unix)]
pub mod client;
#[cfg(all(unix, feature = "coordinator"))]
mod coordinator;
#[cfg(unix)]
mod engine;
#[cfg(unix)]
mod fetch;
pub mod files;
pub mod handler;
pub mod home;
#[cfg(unix)]
mod server;
pub mod setup;

#[cfg(unix)]
pub use server::run;

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::Context as _;
use pinkvault_core::membership;
use pinkvault_net::coord::Address;

/// The files in the vault directory.
pub const VAULT: &str = "vault.db";
pub const KEYS: &str = "keys";
pub const ADMIN_KEY: &str = "admin";
pub const SOCKET: &str = "service.sock";
pub const LOCK: &str = "service.lock";
/// The grandfather's address, if this device uses a coordinator (coordinator.md, devices).
pub const COORDINATOR: &str = "coordinator";

/// The grandfather configured in the vault directory `dir`, if any.
pub fn configured_coordinator(dir: &Path) -> anyhow::Result<Option<Address>> {
    let path = dir.join(COORDINATOR);
    match fs::read_to_string(&path) {
        Ok(text) => Ok(Some(
            text.parse()
                .with_context(|| format!("in {}", path.display()))?,
        )),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("can't read {}", path.display())),
    }
}

/// This computer's host name without `.local`, as the device's name in the membership log.
pub fn default_device_name() -> String {
    let host = hostname().unwrap_or_default();
    let host = host.strip_suffix(".local").unwrap_or(&host);
    let mut name = String::new();
    for c in host.chars().filter(|c| !c.is_control()) {
        if name.len() + c.len_utf8() > membership::MAX_NAME_LEN {
            break;
        }
        name.push(c);
    }
    if name.is_empty() {
        "device".to_owned()
    } else {
        name
    }
}

#[cfg(unix)]
fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the pointer and length describe `buf`, which gethostname writes into.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

#[cfg(not(unix))]
fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}
