//! The OpenVault service (`docs/spec/service.md`): the one process on a device that holds the
//! vault open. It runs the device's iroh endpoint and answers the CLI on a local socket.
//!
//! [`handler`] is what each request does. The service runs it for requests on its socket, and
//! the CLI runs it in-process when no service is running.

pub mod api;
#[cfg(unix)]
pub mod client;
#[cfg(unix)]
mod engine;
pub mod handler;
#[cfg(unix)]
mod server;

#[cfg(unix)]
pub use server::run;

use openvault_core::membership;

/// The files in the openvault directory.
pub const VAULT: &str = "vault.db";
pub const KEYS: &str = "keys";
pub const ADMIN_KEY: &str = "admin";
pub const SOCKET: &str = "service.sock";
pub const LOCK: &str = "service.lock";

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
