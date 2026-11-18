//! The move from openvault to latem vault in 0.6 (OV-11): the names things had before, and
//! moving `~/.openvault` to `~/.latem-vault` on the first run after it.
//!
//! The move is one rename on the same disk, made only while no service runs for the vault.
//! Nothing in the directory is copied or rewritten: the key file, Secure Enclave keys included,
//! is a file in it and moves with it. Until the move can be made, every command uses the old
//! directory and says why it stayed. This file goes when the old names do (OV-15).

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use anyhow::Result;
use latem_vault_service::home::{self, Location};
use latem_vault_service::{LOCK, SOCKET};

/// `latem-vault service install`'s LaunchAgent before 0.6.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const OLD_LABEL: &str = "local.openvault.service";
/// `latem-vault service install`'s systemd user unit before 0.6.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const OLD_UNIT: &str = "openvault.service";
/// The Mac app's LaunchAgent until the app is renamed too (OV-12). Its build of latem-vault may
/// be older than 0.6, and look for the vault only in the old directory.
pub(crate) const OLD_APP_LABEL: &str = "com.abyssinialabs.openvault.service";

/// The first latem that finds the vault in `~/.latem-vault`. An older one looks only in
/// `~/.openvault`, and would lose the vault once it moves.
const LATEM: Version = Version(0, 12, 0);

/// The vault directory: `LATEM_VAULT_HOME` or `OPENVAULT_HOME` if either is set, else
/// `~/.latem-vault`, moved there from `~/.openvault` first if it can be.
pub(crate) fn locate() -> Result<PathBuf> {
    match Location::from_env()? {
        Location::Chosen(dir) => Ok(dir),
        Location::Default { new, old } => {
            if home::exists(&new) || !old.is_dir() {
                return Ok(new);
            }
            match blocker().map_or_else(|| move_dir(&old, &new), Err) {
                Ok(()) => {
                    eprintln!("Moved the vault from {} to {}.", shown(&old), shown(&new));
                    Ok(new)
                }
                Err(why) => {
                    eprintln!(
                        "The vault stays in {} for now, not {}: {why}.",
                        shown(&old),
                        shown(&new)
                    );
                    Ok(old)
                }
            }
        }
    }
}

/// Why the vault can't move yet, apart from a running service: something that would look for
/// it only in the old directory afterwards.
fn blocker() -> Option<String> {
    if let Some(why) = old_latem() {
        return Some(why);
    }
    #[cfg(unix)]
    {
        crate::login::old_definition_blocks_move().or_else(crate::login::app_blocks_move)
    }
    #[cfg(not(unix))]
    None
}

/// Moves `old` to `new` in one rename, while holding the lock a service holds as long as it
/// runs, so none starts in between.
fn move_dir(old: &Path, new: &Path) -> Result<(), String> {
    let running = || {
        "a service is running for it. Stop it, then run any latem-vault command to move it"
            .to_owned()
    };
    let lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(old.join(LOCK))
        .map_err(|e| format!("can't open its {LOCK} ({e})"))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Err(running()),
        Err(fs::TryLockError::Error(e)) => return Err(format!("can't lock its {LOCK} ({e})")),
    }
    // A service from before the lock would answer here without holding it.
    #[cfg(unix)]
    if latem_vault_service::client::is_running(&old.join(SOCKET)) {
        return Err(running());
    }
    fs::rename(old, new).map_err(|e| format!("can't move it ({e})"))?;
    drop(lock);
    Ok(())
}

/// A latem older than [`LATEM`], with why it stops the move. It's the latem first on `PATH`,
/// and the one in `~/.local/bin` where latem installs itself.
fn old_latem() -> Option<String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(path) = env::var_os("PATH") {
        candidates.extend(
            env::split_paths(&path)
                .map(|dir| dir.join("latem"))
                .find(|file| executable(file)),
        );
    }
    if let Some(home) = env::home_dir() {
        let installed = home.join(".local/bin/latem");
        if executable(&installed) {
            candidates.push(installed);
        }
    }
    let mut seen = Vec::new();
    for latem in candidates {
        let real = fs::canonicalize(&latem).unwrap_or_else(|_| latem.clone());
        if seen.contains(&real) {
            continue;
        }
        seen.push(real);
        let output = Command::new(&latem).arg("--version").output();
        let version = output
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| Version::find(&String::from_utf8_lossy(&output.stdout)));
        match version {
            Some(version) if version >= LATEM => {}
            Some(version) => {
                return Some(format!(
                    "{} is latem {version}, which looks for the vault only in the old directory. \
                     Update it to {LATEM} or later with `latem update`, then run any \
                     latem-vault command",
                    shown(&latem)
                ));
            }
            None => {
                return Some(format!(
                    "`{} --version` didn't say which latem it is, and a latem older than \
                     {LATEM} looks for the vault only in the old directory. Update it with \
                     `latem update`, then run any latem-vault command",
                    shown(&latem)
                ));
            }
        }
    }
    None
}

/// `path`, with `~` for the home directory.
fn shown(path: &Path) -> String {
    match env::home_dir().and_then(|home| Some(path.strip_prefix(home).ok()?.to_owned())) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

fn executable(file: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::metadata(file).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    file.is_file()
}

/// Whether `HOME` is this account's home directory, whose `~/.openvault` the Mac app's service
/// would use. Another `HOME`, as in a test, has a vault the app doesn't know about.
#[cfg(unix)]
pub(crate) fn home_is_the_accounts() -> bool {
    let Some(home) = env::home_dir() else {
        return false;
    };
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: the buffer and entry outlive the call, and getpwuid_r writes only into them.
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() || entry.pw_dir.is_null() {
        // Can't tell, so take it to be: the app's check then applies.
        return true;
    }
    // SAFETY: getpwuid_r succeeded, so pw_dir points at a C string in the buffer.
    let dir = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) };
    let dir =
        Path::new(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(dir.to_bytes()));
    same_dir(&home, dir)
}

#[cfg(unix)]
fn same_dir(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// `MAJOR.MINOR.PATCH`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u64, u64, u64);

impl Version {
    /// The first word of `text` that is a version, as in `latem version v0.12.0`. A suffix such
    /// as `-rc1` is left out.
    fn find(text: &str) -> Option<Self> {
        text.split_whitespace().find_map(|word| {
            let word = word.strip_prefix('v').unwrap_or(word);
            let mut parts = word.splitn(3, '.');
            let major = parts.next()?.parse().ok()?;
            let minor = parts.next()?.parse().ok()?;
            let patch = parts.next()?;
            let end = patch
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(patch.len());
            Some(Self(major, minor, patch[..end].parse().ok()?))
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_found_in_what_latem_prints() {
        assert_eq!(
            Version::find("latem version v0.12.0\n"),
            Some(Version(0, 12, 0))
        );
        assert_eq!(Version::find("latem 0.13.2-rc1"), Some(Version(0, 13, 2)));
        assert_eq!(Version::find("latem version dev"), None);
        assert!(Version(0, 11, 9) < LATEM);
        assert!(Version(0, 12, 0) >= LATEM);
        assert!(Version(1, 0, 0) >= LATEM);
    }

    #[test]
    fn the_directory_moves_in_one_rename() {
        let home = tempfile::tempdir().unwrap();
        let (old, new) = (
            home.path().join(".openvault"),
            home.path().join(".latem-vault"),
        );
        fs::create_dir(&old).unwrap();
        fs::write(old.join("keys"), b"key file").unwrap();
        move_dir(&old, &new).unwrap();
        assert!(!old.exists());
        assert_eq!(fs::read(new.join("keys")).unwrap(), b"key file");
    }

    #[test]
    fn the_directory_stays_while_a_service_holds_its_lock() {
        let home = tempfile::tempdir().unwrap();
        let (old, new) = (
            home.path().join(".openvault"),
            home.path().join(".latem-vault"),
        );
        fs::create_dir(&old).unwrap();
        let service = File::create(old.join(LOCK)).unwrap();
        service.lock().unwrap();
        let why = move_dir(&old, &new).unwrap_err();
        assert!(why.starts_with("a service is running for it"), "{why}");
        assert!(old.is_dir() && !new.exists());
    }
}
