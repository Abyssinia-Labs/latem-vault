//! Where a device's vault directory is: `PINKVAULT_HOME` if it's set, else `~/.pinkvault`
//! (service.md, the directory).
//!
//! The directory was `~/.openvault` until 0.6, named by `OPENVAULT_HOME`, and `~/.latem-vault` in
//! 0.6, named by `LATEM_VAULT_HOME`. The old variables are still read for one release, and the CLI
//! moves an old directory to the new one on its first run (`pinkvault`'s migrate.rs). Both go
//! when the old names do (OV-15).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The variable that names another vault directory.
pub const HOME_VAR: &str = "PINKVAULT_HOME";
/// [`HOME_VAR`]'s earlier names, newest first: 0.6's, then openvault's. Still read for one
/// release, after [`HOME_VAR`].
pub const OLD_HOME_VARS: [&str; 2] = ["LATEM_VAULT_HOME", "OPENVAULT_HOME"];
/// The vault directory in the home directory, without [`HOME_VAR`].
pub const DIR: &str = ".pinkvault";
/// [`DIR`]'s earlier names, newest first: 0.6's, then openvault's. The CLI moves the one that
/// holds the vault to [`DIR`].
pub const OLD_DIRS: [&str; 2] = [".latem-vault", ".openvault"];

/// Where the vault directory is, before anything is moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    /// Named by [`HOME_VAR`] or one of [`OLD_HOME_VARS`], and used as it is.
    Chosen(PathBuf),
    /// The default: `new`, unless the vault is still in one of `old`, newest first.
    Default { new: PathBuf, old: Vec<PathBuf> },
}

impl Location {
    /// Where this process's environment puts the vault directory.
    pub fn from_env() -> Result<Self, NoHome> {
        if let Some(dir) = var_os(HOME_VAR, &OLD_HOME_VARS) {
            return Ok(Self::Chosen(dir.into()));
        }
        let home = std::env::home_dir().ok_or(NoHome)?;
        Ok(Self::in_home(&home))
    }

    /// The default directories in the home directory `home`.
    pub fn in_home(home: &Path) -> Self {
        Self::Default {
            new: home.join(DIR),
            old: OLD_DIRS.iter().map(|dir| home.join(dir)).collect(),
        }
    }

    /// The directory as it is now, without moving anything: the new one, unless it doesn't exist
    /// and an old one does. Of two old ones, the newer, which 0.6 used. For the apps, which read
    /// the directory and leave moving it to the CLI.
    pub fn current(&self) -> PathBuf {
        match self {
            Self::Chosen(dir) => dir.clone(),
            Self::Default { new, .. } if exists(new) => new.clone(),
            Self::Default { new, old } => {
                old.iter().find(|dir| dir.is_dir()).unwrap_or(new).clone()
            }
        }
    }
}

/// There's no home directory, and no [`HOME_VAR`] naming the vault directory.
#[derive(Debug, thiserror::Error)]
#[error("can't find your home directory; set {HOME_VAR}")]
pub struct NoHome;

/// The variable `new`, or else the first of `old` that is set: the names it had before, still
/// read for one release.
pub fn var_os(new: &str, old: &[&str]) -> Option<OsString> {
    std::iter::once(new)
        .chain(old.iter().copied())
        .find_map(std::env::var_os)
}

/// Whether anything is at `path`, a broken link included.
pub fn exists(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_directory_wins_once_it_exists() {
        let home = tempfile::tempdir().unwrap();
        let location = Location::in_home(home.path());
        assert_eq!(location.current(), home.path().join(".pinkvault"));

        std::fs::create_dir(home.path().join(".openvault")).unwrap();
        assert_eq!(location.current(), home.path().join(".openvault"));

        // Of two old ones, 0.6's, which 0.6 used.
        std::fs::create_dir(home.path().join(".latem-vault")).unwrap();
        assert_eq!(location.current(), home.path().join(".latem-vault"));

        std::fs::create_dir(home.path().join(".pinkvault")).unwrap();
        assert_eq!(location.current(), home.path().join(".pinkvault"));
    }

    #[test]
    fn a_chosen_directory_is_used_as_it_is() {
        let location = Location::Chosen("/somewhere".into());
        assert_eq!(location.current(), PathBuf::from("/somewhere"));
    }
}
