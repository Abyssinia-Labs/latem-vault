//! Where a device's vault directory is: `LATEM_VAULT_HOME` if it's set, else `~/.latem-vault`
//! (service.md, the directory).
//!
//! Until 0.6 the directory was `~/.openvault`, named by `OPENVAULT_HOME`. The old variable is
//! still read for one release, and the CLI moves the old directory to the new one on its first
//! run (`latem-vault`'s migrate.rs). Both go when the old names do (OV-15).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The variable that names another vault directory.
pub const HOME_VAR: &str = "LATEM_VAULT_HOME";
/// [`HOME_VAR`] before 0.6, still read for one release.
pub const OLD_HOME_VAR: &str = "OPENVAULT_HOME";
/// The vault directory in the home directory, without [`HOME_VAR`].
pub const DIR: &str = ".latem-vault";
/// [`DIR`] before 0.6, which the CLI moves to [`DIR`].
pub const OLD_DIR: &str = ".openvault";

/// Where the vault directory is, before anything is moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    /// Named by [`HOME_VAR`] or [`OLD_HOME_VAR`], and used as it is.
    Chosen(PathBuf),
    /// The default: `new`, unless the vault is still in `old`.
    Default { new: PathBuf, old: PathBuf },
}

impl Location {
    /// Where this process's environment puts the vault directory.
    pub fn from_env() -> Result<Self, NoHome> {
        if let Some(dir) = var_os(HOME_VAR, OLD_HOME_VAR) {
            return Ok(Self::Chosen(dir.into()));
        }
        let home = std::env::home_dir().ok_or(NoHome)?;
        Ok(Self::in_home(&home))
    }

    /// The default directories in the home directory `home`.
    pub fn in_home(home: &Path) -> Self {
        Self::Default {
            new: home.join(DIR),
            old: home.join(OLD_DIR),
        }
    }

    /// The directory as it is now, without moving anything: the new one, unless only the old
    /// one exists. For the apps, which read the directory and leave moving it to the CLI.
    pub fn current(&self) -> PathBuf {
        match self {
            Self::Chosen(dir) => dir.clone(),
            Self::Default { new, old } if !exists(new) && old.is_dir() => old.clone(),
            Self::Default { new, .. } => new.clone(),
        }
    }
}

/// There's no home directory, and no [`HOME_VAR`] naming the vault directory.
#[derive(Debug, thiserror::Error)]
#[error("can't find your home directory; set {HOME_VAR}")]
pub struct NoHome;

/// The variable `new`, or else `old`, which it replaced and which is still read for one
/// release.
pub fn var_os(new: &str, old: &str) -> Option<OsString> {
    std::env::var_os(new).or_else(|| std::env::var_os(old))
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
        assert_eq!(location.current(), home.path().join(".latem-vault"));

        std::fs::create_dir(home.path().join(".openvault")).unwrap();
        assert_eq!(location.current(), home.path().join(".openvault"));

        std::fs::create_dir(home.path().join(".latem-vault")).unwrap();
        assert_eq!(location.current(), home.path().join(".latem-vault"));
    }

    #[test]
    fn a_chosen_directory_is_used_as_it_is() {
        let location = Location::Chosen("/somewhere".into());
        assert_eq!(location.current(), PathBuf::from("/somewhere"));
    }
}
