//! Rules for collection and entry names (records.md, names).

use crate::{Error, Result};

pub const MAX_COLLECTION_LEN: usize = 64;
pub const MAX_ENTRY_LEN: usize = 512;

/// 1–64 characters from `A–Z a–z 0–9 . _ -`, starting with a letter or digit.
pub fn check_collection(name: &str) -> Result<()> {
    let valid = (1..=MAX_COLLECTION_LEN).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    valid.then_some(()).ok_or(Error::InvalidName(
        "collection names are 1–64 characters from A–Z, a–z, 0–9, '.', '_' and '-', \
         starting with a letter or digit",
    ))
}

/// 1–512 bytes of UTF-8; `/`-separated segments that aren't empty, `.` or `..`; no control
/// characters.
pub fn check_entry(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_ENTRY_LEN {
        return Err(Error::InvalidName("entry names are 1–512 bytes"));
    }
    if name.chars().any(char::is_control) {
        return Err(Error::InvalidName(
            "entry names can't contain control characters",
        ));
    }
    if name
        .split('/')
        .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(Error::InvalidName(
            "entry name segments can't be empty, '.' or '..'",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_names() {
        for ok in ["latem-cloud", "ssh", "a", "v1.2_x", &"a".repeat(64)] {
            assert!(check_collection(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-x", ".x", "a/b", "a b", "é", &"a".repeat(65)] {
            assert!(check_collection(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn entry_names() {
        for ok in [
            "prod/SENTRY_DSN",
            "release/upload.jks",
            "x",
            "a b/ç",
            &"a".repeat(512),
        ] {
            assert!(check_entry(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/x",
            "x/",
            "a//b",
            "./x",
            "a/../b",
            "a\nb",
            "a\u{7f}",
            &"a".repeat(513),
        ] {
            assert!(check_entry(bad).is_err(), "{bad:?}");
        }
    }
}
