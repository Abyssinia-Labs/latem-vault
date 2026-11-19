//! The name the person typed for this command, which hints use: someone who typed `pink` is told
//! to run `pink service install`. Homebrew and the release archives put in `pink` as a link to
//! `pinkvault`. Any other name, such as a copy renamed by hand, gets `pinkvault`, the name latem
//! looks for. So do the old names, `latem-vault` and `openvault`, which the tap links to
//! `pinkvault` for one release, and which say so first ([`old_name_notice`]).
//!
//! Messages are written naming `` `pinkvault …` `` and pass through [`hint`] on their way out:
//! errors in `main`, help when the command line is parsed, and other output through [`say!`] and
//! [`esay!`]. Where the name is the program itself rather than a command to type, such as a
//! version line or what macOS asks about, it stays `pinkvault`.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::OnceLock;

/// The binary's own name.
pub const FULL: &str = "pinkvault";

/// The short names, as latem has `ltm`. The same list is in release.yml's archive step, the
/// test that runs them (tests/cli.rs) and the README, and the tap's formula links them.
const SHORT: [&str; 1] = ["pink"];

/// The command's names before 0.7: latem vault's in 0.6, and openvault's before. They run this
/// binary for one release, and go when the old names do (OV-15).
const OLD: [&str; 2] = ["latem-vault", "openvault"];

/// The name to put in hints for a program run as `argv0`.
pub fn chosen(argv0: Option<&OsStr>) -> &'static str {
    let Some(file) = file_name(argv0) else {
        return FULL;
    };
    SHORT
        .into_iter()
        .find(|short| *short == file)
        .unwrap_or(FULL)
}

/// The old name a program run as `argv0` was run by, if it was.
fn old(argv0: Option<&OsStr>) -> Option<&'static str> {
    let file = file_name(argv0)?;
    OLD.into_iter().find(|old| *old == file)
}

/// The file name in `argv0`, without the `.exe` that the name typed on Windows doesn't have.
fn file_name(argv0: Option<&OsStr>) -> Option<String> {
    let file = Path::new(argv0?).file_name()?.to_string_lossy();
    Some(file.strip_suffix(".exe").unwrap_or(&file).to_owned())
}

/// What to say on stderr when this process was run by an old name: that it's `pinkvault` now,
/// and the old name goes in the next release.
pub fn old_name_notice() -> Option<String> {
    notice_for(std::env::args_os().next().as_deref())
}

fn notice_for(argv0: Option<&OsStr>) -> Option<String> {
    let old = old(argv0)?;
    Some(format!(
        "`{old}` is now `pinkvault`, and `pink` for short. The old name works until the next \
         release."
    ))
}

/// The name this process was run as, for hints.
pub fn typed() -> &'static str {
    static TYPED: OnceLock<&'static str> = OnceLock::new();
    TYPED.get_or_init(|| chosen(std::env::args_os().next().as_deref()))
}

/// `text`, with each command it names written as the person typed it.
pub fn hint(text: &str) -> Cow<'_, str> {
    hint_as(text, typed())
}

fn hint_as<'a>(text: &'a str, name: &str) -> Cow<'a, str> {
    if name == FULL || !text.contains("`pinkvault") {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.replace("`pinkvault ", &format!("`{name} "))
            .replace("`pinkvault`", &format!("`{name}`")),
    )
}

/// `println!`, with the commands it names as the person typed them.
macro_rules! say {
    ($($arg:tt)*) => {
        println!("{}", $crate::name::hint(&format!($($arg)*)))
    };
}

/// `eprintln!`, with the commands it names as the person typed them.
macro_rules! esay {
    ($($arg:tt)*) => {
        eprintln!("{}", $crate::name::hint(&format!($($arg)*)))
    };
}

pub(crate) use {esay, say};

/// The command line's definition, with the person's name for it in usage lines and in the
/// commands its help names. `--version` still says `pinkvault`.
pub fn command(command: clap::Command) -> clap::Command {
    rename(command.bin_name(typed()), typed())
}

fn rename(command: clap::Command, name: &str) -> clap::Command {
    let mut command = command.mut_args(|arg| {
        let help = arg
            .get_help()
            .map(|help| hint_as(&help.to_string(), name).into_owned());
        let long = arg
            .get_long_help()
            .map(|help| hint_as(&help.to_string(), name).into_owned());
        let arg = match help {
            Some(help) => arg.help(help),
            None => arg,
        };
        match long {
            Some(long) => arg.long_help(long),
            None => arg,
        }
    });
    if let Some(about) = command.get_about().map(|about| about.to_string()) {
        command = command.about(hint_as(&about, name).into_owned());
    }
    if let Some(long) = command.get_long_about().map(|about| about.to_string()) {
        command = command.long_about(hint_as(&long, name).into_owned());
    }
    let subcommands: Vec<String> = command
        .get_subcommands()
        .map(|sub| sub.get_name().to_owned())
        .collect();
    for sub in subcommands {
        command = command.mut_subcommand(sub, |sub| rename(sub, name));
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_short_names_are_kept() {
        for short in SHORT {
            for typed in [
                short.to_owned(),
                format!("/opt/homebrew/bin/{short}"),
                format!("../bin/{short}"),
                format!("/home/me/bin/{short}/"),
                format!("{short}.exe"),
            ] {
                assert_eq!(chosen(Some(OsStr::new(&typed))), short, "{typed}");
            }
            let windows = format!(r"C:\tools\{short}.exe");
            let want = if cfg!(windows) { short } else { FULL };
            assert_eq!(chosen(Some(OsStr::new(&windows))), want);
            // Only the name itself: not a longer one, nor another case.
            assert_eq!(chosen(Some(OsStr::new(&format!("{short}2")))), FULL);
            assert_eq!(chosen(Some(OsStr::new(&short.to_uppercase()))), FULL);
        }
    }

    #[test]
    fn any_other_name_is_pinkvault() {
        assert_eq!(chosen(Some(OsStr::new("pinkvault"))), FULL);
        assert_eq!(chosen(Some(OsStr::new("/usr/local/bin/pinkvault"))), FULL);
        assert_eq!(chosen(Some(OsStr::new("pinkvault.exe"))), FULL);
        for old in OLD {
            assert_eq!(chosen(Some(OsStr::new(old))), FULL);
        }
        assert_eq!(chosen(Some(OsStr::new(""))), FULL);
        assert_eq!(chosen(None), FULL);
    }

    #[test]
    fn an_old_name_says_it_is_pinkvault_now() {
        for (typed, old) in [
            ("latem-vault", "latem-vault"),
            ("/opt/homebrew/bin/latem-vault", "latem-vault"),
            ("openvault", "openvault"),
            ("/home/me/.local/bin/openvault", "openvault"),
            ("openvault.exe", "openvault"),
        ] {
            let notice = notice_for(Some(OsStr::new(typed))).unwrap();
            assert!(
                notice.starts_with(&format!("`{old}` is now `pinkvault`")),
                "{notice}"
            );
        }
        for typed in [
            "pinkvault",
            "pink",
            "lv",
            "vlt",
            "latem",
            "latem-vault2",
            "",
        ] {
            assert_eq!(notice_for(Some(OsStr::new(typed))), None, "{typed}");
        }
        assert_eq!(notice_for(None), None);
    }

    #[test]
    fn hints_name_the_command_as_typed() {
        assert_eq!(
            hint_as("run `pinkvault service install` here", "pink"),
            "run `pink service install` here"
        );
        assert_eq!(
            hint_as("run `pinkvault join` and `pinkvault approve` again", "pink"),
            "run `pink join` and `pink approve` again"
        );
        assert_eq!(
            hint_as("any `pinkvault` command", "pink"),
            "any `pink` command"
        );
    }

    #[test]
    fn the_program_itself_keeps_its_name() {
        for text in [
            "The service is running: pinkvault 0.7.0, pid 7.",
            "macOS asks whether pinkvault may find devices on your local network",
            "Written to ~/.pinkvault/keys",
        ] {
            assert!(matches!(hint_as(text, "pink"), Cow::Borrowed(t) if t == text));
        }
        let text = "run `pinkvault init`";
        assert!(matches!(hint_as(text, FULL), Cow::Borrowed(t) if t == text));
    }
}
