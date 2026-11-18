//! The name the person typed for this command, which hints use: someone who typed `vault` is told
//! to run `vault service install`. Homebrew and the release archives put in `vault` and `lv` as
//! links to `latem-vault`. Any other name, such as the `openvault` shim's (which runs this binary
//! as `latem-vault`) or a copy renamed by hand, gets `latem-vault`, the name latem looks for.
//!
//! Messages are written naming `` `latem-vault …` `` and pass through [`hint`] on their way out:
//! errors in `main`, help when the command line is parsed, and other output through [`say!`] and
//! [`esay!`]. Where the name is the program itself rather than a command to type, such as a
//! version line or what macOS asks about, it stays `latem-vault`.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::OnceLock;

/// The binary's own name.
pub const FULL: &str = "latem-vault";

/// The short names, as latem has `ltm`. The same list is in release.yml's archive step, the
/// test that runs them (tests/cli.rs) and the README, and the tap's formula links them.
const SHORT: [&str; 2] = ["vault", "lv"];

/// The name to put in hints for a program run as `argv0`.
pub fn chosen(argv0: Option<&OsStr>) -> &'static str {
    let Some(file) = argv0.and_then(|path| Path::new(path).file_name()) else {
        return FULL;
    };
    let file = file.to_string_lossy();
    // On Windows the name the person typed has no `.exe`.
    let file = file.strip_suffix(".exe").unwrap_or(&file);
    SHORT
        .into_iter()
        .find(|short| *short == file)
        .unwrap_or(FULL)
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
    if name == FULL || !text.contains("`latem-vault") {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.replace("`latem-vault ", &format!("`{name} "))
            .replace("`latem-vault`", &format!("`{name}`")),
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
/// commands its help names. `--version` still says `latem-vault`.
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
    fn any_other_name_is_latem_vault() {
        assert_eq!(chosen(Some(OsStr::new("latem-vault"))), FULL);
        assert_eq!(chosen(Some(OsStr::new("/usr/local/bin/latem-vault"))), FULL);
        assert_eq!(chosen(Some(OsStr::new("latem-vault.exe"))), FULL);
        // The openvault shim execs latem-vault, but a link named openvault would show this.
        assert_eq!(chosen(Some(OsStr::new("openvault"))), FULL);
        assert_eq!(chosen(Some(OsStr::new(""))), FULL);
        assert_eq!(chosen(None), FULL);
    }

    #[test]
    fn hints_name_the_command_as_typed() {
        assert_eq!(
            hint_as("run `latem-vault service install` here", "vault"),
            "run `vault service install` here"
        );
        assert_eq!(
            hint_as(
                "run `latem-vault join` and `latem-vault approve` again",
                "lv"
            ),
            "run `lv join` and `lv approve` again"
        );
        assert_eq!(
            hint_as("any `latem-vault` command", "lv"),
            "any `lv` command"
        );
    }

    #[test]
    fn the_program_itself_keeps_its_name() {
        for text in [
            "The service is running: latem-vault 0.6.0, pid 7.",
            "macOS asks whether latem-vault may find devices on your local network",
            "Written to ~/.latem-vault/keys",
        ] {
            assert!(matches!(hint_as(text, "vault"), Cow::Borrowed(t) if t == text));
        }
        let text = "run `latem-vault init`";
        assert!(matches!(hint_as(text, FULL), Cow::Borrowed(t) if t == text));
    }
}
