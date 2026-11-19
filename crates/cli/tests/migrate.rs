//! The first run after 0.7 moves `~/.latem-vault`, or `~/.openvault` where that never moved, to
//! `~/.pinkvault` (migrate.rs), in a temporary `HOME` with no vault variable set, and a `PATH`
//! that holds only a fake `latem`.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The vault directories before 0.7: 0.6's, then openvault's.
const OLD: [&str; 2] = [".latem-vault", ".openvault"];

/// Every name for the vault directory's variable, the old ones included.
const HOME_VARS: [&str; 3] = ["PINKVAULT_HOME", "LATEM_VAULT_HOME", "OPENVAULT_HOME"];

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    /// A home directory with a vault in `~/<old>`, holding `latem/A`.
    fn with_vault_in(old: &str) -> Self {
        let home = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir(home.bin()).unwrap();
        home.make_vault(old, "1");
        home
    }

    /// Makes a vault in `~/<dir>` whose `latem/A` is `value`.
    fn make_vault(&self, dir: &str, value: &str) {
        let dir = self.path(dir);
        let init = self
            .command(&["init", "--keys", "software", "--name", "old"])
            .env("PINKVAULT_HOME", &dir)
            .output()
            .unwrap();
        assert!(init.status.success(), "{}", stderr(&init));
        for args in [
            &["collections", "create", "latem"][..],
            &["set", "latem/A", "--var"],
        ] {
            let mut child = self
                .command(args)
                .env("PINKVAULT_HOME", &dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let input = if args[0] == "set" {
                value.to_owned()
            } else {
                phrase(&String::from_utf8_lossy(&init.stdout))
            };
            std::io::Write::write_all(child.stdin.as_mut().unwrap(), input.as_bytes()).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "{}", stderr(&output));
        }
    }

    fn path(&self, dir: &str) -> PathBuf {
        self.dir.path().join(dir)
    }

    fn new_dir(&self) -> PathBuf {
        self.path(".pinkvault")
    }

    fn bin(&self) -> PathBuf {
        self.dir.path().join("bin")
    }

    /// Puts a `latem` on `PATH` that says it's `version`.
    fn latem(&self, version: &str) {
        let latem = self.bin().join("latem");
        fs::write(
            &latem,
            format!("#!/bin/sh\necho 'latem version {version}'\n"),
        )
        .unwrap();
        fs::set_permissions(&latem, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pinkvault"));
        command.args(args);
        for variable in HOME_VARS {
            command.env_remove(variable);
        }
        command
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XPC_SERVICE_NAME")
            .env("HOME", self.dir.path())
            .env("PATH", self.bin())
            .env(
                "PINKVAULT_MDNS_SERVICE",
                format!("ovm-{:x}", std::process::id()),
            )
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        let output = self.command(args).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        output
    }

    /// `pinkvault service` on `~/<old>`, as 0.6's or openvault's would be.
    fn old_service(&self, old: &str) -> Service {
        let child = self
            .command(&["service"])
            .env("PINKVAULT_HOME", self.path(old))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let socket = self.path(old).join("service.sock");
        let started = Instant::now();
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            assert!(started.elapsed() < Duration::from_secs(20), "no service");
            std::thread::sleep(Duration::from_millis(50));
        }
        Service(child)
    }
}

struct Service(Child);

impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: kill has no memory-safety preconditions; the pid is our own child's.
        unsafe { libc::kill(self.0.id() as i32, libc::SIGTERM) };
        let _ = self.0.wait();
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The recovery phrase in `init`'s output, whose numbered words run down columns.
fn phrase(stdout: &str) -> String {
    let words: Vec<&str> = stdout.split_whitespace().collect();
    let mut numbered: Vec<(usize, &str)> = words
        .windows(2)
        .filter_map(|pair| Some((pair[0].strip_suffix('.')?.parse().ok()?, pair[1])))
        .collect();
    numbered.sort();
    numbered
        .into_iter()
        .map(|(_, word)| word)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn the_first_run_moves_the_vault_from_each_old_directory() {
    for old in OLD {
        let home = Home::with_vault_in(old);
        let keys = fs::read(home.path(old).join("keys")).unwrap();

        let moved = home.run(&["get", "latem/A"]);
        assert_eq!(stdout(&moved), "1");
        assert_eq!(
            stderr(&moved),
            format!("Moved the vault from ~/{old} to ~/.pinkvault.\n")
        );
        assert!(!home.path(old).exists());
        assert_eq!(fs::read(home.new_dir().join("keys")).unwrap(), keys);

        let again = home.run(&["get", "latem/A"]);
        assert_eq!(stdout(&again), "1");
        assert_eq!(stderr(&again), "");
    }
}

#[test]
fn two_old_directories_stay_where_they_are() {
    let home = Home::with_vault_in(".latem-vault");
    home.make_vault(".openvault", "2");

    // 0.6 used ~/.latem-vault, so commands go on using it, and nothing moves.
    let stayed = home.run(&["get", "latem/A"]);
    assert_eq!(stdout(&stayed), "1");
    let why = stderr(&stayed);
    assert!(
        why.starts_with(
            "The vault stays in ~/.latem-vault for now, not ~/.pinkvault: ~/.openvault is here \
             too, and only one can move."
        ),
        "{why}"
    );
    assert!(home.path(".latem-vault").is_dir() && home.path(".openvault").is_dir());
    assert!(!home.new_dir().exists());

    // Once the person has moved one aside, the other moves.
    fs::rename(home.path(".openvault"), home.path("openvault-aside")).unwrap();
    let moved = home.run(&["get", "latem/A"]);
    assert_eq!(stdout(&moved), "1");
    assert_eq!(
        stderr(&moved),
        "Moved the vault from ~/.latem-vault to ~/.pinkvault.\n"
    );
}

#[test]
fn the_new_directory_wins_over_an_old_one() {
    let home = Home::with_vault_in(".pinkvault");
    home.make_vault(".latem-vault", "2");
    let output = home.run(&["get", "latem/A"]);
    assert_eq!(stdout(&output), "1");
    assert_eq!(stderr(&output), "");
    assert!(home.path(".latem-vault").is_dir());
}

#[test]
fn an_old_latem_keeps_the_vault_where_it_is() {
    let home = Home::with_vault_in(".latem-vault");
    home.latem("v0.13.2");

    let stayed = home.run(&["get", "latem/A"]);
    assert_eq!(stdout(&stayed), "1");
    let why = stderr(&stayed);
    assert!(
        why.starts_with(
            "The vault stays in ~/.latem-vault for now, not ~/.pinkvault: ~/bin/latem is latem \
             0.13.2"
        ),
        "{why}"
    );
    assert!(why.contains("`latem update`"), "{why}");
    assert!(home.path(".latem-vault").is_dir() && !home.new_dir().exists());

    home.latem("v0.14.0");
    let moved = home.run(&["get", "latem/A"]);
    assert!(
        stderr(&moved).starts_with("Moved the vault"),
        "{}",
        stderr(&moved)
    );
    assert!(home.new_dir().is_dir() && !home.path(".latem-vault").exists());
}

#[test]
fn a_running_service_keeps_the_vault_where_it_is() {
    let home = Home::with_vault_in(".latem-vault");
    let service = home.old_service(".latem-vault");

    let stayed = home.run(&["get", "latem/A"]);
    assert_eq!(stdout(&stayed), "1");
    assert!(
        stderr(&stayed).contains(": a service is running for it. Stop it, then run any"),
        "{}",
        stderr(&stayed)
    );
    assert!(home.path(".latem-vault").is_dir() && !home.new_dir().exists());

    drop(service);
    let moved = home.run(&["get", "latem/A"]);
    assert!(
        stderr(&moved).starts_with("Moved the vault"),
        "{}",
        stderr(&moved)
    );
    assert!(!home.new_dir().join("service.sock").exists());
}

#[test]
fn the_service_moves_the_vault_when_it_starts() {
    let home = Home::with_vault_in(".openvault");
    let log = home.dir.path().join("service.log");
    let child = home
        .command(&["service", "--log", log.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _service = Service(child);
    let socket = home.new_dir().join("service.sock");
    let started = Instant::now();
    while std::os::unix::net::UnixStream::connect(&socket).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let log = fs::read_to_string(&log).unwrap();
    assert!(
        log.starts_with("Moved the vault from ~/.openvault"),
        "{log}"
    );
    assert!(!home.path(".openvault").exists());
    assert_eq!(stdout(&home.run(&["get", "latem/A"])), "1");
}

/// The old variables are still read, and a directory any of them names is used as it is.
#[test]
fn a_chosen_directory_is_never_moved() {
    let home = Home::with_vault_in(".latem-vault");
    for variable in HOME_VARS {
        let output = home
            .command(&["get", "latem/A"])
            .env(variable, home.path(".latem-vault"))
            .output()
            .unwrap();
        assert_eq!(stdout(&output), "1", "{variable}: {}", stderr(&output));
        assert_eq!(stderr(&output), "");
        assert!(home.path(".latem-vault").is_dir() && !home.new_dir().exists());
    }
}

/// `PINKVAULT_HOME` wins over the old names, and 0.6's over openvault's.
#[test]
fn the_newest_variable_wins() {
    let home = Home::with_vault_in("a");
    home.make_vault("b", "2");
    home.make_vault("c", "3");
    let get = |vars: &[(&str, &str)]| {
        let mut command = home.command(&["get", "latem/A"]);
        for (variable, dir) in vars {
            command.env(variable, home.path(dir));
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        stdout(&output)
    };
    let all = [
        ("PINKVAULT_HOME", "a"),
        ("LATEM_VAULT_HOME", "b"),
        ("OPENVAULT_HOME", "c"),
    ];
    assert_eq!(get(&all), "1");
    assert_eq!(get(&all[1..]), "2");
    assert_eq!(get(&all[2..]), "3");
}
