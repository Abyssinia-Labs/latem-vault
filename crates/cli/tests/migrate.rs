//! The first run after 0.6 moves `~/.openvault` to `~/.latem-vault` (migrate.rs), in a
//! temporary `HOME` with no `LATEM_VAULT_HOME`, and a `PATH` that holds only a fake `latem`.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    /// A home directory with a vault where openvault kept it, holding `latem/A`.
    fn with_old_vault() -> Self {
        let home = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir(home.bin()).unwrap();
        let init = home
            .command(&["init", "--keys", "software", "--name", "old"])
            .env("LATEM_VAULT_HOME", home.old_dir())
            .output()
            .unwrap();
        assert!(init.status.success(), "{}", stderr(&init));
        for args in [
            &["collections", "create", "latem"][..],
            &["set", "latem/A", "--var"],
        ] {
            let mut child = home
                .command(args)
                .env("LATEM_VAULT_HOME", home.old_dir())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let input = if args[0] == "set" {
                "1".to_owned()
            } else {
                phrase(&String::from_utf8_lossy(&init.stdout))
            };
            std::io::Write::write_all(child.stdin.as_mut().unwrap(), input.as_bytes()).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "{}", stderr(&output));
        }
        home
    }

    fn old_dir(&self) -> PathBuf {
        self.dir.path().join(".openvault")
    }

    fn new_dir(&self) -> PathBuf {
        self.dir.path().join(".latem-vault")
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_latem-vault"));
        command
            .args(args)
            .env_remove("LATEM_VAULT_HOME")
            .env_remove("OPENVAULT_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XPC_SERVICE_NAME")
            .env("HOME", self.dir.path())
            .env("PATH", self.bin())
            .env(
                "LATEM_VAULT_MDNS_SERVICE",
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

    /// `latem-vault service` on the old directory, as openvault's would be.
    fn old_service(&self) -> Service {
        let child = self
            .command(&["service"])
            .env("LATEM_VAULT_HOME", self.old_dir())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let socket = self.old_dir().join("service.sock");
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
fn the_first_run_moves_the_vault() {
    let home = Home::with_old_vault();
    let keys = fs::read(home.old_dir().join("keys")).unwrap();

    let moved = home.run(&["get", "latem/A"]);
    assert_eq!(stdout(&moved), "1");
    assert_eq!(
        stderr(&moved),
        "Moved the vault from ~/.openvault to ~/.latem-vault.\n"
    );
    assert!(!home.old_dir().exists());
    assert_eq!(fs::read(home.new_dir().join("keys")).unwrap(), keys);

    let again = home.run(&["get", "latem/A"]);
    assert_eq!(stdout(&again), "1");
    assert_eq!(stderr(&again), "");
}

#[test]
fn an_old_latem_keeps_the_vault_where_it_is() {
    let home = Home::with_old_vault();
    home.latem("v0.11.2");

    let stayed = home.run(&["get", "latem/A"]);
    assert_eq!(stdout(&stayed), "1");
    let why = stderr(&stayed);
    assert!(
        why.starts_with(
            "The vault stays in ~/.openvault for now, not ~/.latem-vault: ~/bin/latem is latem \
             0.11.2"
        ),
        "{why}"
    );
    assert!(why.contains("`latem update`"), "{why}");
    assert!(home.old_dir().is_dir() && !home.new_dir().exists());

    home.latem("v0.12.0");
    let moved = home.run(&["get", "latem/A"]);
    assert!(
        stderr(&moved).starts_with("Moved the vault"),
        "{}",
        stderr(&moved)
    );
    assert!(home.new_dir().is_dir() && !home.old_dir().exists());
}

#[test]
fn a_running_service_keeps_the_vault_where_it_is() {
    let home = Home::with_old_vault();
    let service = home.old_service();

    let stayed = home.run(&["get", "latem/A"]);
    assert_eq!(stdout(&stayed), "1");
    assert!(
        stderr(&stayed).contains(": a service is running for it. Stop it, then run any"),
        "{}",
        stderr(&stayed)
    );
    assert!(home.old_dir().is_dir() && !home.new_dir().exists());

    drop(service);
    let moved = home.run(&["get", "latem/A"]);
    assert!(
        stderr(&moved).starts_with("Moved the vault"),
        "{}",
        stderr(&moved)
    );
    assert!(!home.old_dir().join("service.sock").exists());
}

#[test]
fn the_service_moves_the_vault_when_it_starts() {
    let home = Home::with_old_vault();
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
    assert!(log.starts_with("Moved the vault from"), "{log}");
    assert!(!home.old_dir().exists());
    assert_eq!(stdout(&home.run(&["get", "latem/A"])), "1");
}

#[test]
fn a_chosen_directory_is_never_moved() {
    let home = Home::with_old_vault();
    for variable in ["LATEM_VAULT_HOME", "OPENVAULT_HOME"] {
        let output = home
            .command(&["get", "latem/A"])
            .env(variable, home.old_dir())
            .output()
            .unwrap();
        assert_eq!(stdout(&output), "1", "{}", stderr(&output));
        assert_eq!(stderr(&output), "");
        assert!(home.old_dir().is_dir() && !home.new_dir().exists());
    }
}
