//! Runs the `openvault` binary against a temporary `OPENVAULT_HOME`. Keys are software keys,
//! so these tests run anywhere; the keystore crate tests the Secure Enclave.

use std::io::Write;
use std::process::{Command, Output, Stdio};

struct Device {
    home: tempfile::TempDir,
}

impl Device {
    /// A device with a vault and a `latem` collection.
    fn new() -> Self {
        let device = Self::empty();
        device.ok(&["init", "--keys", "software"]);
        device.ok(&["collections", "create", "latem"]);
        device
    }

    fn empty() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_openvault"));
        command
            .args(args)
            .env("OPENVAULT_HOME", self.home.path())
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn fails(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(!output.status.success(), "{args:?} succeeded");
        String::from_utf8(output.stderr).unwrap()
    }

    fn set(&self, entry: &str, kind: &str, value: &[u8]) {
        let mut child = self
            .command(&["set", entry, kind])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(value).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "set {entry} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn init_creates_a_private_vault_and_shows_the_phrase() {
    let device = Device::empty();
    let home = device.home.path().join("nested");
    let output = Command::new(env!("CARGO_BIN_EXE_openvault"))
        .args(["init", "--keys", "software"])
        .env("OPENVAULT_HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Recovery phrase"));
    let words: Vec<&str> = stdout
        .split_whitespace()
        .skip_while(|w| *w != "1.")
        .collect::<Vec<_>>()
        .chunks(2)
        .take(24)
        .filter(|pair| pair[0].ends_with('.'))
        .map(|pair| pair[1])
        .collect();
    assert_eq!(words.len(), 24, "{stdout}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&home), 0o700);
        assert_eq!(mode(&home.join("keys")), 0o600);
        assert_eq!(mode(&home.join("vault.db")), 0o600);
    }

    let again = Command::new(env!("CARGO_BIN_EXE_openvault"))
        .args(["init", "--keys", "software"])
        .env("OPENVAULT_HOME", &home)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already a vault"));
}

#[test]
fn commands_need_a_vault() {
    let device = Device::empty();
    assert!(device.fails(&["get", "latem/x"]).contains("openvault init"));
    assert!(device.fails(&["collections"]).contains("openvault init"));
}

#[test]
fn set_get_list_delete() {
    let device = Device::new();
    device.set(
        "latem/prod/SENTRY_DSN",
        "--secret",
        b"https://sentry.example\n",
    );
    device.set("latem/prod/REGION", "--var", b"eu-west-1\r\n");
    device.set("latem/dev/REGION", "--var", b"local");
    device.set("latem/raw", "--secret", b"two\n\n");

    // One trailing newline is dropped; the rest is kept byte for byte.
    assert_eq!(
        device.ok(&["get", "latem/prod/SENTRY_DSN"]),
        "https://sentry.example"
    );
    assert_eq!(device.ok(&["get", "latem/prod/REGION"]), "eu-west-1");
    assert_eq!(device.ok(&["get", "latem/raw"]), "two\n");

    assert_eq!(device.ok(&["collections"]), "latem\n");
    assert_eq!(
        device.ok(&["list", "latem"]),
        "var     dev/REGION\nvar     prod/REGION\nsecret  prod/SENTRY_DSN\nsecret  raw\n"
    );
    assert_eq!(
        device.ok(&["list", "latem/prod/"]),
        "var     prod/REGION\nsecret  prod/SENTRY_DSN\n"
    );

    device.set("latem/prod/REGION", "--var", b"us-east-1");
    assert_eq!(device.ok(&["get", "latem/prod/REGION"]), "us-east-1");

    device.ok(&["delete", "latem/prod/REGION"]);
    assert!(
        device
            .fails(&["get", "latem/prod/REGION"])
            .contains("doesn't exist")
    );
    assert!(
        device
            .fails(&["delete", "latem/prod/REGION"])
            .contains("doesn't exist")
    );
}

#[test]
fn rejects_bad_names_and_missing_collections() {
    let device = Device::new();
    assert!(
        device
            .fails(&["get", "latem"])
            .contains("<collection>/<name>")
    );
    assert!(device.fails(&["get", "latem/a/../b"]).contains("segments"));
    assert!(
        device
            .fails(&["get", "other/x"])
            .contains("no collection other")
    );
    assert!(
        device
            .fails(&["collections", "create", "latem"])
            .contains("already exists")
    );
    assert!(device.fails(&["set", "latem/x"]).contains("--secret"));
}

#[test]
fn run_puts_a_folder_in_the_environment() {
    let device = Device::new();
    device.set("latem/prod/SENTRY_DSN", "--secret", b"https://sentry");
    device.set("latem/prod/REGION", "--var", b"eu west");
    device.set("latem/dev/OTHER", "--var", b"no");

    let output = device.run(&[
        "run",
        "--collection",
        "latem",
        "--env",
        "prod",
        "--",
        "sh",
        "-c",
        r#"printf '%s|%s|%s' "$SENTRY_DSN" "$REGION" "${OTHER-unset}""#,
    ]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"https://sentry|eu west|unset");

    let exit = |script: &str| {
        device
            .run(&[
                "run",
                "--collection",
                "latem",
                "--env",
                "prod",
                "--",
                "sh",
                "-c",
                script,
            ])
            .status
            .code()
    };
    assert_eq!(exit("exit 7"), Some(7));

    let missing = device.run(&[
        "run",
        "--collection",
        "latem",
        "--env",
        "prod",
        "--",
        "openvault-no-such-command",
    ]);
    assert_eq!(missing.status.code(), Some(127));
}

#[test]
fn run_rejects_unusable_folders() {
    let device = Device::new();
    let run =
        |env: &str| device.fails(&["run", "--collection", "latem", "--env", env, "--", "true"]);
    assert!(run("prod").contains("has no secrets or variables"));

    device.set("latem/prod/nested/KEY", "--secret", b"x");
    assert!(run("prod").contains("can't be an environment variable"));

    device.set("latem/staging/1KEY", "--secret", b"x");
    assert!(run("staging").contains("can't be an environment variable"));

    device.set("latem/qa/KEY", "--secret", b"a\0b");
    assert!(run("qa").contains("NUL"));
}
