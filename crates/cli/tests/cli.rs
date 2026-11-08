//! Runs the `openvault` binary against a temporary `OPENVAULT_HOME`. Keys are software keys,
//! so these tests run anywhere; the keystore crate tests the Secure Enclave and passphrases.

use std::io::Write;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};

use openvault_core::Vault;
use openvault_crypto::RecoveryKey;
use openvault_keystore::Keys;

struct Device {
    home: tempfile::TempDir,
    /// The recovery phrase `init` showed.
    phrase: String,
}

impl Device {
    /// A device with a vault and a `latem` collection.
    fn new() -> Self {
        let mut device = Self::empty();
        device.phrase = phrase(&device.ok(&["init", "--keys", "software", "--name", "test"]));
        device.create_collection("latem");
        device
    }

    fn empty() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            phrase: String::new(),
        }
    }

    fn create_collection(&self, name: &str) {
        let output = self.run_with_stdin(&["collections", "create", name], self.phrase.as_bytes());
        assert!(
            output.status.success(),
            "creating {name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_openvault"));
        command
            .args(args)
            .env("OPENVAULT_HOME", self.home.path())
            .stdin(Stdio::null());
        // No controlling terminal, as in CI, so a command that asks for a passphrase fails
        // instead of waiting for someone to type it.
        #[cfg(unix)]
        // SAFETY: setsid is async-signal-safe, and nothing else runs before exec.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
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

    fn run_with_stdin(&self, args: &[&str], stdin: &[u8]) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    fn set(&self, entry: &str, kind: &str, value: &[u8]) {
        let output = self.run_with_stdin(&["set", entry, kind], value);
        assert!(
            output.status.success(),
            "set {entry} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Writes a file next to the vault and returns its path.
    fn file(&self, name: &str, contents: &[u8]) -> String {
        let path = self.home.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_owned()
    }
}

/// The recovery phrase in `init`'s output, whose numbered words run down the columns.
fn phrase(stdout: &str) -> String {
    let tokens: Vec<&str> = stdout
        .split_whitespace()
        .skip_while(|token| *token != "1.")
        .collect();
    let mut words: Vec<(usize, &str)> = tokens
        .chunks(2)
        .take(24)
        .map(|pair| (pair[0].trim_end_matches('.').parse().unwrap(), pair[1]))
        .collect();
    words.sort();
    let words: Vec<&str> = words.into_iter().map(|(_, word)| word).collect();
    assert_eq!(words.len(), 24, "{stdout}");
    words.join(" ")
}

#[test]
fn init_creates_a_private_vault_and_shows_the_phrase() {
    let device = Device::empty();
    let home = device.home.path().join("nested");
    let output = Command::new(env!("CARGO_BIN_EXE_openvault"))
        .args(["init", "--keys", "software", "--name", "Build Mac"])
        .env("OPENVAULT_HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Device  Build Mac, "), "{stdout}");
    // Software keys come without an admin key; the recovery phrase is the only one.
    assert!(
        stdout.contains("Admin   your recovery phrase only"),
        "{stdout}"
    );
    assert!(!home.join("admin").exists());
    assert!(stdout.contains("Recovery phrase"));
    phrase(&stdout);

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
fn creating_a_collection_asks_for_the_recovery_phrase() {
    let device = Device::new();
    let other = Device::new();
    let create = |stdin: &str| {
        let output = device.run_with_stdin(&["collections", "create", "ssh"], stdin.as_bytes());
        (
            output.status.success(),
            String::from_utf8(output.stderr).unwrap(),
        )
    };

    let (ok, stderr) = create("not a phrase\n");
    assert!(
        !ok && stderr.contains("recovery phrase is invalid"),
        "{stderr}"
    );
    let (ok, stderr) = create(&other.phrase);
    assert!(
        !ok && stderr.contains("belongs to another vault"),
        "{stderr}"
    );
    assert_eq!(device.ok(&["collections"]), "latem\n");

    let (ok, stderr) = create(&format!("  {}\n", device.phrase.to_uppercase()));
    assert!(ok, "{stderr}");
    assert_eq!(device.ok(&["collections"]), "latem\nssh\n");

    let bad_name = Device::empty();
    assert!(
        bad_name
            .fails(&["init", "--keys", "software", "--name", ""])
            .contains("device name")
    );
    assert!(!bad_name.home.path().join("vault.db").exists());
    assert!(!bad_name.home.path().join("keys").exists());
}

#[cfg(unix)]
#[test]
fn passphrase_keys_need_a_terminal() {
    let device = Device::empty();
    let error = device.fails(&["init", "--keys", "passphrase", "--name", "test"]);
    assert!(error.contains("no terminal"), "{error}");
    assert!(!device.home.path().join("keys").exists());

    // The vault `init` makes on a terminal.
    let keys = Keys::create_with_passphrase(
        &device.home.path().join("keys"),
        "correct horse battery staple",
    )
    .unwrap();
    let recovery = RecoveryKey::generate();
    Vault::create(
        &device.home.path().join("vault.db"),
        keys,
        &recovery,
        "test",
        None,
    )
    .unwrap();
    let error = device.fails(&["collections"]);
    assert!(
        error.contains("protected by a passphrase") && error.contains("no terminal"),
        "{error}"
    );
}

#[test]
fn the_version_names_the_build() {
    let version = Device::empty().ok(&["--version"]);
    let build = version
        .trim()
        .strip_prefix(concat!("openvault ", env!("CARGO_PKG_VERSION"), " ("))
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("{version}"));
    assert!(
        build == "unknown" || (build.len() == 7 && build.bytes().all(|b| b.is_ascii_hexdigit())),
        "{build}"
    );
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
fn run_can_prefix_names() {
    let device = Device::new();
    device.set("latem/prod/MATCH_PASSWORD", "--secret", b"pw");
    device.set("latem/prod/REGION", "--var", b"eu");

    let output = device.run(&[
        "run",
        "--collection",
        "latem",
        "--env",
        "prod",
        "--prefix",
        "LATEM_SECRET_",
        "--",
        "sh",
        "-c",
        r#"printf '%s|%s|%s' "$LATEM_SECRET_MATCH_PASSWORD" "$LATEM_SECRET_REGION" "${MATCH_PASSWORD-unset}""#,
    ]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"pw|eu|unset");

    let prefix = |prefix: &str| {
        device.fails(&[
            "run",
            "--collection",
            "latem",
            "--env",
            "prod",
            "--prefix",
            prefix,
            "--",
            "true",
        ])
    };
    for bad in ["1X_", "LATEM-SECRET_", "LATEM SECRET_"] {
        assert!(prefix(bad).contains("--prefix must be"), "{bad}");
    }

    // The part after the folder is checked by itself, so a prefix doesn't make it usable.
    device.set("latem/staging/1KEY", "--secret", b"x");
    let output = device.fails(&[
        "run",
        "--collection",
        "latem",
        "--env",
        "staging",
        "--prefix",
        "LATEM_SECRET_",
        "--",
        "true",
    ]);
    assert!(output.contains("can't be an environment variable"));
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

#[test]
fn import_env_reads_latem_secrets_files() {
    let device = Device::new();
    let file = device.file(
        "secrets.env",
        b"# latem\n\
          SENTRY_DSN=https://sentry # kept\n\
          \n\
          REGION = eu-west-1\n\
          KEY_P8=\"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\"\n\
          LITERAL='$HOME \\n'\n",
    );
    let import = [
        "import-env",
        &file,
        "--collection",
        "latem",
        "--env",
        "prod",
        "--var",
        "REGION",
    ];
    assert_eq!(
        device.ok(&import),
        "secret  prod/SENTRY_DSN\nvar     prod/REGION\nsecret  prod/KEY_P8\nsecret  prod/LITERAL\n\
         Imported 4 entries into latem/prod/.\n"
    );
    assert_eq!(
        device.ok(&["get", "latem/prod/SENTRY_DSN"]),
        "https://sentry # kept"
    );
    assert_eq!(device.ok(&["get", "latem/prod/LITERAL"]), "$HOME \\n");
    let output = device.run(&[
        "run",
        "--collection",
        "latem",
        "--env",
        "prod",
        "--",
        "sh",
        "-c",
        r#"printf '%s|%s' "$REGION" "$KEY_P8""#,
    ]);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "eu-west-1|-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    );

    let output = device.run_with_stdin(
        &["import-env", "-", "--collection", "latem", "--env", "dev/"],
        b"REGION=local\n",
    );
    assert!(output.status.success());
    assert_eq!(device.ok(&["get", "latem/dev/REGION"]), "local");
}

#[test]
fn import_env_writes_everything_or_nothing() {
    let device = Device::new();
    let import = |contents: &[u8], extra: &[&str]| {
        let file = device.file("secrets.env", contents);
        let mut args = vec![
            "import-env",
            &file,
            "--collection",
            "latem",
            "--env",
            "prod",
        ];
        args.extend(extra);
        device.run(&args)
    };
    let fails = |contents: &[u8], extra: &[&str], expected: &str| {
        let output = import(contents, extra);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!output.status.success());
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!stderr.contains("hunter"), "{stderr}");
        assert_eq!(device.ok(&["list", "latem"]), "");
    };

    fails(b"A=1\nhunter2\n", &[], "line 2: expected NAME=value");
    fails(b"A=1\nA=hunter2\n", &[], "A is set on lines 1 and 2");
    fails(
        b"A=1\nB=hunter\0\n",
        &[],
        "line 2: the value has a NUL byte",
    );
    fails(b"A=1\n", &["--var", "B"], "--var B");
    fails(b"# nothing\n", &[], "has no NAME=value lines");
    fails(
        &[b"A=1\nB=".as_slice(), &[b'x'; 1 << 20]].concat(),
        &[],
        "larger than",
    );
    assert!(
        device
            .fails(&[
                "import-env",
                "/no/such/file",
                "--collection",
                "latem",
                "--env",
                "prod"
            ])
            .contains("can't read /no/such/file")
    );

    assert!(import(b"A=1\nB=2\n", &[]).status.success());
    let output = import(b"A=1\nB=3\nC=4\n", &[]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("latem already has prod/A, prod/B; pass --overwrite")
    );
    assert!(
        device
            .fails(&["get", "latem/prod/C"])
            .contains("doesn't exist")
    );

    let output = import(b"A=1\nB=3\nC=4\n", &["--overwrite", "--var", "C"]);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "secret  prod/B\nvar     prod/C\n\
         Imported 2 entries into latem/prod/; 1 entry already had the same value.\n"
    );
    assert_eq!(device.ok(&["get", "latem/prod/B"]), "3");

    // The same value as a different kind is a change.
    let output = import(b"A=1\n", &["--overwrite", "--var", "A"]);
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("var     prod/A\n")
    );
}

/// `openvault service` running in the background for a device. Stopped with SIGTERM when
/// dropped, as Ctrl-C would.
#[cfg(unix)]
struct Service {
    child: std::process::Child,
    log: std::path::PathBuf,
}

#[cfg(unix)]
impl Service {
    fn start(device: &Device) -> Self {
        let log = device.home.path().join("service.log");
        let child = device
            .command(&["service"])
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let service = Self { child, log };
        let socket = device.home.path().join("service.sock");
        let started = std::time::Instant::now();
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "the service didn't start: {}",
                service.log()
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        service
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Stops it with SIGTERM and returns whether it exited cleanly.
    fn stop(mut self) -> bool {
        self.terminate()
    }

    fn terminate(&mut self) -> bool {
        // SAFETY: kill has no memory-safety preconditions; the pid is our own child's.
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        self.child.wait().unwrap().success()
    }
}

#[cfg(unix)]
impl Drop for Service {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            self.terminate();
        }
    }
}

#[cfg(unix)]
#[test]
fn commands_go_through_the_service() {
    use std::os::unix::fs::PermissionsExt;

    let device = Device::new();
    device.set("latem/prod/SENTRY_DSN", "--secret", b"https://sentry");
    let service = Service::start(&device);

    // With the key file readable by others, a command that opened the vault itself would
    // refuse it, so these can only work through the service.
    let keys = device.home.path().join("keys");
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o644)).unwrap();

    device.set("latem/prod/REGION", "--var", b"eu west");
    assert_eq!(
        device.ok(&["get", "latem/prod/SENTRY_DSN"]),
        "https://sentry"
    );
    assert_eq!(
        device.ok(&["list", "latem"]),
        "var     prod/REGION\nsecret  prod/SENTRY_DSN\n"
    );
    let output = device.run(&[
        "run",
        "--collection",
        "latem",
        "--env",
        "prod",
        "--",
        "sh",
        "-c",
        r#"printf '%s|%s' "$SENTRY_DSN" "$REGION""#,
    ]);
    assert_eq!(
        output.stdout,
        b"https://sentry|eu west",
        "{}",
        service.log()
    );
    let file = device.file("secrets.env", b"TOKEN=abc\nREGION=eu west\n");
    let imported = device.ok(&[
        "import-env",
        &file,
        "--collection",
        "latem",
        "--env",
        "prod",
        "--var",
        "REGION",
        "--overwrite",
    ]);
    assert!(
        imported.contains("1 entry already had the same value"),
        "{imported}"
    );
    device.ok(&["delete", "latem/prod/TOKEN"]);
    assert!(
        device
            .fails(&["get", "latem/prod/TOKEN"])
            .contains("doesn't exist")
    );

    // No admin key here, so the service asks for the recovery phrase through the CLI.
    let output = device.run_with_stdin(&["collections", "create", "ssh"], device.phrase.as_bytes());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(device.ok(&["collections"]), "latem\nssh\n");
    let wrong = RecoveryKey::generate().to_phrase();
    let output = device.run_with_stdin(&["collections", "create", "other"], wrong.as_bytes());
    assert!(String::from_utf8_lossy(&output.stderr).contains("belongs to another vault"));

    let devices = device.ok(&["devices"]);
    assert!(devices.contains("this device"), "{devices}");
    assert!(!devices.contains("openvault service"), "{devices}");

    assert!(service.stop(), "the service didn't exit cleanly");
    assert!(!device.home.path().join("service.sock").exists());
    // Without the service, commands open the vault themselves again.
    assert!(device.fails(&["collections"]).contains("0600"));
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(device.ok(&["get", "latem/prod/REGION"]), "eu west");
}

#[cfg(unix)]
#[test]
fn one_service_per_vault() {
    let device = Device::new();
    let _service = Service::start(&device);
    let error = device.fails(&["service"]);
    assert!(error.contains("already running"), "{error}");
}

#[cfg(unix)]
#[test]
fn the_service_sees_writes_by_other_processes() {
    let device = Device::new();
    let service = Service::start(&device);

    // A collection created by another process, as a command run while the service was
    // starting could. The service's next log entry must follow it.
    let keys = Keys::load(&device.home.path().join("keys")).unwrap();
    let mut vault = Vault::open(&device.home.path().join("vault.db"), keys).unwrap();
    let recovery = RecoveryKey::from_phrase(&device.phrase).unwrap();
    vault
        .create_collection("elsewhere", &recovery.admin_signing_key())
        .unwrap();
    drop(vault);

    device.create_collection("ssh");
    assert_eq!(
        device.ok(&["collections"]),
        "elsewhere\nlatem\nssh\n",
        "{}",
        service.log()
    );
}

#[test]
fn devices_lists_this_device() {
    let device = Device::new();
    let devices = device.ok(&["devices"]);
    let first = devices.lines().next().unwrap();
    assert!(first.starts_with("test "), "{devices}");
    assert!(
        first.contains("file") && first.ends_with("this device"),
        "{devices}"
    );
    assert!(devices.contains("Run `openvault service`"), "{devices}");
}

/// A joining device announces itself to the whole network, so two tests joining at once would
/// each find the other's device. Tests take turns while they join.
#[cfg(unix)]
static JOINING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A child process that is killed if the test fails before it exits, so a waiting
/// `openvault join` doesn't go on announcing itself.
#[cfg(unix)]
struct Child(std::process::Child);

#[cfg(unix)]
impl Drop for Child {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[cfg(unix)]
#[test]
fn a_device_joins_with_a_code() {
    use std::io::{BufRead, BufReader};

    let _turn = JOINING.lock().unwrap_or_else(|e| e.into_inner());
    let admin = Device::new();
    let joiner = Device::empty();
    let mut joining = Child(
        joiner
            .command(&["join", "--keys", "software", "--name", "Desktop"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(joining.0.stdout.take().unwrap()).lines();
    // The code is the indented line of six digits.
    let code = loop {
        let line = lines
            .next()
            .expect("join exited before showing a code")
            .unwrap();
        let digits: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        if line.starts_with("    ")
            && digits.len() == 6
            && digits.bytes().all(|b| b.is_ascii_digit())
        {
            break digits;
        }
    };

    // A wrong code first, which the admin may correct.
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let answers = format!("{wrong}\n{code}\ny\n{}\n", admin.phrase);
    let output = admin.run_with_stdin(&["approve", "--read", "latem"], answers.as_bytes());
    let (stdout, stderr) = (
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Found Desktop") && stderr.contains("Wrong code."),
        "{stderr}"
    );
    assert!(
        stdout.contains("Device    Desktop") && stdout.contains("Scopes    read latem"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Desktop joined the vault, with scopes read latem."),
        "{stdout}"
    );

    let rest: Vec<String> = lines.map(Result::unwrap).collect();
    let status = joining.0.wait().unwrap();
    assert!(status.success(), "join failed");
    assert!(
        rest.iter().any(|line| line.starts_with("Joined the vault")),
        "{rest:?}"
    );
    assert!(!joiner.home.path().join("joining").exists());

    // Each device's log now lists both, with names that open on either.
    for device in [&admin, &joiner] {
        let devices = device.ok(&["devices"]);
        assert!(
            devices.contains("Desktop") && devices.contains("test "),
            "{devices}"
        );
    }
    let error = joiner.fails(&["join"]);
    assert!(error.contains("already in a vault"), "{error}");
}

/// Runs `args` until it prints `expected`, or fails after 60 seconds.
#[cfg(unix)]
fn eventually(device: &Device, args: &[&str], expected: &str) {
    let started = std::time::Instant::now();
    loop {
        let output = device.run(args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && stdout.contains(expected) {
            return;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "{args:?} never printed {expected:?}; last: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Joins `joiner` to `admin`'s vault with read on latem, through the CLI.
#[cfg(unix)]
fn join(admin: &Device, joiner: &Device) {
    use std::io::{BufRead, BufReader};

    let _turn = JOINING.lock().unwrap_or_else(|e| e.into_inner());
    let mut joining = Child(
        joiner
            .command(&["join", "--keys", "software", "--name", "Desktop"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(joining.0.stdout.take().unwrap()).lines();
    let code = loop {
        let line = lines
            .next()
            .expect("join exited before showing a code")
            .unwrap();
        let digits: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        if line.starts_with("    ") && digits.len() == 6 {
            break digits;
        }
    };
    let answers = format!("{code}\ny\n{}\n", admin.phrase);
    let output = admin.run_with_stdin(&["approve", "--read", "latem"], answers.as_bytes());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    lines.for_each(drop);
    assert!(joining.0.wait().unwrap().success());
}

#[cfg(unix)]
#[test]
fn services_sync_a_joined_device() {
    let admin = Device::new();
    admin.set("latem/prod/SENTRY_DSN", "--secret", b"https://sentry");
    let joiner = Device::empty();
    join(&admin, &joiner);
    assert_eq!(joiner.ok(&["collections"]), "", "nothing before sync");

    let admin_service = Service::start(&admin);
    let joiner_service = Service::start(&joiner);
    // The services find each other with mDNS and sync.
    eventually(&joiner, &["get", "latem/prod/SENTRY_DSN"], "https://sentry");
    assert_eq!(joiner.ok(&["collections"]), "latem\n");
    eventually(&admin, &["devices"], "visible");

    // A write on the admin reaches the joined device while both run.
    admin.set("latem/prod/REGION", "--var", b"eu west");
    eventually(&joiner, &["get", "latem/prod/REGION"], "eu west");
    // It can read but not write.
    let output = joiner.run_with_stdin(&["set", "latem/prod/X", "--var"], b"1");
    assert!(String::from_utf8_lossy(&output.stderr).contains("can't write"));

    assert!(admin_service.stop());
    let log = joiner_service.log();
    assert!(log.contains("synced with test"), "{log}");
}
