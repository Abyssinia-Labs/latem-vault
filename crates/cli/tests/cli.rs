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
    assert!(run("prod").contains("has no secrets, variables or files"));

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

/// A folder to import: a keystore, a key in a subfolder, a script, a 2.5 MiB file, and Finder's
/// litter.
fn release_folder(device: &Device) -> std::path::PathBuf {
    let dir = device.home.path().join("src/release");
    std::fs::create_dir_all(dir.join("ios")).unwrap();
    std::fs::write(dir.join("upload.jks"), vec![7u8; 3000]).unwrap();
    std::fs::write(
        dir.join("ios/AuthKey_ABC.p8"),
        b"-----BEGIN PRIVATE KEY-----",
    )
    .unwrap();
    std::fs::write(dir.join("big.bin"), big_file()).unwrap();
    std::fs::write(dir.join("sign.sh"), b"#!/bin/sh\necho signed\n").unwrap();
    std::fs::write(dir.join(".DS_Store"), b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("sign.sh");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir
}

/// 2.5 MiB that differ from one MiB to the next.
fn big_file() -> Vec<u8> {
    (0..(5usize << 19))
        .map(|i| (i / 1000 % 251) as u8)
        .collect()
}

fn chunk_files(device: &Device) -> usize {
    let dir = device.home.path().join("chunks");
    std::fs::read_dir(&dir)
        .map(|dirs| {
            dirs.flatten()
                .map(|sub| std::fs::read_dir(sub.path()).unwrap().count())
                .sum()
        })
        .unwrap_or(0)
}

#[test]
fn files_are_imported_read_and_run_with() {
    let device = Device::new();
    let dir = release_folder(&device);
    let dir = dir.to_str().unwrap();
    let import = |args: &[&str]| {
        let mut all = vec![
            "import",
            dir,
            "--collection",
            "latem",
            "--disk-not-encrypted",
        ];
        all.extend_from_slice(args);
        device.ok(&all)
    };
    let output = import(&[]);
    assert!(
        output.contains("Imported 4 files (2.5 MiB) into latem."),
        "{output}"
    );
    assert!(output.contains(".DS_Store: it's Finder's"), "{output}");
    assert!(output.contains("The originals are still in"), "{output}");
    assert_eq!(
        device.ok(&["list", "latem/release"]),
        "file    release/big.bin  2.5 MiB\n\
         file    release/ios/AuthKey_ABC.p8  27 B\n\
         file    release/sign.sh  22 B\n\
         file    release/upload.jks  2.9 KiB\n"
    );
    // The 2.5 MiB file is three chunks; the rest are in their manifests.
    assert_eq!(chunk_files(&device), 3);

    // To stdout, or to a private file with its time and executable bit.
    let output = device.run(&["get", "latem/release/upload.jks"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, vec![7u8; 3000]);
    let out = device.home.path().join("out.bin");
    device.ok(&["get", "latem/release/big.bin", "-o", out.to_str().unwrap()]);
    assert!(std::fs::read(&out).unwrap() == big_file());
    let script = device.home.path().join("sign.sh");
    device.ok(&[
        "get",
        "latem/release/sign.sh",
        "-o",
        script.to_str().unwrap(),
    ]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&out), mode(&script)), (0o600, 0o700));
    }
    // Kept to the second.
    let secs = |path: &std::path::Path| {
        std::fs::metadata(path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    assert_eq!(
        secs(&script),
        secs(&std::path::Path::new(dir).join("sign.sh"))
    );

    // Importing again writes nothing; a change near the end writes only the last chunk.
    let output = import(&[]);
    assert!(
        output
            .contains("Imported 0 files (0 B) into latem; 4 files already had the same contents."),
        "{output}"
    );
    let mut changed = big_file();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(format!("{dir}/big.bin"), &changed).unwrap();
    assert!(import(&[]).contains("Imported 1 file (2.5 MiB)"));
    assert_eq!(chunk_files(&device), 4);

    // `run` writes the folder's files somewhere private, and deletes them after.
    let output = device.ok(&[
        "run",
        "--collection",
        "latem",
        "--env",
        "release",
        "--",
        "sh",
        "-c",
        r#"wc -c < "$UPLOAD_JKS" | tr -d ' '; "$SIGN_SH"; cat "$AUTHKEY_ABC_P8"; echo; dirname "$BIG_BIN""#,
    ]);
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        &lines[..3],
        ["3000", "signed", "-----BEGIN PRIVATE KEY-----"],
        "{output}"
    );
    let run_dir = std::path::Path::new(lines[3]);
    assert!(
        run_dir.starts_with(std::env::temp_dir().canonicalize().unwrap())
            || run_dir.starts_with(std::env::temp_dir()),
        "{output}"
    );
    assert!(!run_dir.exists(), "{} is left behind", run_dir.display());
    // The command's exit status is run's.
    let status = device
        .run(&[
            "run",
            "--collection",
            "latem",
            "--env",
            "release",
            "--",
            "sh",
            "-c",
            "exit 3",
        ])
        .status;
    assert_eq!(status.code(), Some(3));

    // A secret and a file can't set the same variable.
    device.set("latem/release/UPLOAD_JKS", "--secret", b"x");
    let error = device.fails(&[
        "run",
        "--collection",
        "latem",
        "--env",
        "release",
        "--",
        "true",
    ]);
    assert!(error.contains("would both set UPLOAD_JKS"), "{error}");
    // Nor can a file take a secret's name.
    let error = device.fails(&[
        "import",
        &device.file("UPLOAD_JKS", b"x"),
        "--collection",
        "latem",
        "--into",
        "release",
        "--disk-not-encrypted",
    ]);
    assert!(
        error.contains("is a secret; a file can't take its name"),
        "{error}"
    );

    // A single file goes at the top, or into a folder.
    let single = device.file("notes.txt", b"hello");
    device.ok(&[
        "import",
        &single,
        "--collection",
        "latem",
        "--disk-not-encrypted",
    ]);
    assert_eq!(device.ok(&["get", "latem/notes.txt"]), "hello");
    device.ok(&["delete", "latem/release/big.bin"]);
    assert!(
        device
            .fails(&["get", "latem/release/big.bin"])
            .contains("doesn't exist")
    );

    assert_eq!(
        device.ok(&["placement", "latem"]),
        "latem: keep. Every current file's chunks stay here.\n"
    );
    assert!(
        device
            .ok(&["placement", "latem", "on-demand"])
            .contains("latem: on demand.")
    );
    assert!(device.ok(&["placement", "latem"]).contains("on demand"));
}

#[cfg(unix)]
#[test]
fn files_go_through_the_service() {
    let device = Device::new();
    let dir = release_folder(&device);
    let service = Service::start(&device);
    let output = device.ok(&[
        "import",
        dir.to_str().unwrap(),
        "--collection",
        "latem",
        "--into",
        "prod",
        "--disk-not-encrypted",
    ]);
    assert!(
        output.contains("Imported 4 files"),
        "{output}\n{}",
        service.log()
    );
    let output = device.run(&["get", "latem/prod/big.bin"]);
    assert!(output.stdout == big_file(), "{}", service.log());
    let output = device.ok(&[
        "run",
        "--collection",
        "latem",
        "--env",
        "prod",
        "--",
        "sh",
        "-c",
        r#"wc -c < "$BIG_BIN" | tr -d ' '"#,
    ]);
    assert_eq!(output, format!("{}\n", 5 << 19));
    assert!(
        device
            .ok(&["list", "latem"])
            .contains("file    prod/big.bin  2.5 MiB\n")
    );
    assert!(service.stop(), "the service didn't exit cleanly");
}

#[cfg(unix)]
#[test]
fn the_service_can_log_to_a_file() {
    let device = Device::empty();
    // Even the error before the service starts goes to the file, and `~/` is HOME.
    let output = device
        .command(&["service", "--log", "~/service.log"])
        .env("HOME", device.home.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty(), "{output:?}");
    let log = std::fs::read_to_string(device.home.path().join("service.log")).unwrap();
    assert!(log.contains("no vault in"), "{log}");

    let error = device.fails(&["service", "--log", "service.log", "status"]);
    assert!(error.contains("cannot be used with"), "{error}");
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

/// Reaching devices away from home is behind the `coordinator` feature, which is off by default.
#[cfg(not(feature = "coordinator"))]
#[test]
fn the_coordinator_is_left_out() {
    let device = Device::new();
    for command in ["coordinator", "grandfather"] {
        let error = device.fails(&[command]);
        assert!(error.contains("unrecognized subcommand"), "{error}");
    }
}

#[cfg(feature = "coordinator")]
#[test]
fn coordinator_is_set_per_device() {
    let device = Device::new();
    let none = device.ok(&["coordinator"]);
    assert!(none.starts_with("None:"), "{none}");
    assert!(none.contains("openvault grandfather --vault "), "{none}");

    let id = "ab".repeat(32);
    let error = device.fails(&["coordinator", "set", &format!("{id}@vault.example.com")]);
    assert!(error.contains("not a grandfather's address"), "{error}");
    device.ok(&[
        "coordinator",
        "set",
        &format!("ov1:{id}@Vault.Example.com:8443"),
    ]);
    let shown = device.ok(&["coordinator"]);
    assert_eq!(
        shown.lines().next().unwrap(),
        format!("ov1:{id}@vault.example.com:8443")
    );

    device.ok(&["coordinator", "unset"]);
    assert!(device.ok(&["coordinator"]).starts_with("None:"));
    let error = device.fails(&["coordinator", "unset"]);
    assert!(error.contains("no coordinator set"), "{error}");
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

#[test]
fn scopes_change_with_an_admin_signature() {
    let admin = Device::new();
    admin.create_collection("ssh");
    let joiner = Device::empty();
    join(&admin, &joiner);
    let signed = |args: &[&str]| {
        let output = admin.run_with_stdin(args, format!("{}\n", admin.phrase).as_bytes());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };

    let out = signed(&["scope", "Desktop", "ssh", "read"]);
    assert!(out.contains("Desktop now has read on ssh."), "{out}");
    assert!(out.contains("ssh's keys reach Desktop"), "{out}");
    let out = signed(&["scope", "Desktop", "latem", "write"]);
    assert_eq!(out, "Desktop now has write on latem.\n");
    let out = signed(&["scope", "Desktop", "latem", "read"]);
    assert!(
        out.contains(
            "latem has a new key, so what Desktop signs with the old one no longer counts"
        ),
        "{out}"
    );
    let out = signed(&["scope", "Desktop", "ssh", "none"]);
    assert!(
        out.contains("Desktop no longer has a scope on ssh.")
            && out.contains("nothing written from now on reaches Desktop"),
        "{out}"
    );

    // Refused before any phrase is asked for.
    assert!(
        admin
            .fails(&["scope", "Desktop", "ssh", "none"])
            .contains("already has that scope")
    );
    assert!(
        admin
            .fails(&["scope", "Nobody", "ssh", "read"])
            .contains("no device is called Nobody")
    );
    assert!(
        admin
            .fails(&["scope", "Desktop", "nope", "read"])
            .contains("no collection nope")
    );
    assert!(
        admin
            .fails(&["scope", "test", "ssh", "read"])
            .contains("is this device")
    );
}

#[cfg(unix)]
#[test]
fn services_sync_a_joined_device() {
    use std::time::{Duration, Instant};

    use openvault_service::api::{PeerState, Request, Response};

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
    // Once its session has caught up, apps see the device as on the network rather than
    // syncing, though the session stays open until a minute passes without a message
    // (sync.md, lifetime). It logs what it moved only when it closes.
    let socket = admin.home.path().join("service.sock");
    let started = Instant::now();
    loop {
        let Ok(Some(Response::Peers(peers))) =
            openvault_service::client::call(&socket, &Request::Peers)
        else {
            panic!("no peers: {}", admin_service.log());
        };
        if peers[0].state == PeerState::OnNetwork {
            break;
        }
        assert_eq!(peers[0].state, PeerState::Syncing);
        assert!(started.elapsed() < Duration::from_secs(15), "{peers:?}");
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        !joiner_service.log().contains("synced with"),
        "the session closed: {}",
        joiner_service.log()
    );
    // It can read but not write.
    let output = joiner.run_with_stdin(&["set", "latem/prod/X", "--var"], b"1");
    assert!(String::from_utf8_lossy(&output.stderr).contains("can't write"));
    // A session logs what it moved when it closes, here because the admin's service stops.
    assert!(admin_service.stop());
    let log = joiner_service.log();
    assert!(log.contains("synced with test"), "{log}");

    // Once revoked, it gets nothing new, though the two still see each other. The review lists
    // what it could read.
    let admin_service = Service::start(&admin);
    eventually(&admin, &["devices"], "visible");
    let answers = format!("y\n{}\n", admin.phrase);
    let output = admin.run_with_stdin(&["devices", "revoke", "Desktop"], answers.as_bytes());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("Reads     latem (1 secret)"), "{stdout}");
    assert!(stdout.contains("New keys for latem"), "{stdout}");
    assert!(stdout.contains("  latem/prod/SENTRY_DSN"), "{stdout}");
    let devices = admin.ok(&["devices"]);
    assert!(
        devices
            .lines()
            .any(|line| line.starts_with("Desktop") && line.ends_with("revoked")),
        "{devices}"
    );
    assert!(
        admin
            .fails(&["devices", "revoke", "Desktop"])
            .contains("already revoked")
    );
    admin.set("latem/prod/AFTER", "--var", b"secret now");
    assert_eq!(admin.ok(&["get", "latem/prod/REGION"]), "eu west");
    // Its session ends once it asks for the new log entries.
    let started = std::time::Instant::now();
    while !joiner_service.log().contains("not a member") {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "{}",
            joiner_service.log()
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(
        joiner.run(&["get", "latem/prod/AFTER"]).stdout.is_empty(),
        "{}",
        joiner_service.log()
    );
    assert!(admin_service.stop());
}

/// The requests the Mac app makes (service.md, for apps), straight on the socket.
#[cfg(unix)]
#[test]
fn apps_read_and_watch_through_the_service() {
    use std::time::{Duration, Instant};

    use openvault_core::Kind;
    use openvault_core::membership::Scope;
    use openvault_service::api::{self, Event, Request, Response, Signer};

    let device = Device::new();
    device.set("latem/prod/SENTRY_DSN", "--secret", b"https://sentry");
    device.set("latem/prod/REGION", "--var", b"eu west");
    let service = Service::start(&device);
    let socket = device.home.path().join("service.sock");
    let call = |request: Request| {
        openvault_service::client::call(&socket, &request)
            .unwrap()
            .unwrap()
    };

    let Response::Vault(info) = call(Request::Vault) else {
        panic!("no vault info: {}", service.log());
    };
    assert!(!info.admin, "software keys have no admin key");
    let recovery = RecoveryKey::from_phrase(&device.phrase).unwrap();
    let fingerprint = openvault_crypto::hash::hash(recovery.unwrap_key().wrap_key().as_bytes());
    assert_eq!(info.recovery, fingerprint[..4]);

    let Response::CollectionSummaries(summaries) = call(Request::CollectionSummaries) else {
        panic!("no summaries");
    };
    assert_eq!(summaries.len(), 1);
    let latem = &summaries[0];
    assert_eq!(
        (
            latem.name.as_str(),
            latem.secrets,
            latem.variables,
            latem.key
        ),
        ("latem", 1, 1, 0)
    );
    assert_eq!(latem.devices, [(info.device, Scope::Write)]);

    let Response::EntryDetails(details) = call(Request::EntryDetails {
        collection: "latem".into(),
    }) else {
        panic!("no entry details");
    };
    let shown: Vec<_> = details
        .iter()
        .map(|d| (d.name.as_str(), d.kind, &d.value[..], d.set_by, d.key))
        .collect();
    assert_eq!(
        shown,
        [
            ("prod/REGION", Kind::Var, &b"eu west"[..], info.device, 0),
            // A list never holds a secret's value.
            ("prod/SENTRY_DSN", Kind::Secret, &b""[..], info.device, 0),
        ]
    );

    let Response::Log(lines) = call(Request::Log { from: 0, max: 256 }) else {
        panic!("no log");
    };
    assert_eq!(lines[0].change, 0x01, "genesis comes first");
    assert!(lines.iter().all(|line| line.signer == Signer::Recovery));
    assert_eq!(lines.last().unwrap().seq, info.log_head);
    let Response::Log(page) = call(Request::Log {
        from: info.log_head,
        max: 5,
    }) else {
        panic!("no log page");
    };
    assert_eq!(page.len(), 1);

    // A change to the scope the device already has is refused before the phrase is needed.
    let Response::Error { message, .. } = call(Request::SetScopes {
        device: info.device,
        changes: vec![("latem".into(), Scope::Write)],
        recovery_phrase: None,
    }) else {
        panic!("an unchanged scope was set");
    };
    assert!(message.contains("already has those scopes"), "{message}");
    let Response::Peers(peers) = call(Request::Peers) else {
        panic!("no peers");
    };
    assert!(peers.is_empty(), "{peers:?}");

    // A watch hears of a write by another command.
    let mut watch = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    api::write_message(&mut watch, &Request::Watch.encode()).unwrap();
    let (kind, body) = api::read_message(&mut watch).unwrap();
    assert!(matches!(Response::decode(kind, &body), Ok(Response::Done)));
    watch
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    device.set("latem/prod/TOKEN", "--secret", b"abc");
    let started = Instant::now();
    loop {
        assert!(started.elapsed() < Duration::from_secs(10), "no event");
        let (kind, body) = api::read_message(&mut watch).unwrap();
        let Ok(Response::Event(event)) = Response::decode(kind, &body) else {
            panic!("not an event");
        };
        if event.what & Event::ENTRIES != 0 {
            assert_eq!(event.collections, ["latem"]);
            break;
        }
    }
    drop(watch);
    assert!(service.stop(), "the service didn't exit cleanly");
}

/// A device joins through the service, as the Mac app approves one (service.md, for apps).
#[cfg(unix)]
#[test]
fn devices_join_through_the_service() {
    use std::io::{BufRead, BufReader};
    use std::time::{Duration, Instant};

    use openvault_core::membership::Scope;
    use openvault_service::api::{ErrorCode, Request, Response};

    let _turn = JOINING.lock().unwrap_or_else(|e| e.into_inner());
    let admin = Device::new();
    let service = Service::start(&admin);
    let socket = admin.home.path().join("service.sock");
    let call = |request: Request| {
        openvault_service::client::call(&socket, &request)
            .unwrap()
            .unwrap()
    };

    let joiner = Device::empty();
    let log = joiner.home.path().join("join.log");
    let mut join = joiner
        .command(&["join", "--keys", "software", "--name", "Joiner"])
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .map(Child)
        .unwrap();
    let mut lines = BufReader::new(join.0.stdout.take().unwrap()).lines();
    let code = loop {
        let line = lines.next().expect("join printed no code").unwrap();
        let digits: String = line.chars().filter(char::is_ascii_digit).collect();
        if digits.len() == 6 && line.trim().len() == 7 {
            break digits;
        }
    };

    let started = Instant::now();
    let found = loop {
        let Response::Joiners(joiners) = call(Request::Joiners) else {
            panic!("no joiners");
        };
        if let Some(found) = joiners.into_iter().find(|j| j.name == "Joiner") {
            break found;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the joiner never showed up: {}",
            service.log()
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    assert_eq!(found.platform, std::env::consts::OS);

    let wrong = if code == "000000" { "111111" } else { "000000" };
    let Response::Error {
        code: ErrorCode::WrongCode,
        message,
    } = call(Request::CheckCode {
        joiner: found.endpoint,
        code: wrong.to_owned().into(),
    })
    else {
        panic!("a wrong code got through");
    };
    assert_eq!(message, "wrong code; 2 tries left");
    let Response::JoinRequest(request) = call(Request::CheckCode {
        joiner: found.endpoint,
        code: code.into(),
    }) else {
        panic!("the code didn't match: {}", service.log());
    };
    assert_eq!((request.name.as_str(), request.hardware), ("Joiner", false));

    // No admin key here, so approving needs the recovery phrase.
    let scopes = vec![("latem".to_owned(), Scope::Read)];
    let Response::Error {
        code: ErrorCode::RecoveryPhraseNeeded,
        ..
    } = call(Request::Approve {
        session: request.session,
        scopes: scopes.clone(),
        recovery_phrase: None,
    })
    else {
        panic!("approved without a signature");
    };
    let approved = call(Request::Approve {
        session: request.session,
        scopes,
        recovery_phrase: Some(admin.phrase.clone().into()),
    });
    assert!(matches!(approved, Response::Done), "{approved:?}");

    let status = join.0.wait().unwrap();
    assert!(
        status.success(),
        "join failed: {}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    assert!(
        rest.iter().any(|line| line.starts_with("Joined the vault")),
        "{rest:?}"
    );
    let Response::Peers(peers) = call(Request::Peers) else {
        panic!("no peers");
    };
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].device, request.device);
    assert!(service.stop(), "the service didn't exit cleanly");
}

/// `openvault approve` takes the service's way when one runs.
#[cfg(unix)]
#[test]
fn approve_goes_through_the_service() {
    use std::io::{BufRead, BufReader};

    let _turn = JOINING.lock().unwrap_or_else(|e| e.into_inner());
    let admin = Device::new();
    let service = Service::start(&admin);
    let joiner = Device::empty();
    let log = joiner.home.path().join("join.log");
    let mut join = joiner
        .command(&["join", "--keys", "software", "--name", "Joiner"])
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .map(Child)
        .unwrap();
    let mut lines = BufReader::new(join.0.stdout.take().unwrap()).lines();
    let code = loop {
        let line = lines.next().expect("join printed no code").unwrap();
        let digits: String = line.chars().filter(char::is_ascii_digit).collect();
        if digits.len() == 6 && line.trim().len() == 7 {
            break digits;
        }
    };

    let answers = format!("{code}\ny\n{}\n", admin.phrase);
    let output = admin.run_with_stdin(&["approve", "--read", "latem"], answers.as_bytes());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}\n{}", service.log());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Joiner joined the vault, with scopes read latem."),
        "{stdout}"
    );
    assert!(
        join.0.wait().unwrap().success(),
        "join failed: {}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    let devices = admin.ok(&["devices"]);
    assert!(devices.contains("Joiner"), "{devices}");
}
