//! The `openvault` command (design §14).
//!
//! Everything for this device lives in one directory, `~/.openvault` unless `OPENVAULT_HOME`
//! names another: the key file (`keys`) and the vault database (`vault.db`).

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use openvault_core::record::MAX_VALUE_LEN;
use openvault_core::{Kind, Vault, names};
use openvault_crypto::RecoveryKey;
use openvault_keystore::{Backend, Keys};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "openvault",
    version,
    about = "Secrets and variables, encrypted on your own devices."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a vault on this device and show its recovery phrase.
    Init {
        /// Where this device's keys live [default: the Secure Enclave when this Mac has one]
        #[arg(long, value_enum)]
        keys: Option<KeysArg>,
    },
    /// List collections, or create one.
    Collections {
        #[command(subcommand)]
        action: Option<CollectionsAction>,
    },
    /// Set a secret or variable. The value is read from stdin.
    Set {
        /// `<collection>/<name>`, such as `latem/prod/SENTRY_DSN`
        entry: String,
        #[command(flatten)]
        kind: KindArg,
    },
    /// Print the value of a secret or variable.
    Get {
        /// `<collection>/<name>`
        entry: String,
    },
    /// List the names in a collection, or in one folder of it. Values aren't shown.
    List {
        /// `<collection>` or `<collection>/<folder>`
        path: String,
    },
    /// Delete a secret or variable.
    Delete {
        /// `<collection>/<name>`
        entry: String,
    },
    /// Run a command with a folder's secrets and variables as environment variables.
    Run {
        #[arg(long)]
        collection: String,
        /// The folder to load, such as `prod`: `prod/SENTRY_DSN` becomes `SENTRY_DSN`
        #[arg(long)]
        env: String,
        /// The command to run, after `--`
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
}

#[derive(Subcommand)]
enum CollectionsAction {
    /// Create a collection.
    Create { name: String },
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct KindArg {
    /// Store a secret; typing it at the prompt doesn't echo
    #[arg(long)]
    secret: bool,
    /// Store a variable: a value that isn't secret, such as a URL
    #[arg(long)]
    var: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum KeysArg {
    SecureEnclave,
    Software,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("openvault: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Command) -> Result<ExitCode> {
    let home = Home::locate()?;
    match command {
        Command::Init { keys } => {
            let backend = match keys {
                Some(KeysArg::SecureEnclave) => Backend::SecureEnclave,
                Some(KeysArg::Software) => Backend::Software,
                None => Backend::best(),
            };
            init(&home, backend)?;
        }
        Command::Collections { action: None } => {
            for collection in home.open()?.collections()? {
                println!("{}", collection.name);
            }
        }
        Command::Collections {
            action: Some(CollectionsAction::Create { name }),
        } => {
            home.open()?.create_collection(&name)?;
        }
        Command::Set { entry, kind } => {
            set(
                &home,
                &entry,
                if kind.secret { Kind::Secret } else { Kind::Var },
            )?;
        }
        Command::Get { entry } => get(&home, &entry)?,
        Command::List { path } => list(&home, &path)?,
        Command::Delete { entry } => delete(&home, &entry)?,
        Command::Run {
            collection,
            env,
            command,
        } => return run(&home, &collection, &env, &command),
    }
    Ok(ExitCode::SUCCESS)
}

/// The directory holding this device's key file and vault database.
struct Home(PathBuf);

impl Home {
    fn locate() -> Result<Self> {
        if let Some(dir) = std::env::var_os("OPENVAULT_HOME") {
            return Ok(Self(dir.into()));
        }
        let home =
            std::env::home_dir().context("can't find your home directory; set OPENVAULT_HOME")?;
        Ok(Self(home.join(".openvault")))
    }

    fn keys(&self) -> PathBuf {
        self.0.join("keys")
    }

    fn vault(&self) -> PathBuf {
        self.0.join("vault.db")
    }

    fn open(&self) -> Result<Vault<Keys>> {
        if !self.vault().exists() {
            bail!(
                "no vault in {}; run `openvault init` first",
                self.0.display()
            );
        }
        let keys = Keys::load(&self.keys())?;
        Ok(Vault::open(&self.vault(), keys)?)
    }
}

fn init(home: &Home, backend: Backend) -> Result<()> {
    if home.vault().exists() {
        bail!("there is already a vault in {}", home.0.display());
    }
    create_private_dir(&home.0)?;
    let keys = Keys::create(&home.keys(), backend)?;
    let recovery = RecoveryKey::generate();
    let vault = Vault::create(&home.vault(), keys, &recovery.unwrap_key().wrap_key()).inspect_err(
        |_| {
            let _ = fs::remove_file(home.keys());
        },
    )?;

    let keys = match backend {
        Backend::SecureEnclave => "Secure Enclave".to_owned(),
        Backend::Software => format!("software, in {}", home.keys().display()),
    };
    println!("Created a vault in {}.", home.0.display());
    println!();
    println!("  Vault   {}", vault.vault_id());
    println!("  Device  {}", vault.device_id());
    println!("  Keys    {keys}");
    println!();
    println!("Recovery phrase:");
    println!();
    let phrase = recovery.to_phrase();
    let words: Vec<&str> = phrase.split(' ').collect();
    let rows = words.len().div_ceil(4);
    for row in 0..rows {
        let line: Vec<String> = (row..words.len())
            .step_by(rows)
            .map(|i| format!("{:>4}. {:<10}", i + 1, words[i]))
            .collect();
        println!("{}", line.concat().trim_end());
    }
    println!();
    println!("Write these 24 words down and keep them offline, on paper or in the Passwords app.");
    println!("They are shown only once. With them you can recover every collection if this");
    println!("device is lost.");
    Ok(())
}

fn set(home: &Home, entry: &str, kind: Kind) -> Result<()> {
    let (collection, name) = split_entry(entry)?;
    let mut vault = home.open()?;
    let id = vault.collection(collection)?;
    let value = read_value(kind)?;
    vault.set(id, name, kind, &value)?;
    Ok(())
}

fn get(home: &Home, entry: &str) -> Result<()> {
    let (collection, name) = split_entry(entry)?;
    let mut vault = home.open()?;
    let id = vault.collection(collection)?;
    let entry = vault
        .get(id, name)?
        .ok_or_else(|| anyhow!("{collection}/{name} doesn't exist"))?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&entry.value)?;
    if stdout.is_terminal() {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(())
}

fn list(home: &Home, path: &str) -> Result<()> {
    let path = path.trim_end_matches('/');
    let (collection, folder) = match path.split_once('/') {
        Some((collection, folder)) => (collection, Some(folder)),
        None => (path, None),
    };
    names::check_collection(collection)?;
    if let Some(folder) = folder {
        names::check_entry(folder)?;
    }
    let vault = home.open()?;
    let id = vault.collection(collection)?;
    let prefix = folder.map(|folder| format!("{folder}/"));
    for info in vault.list(id)? {
        if prefix
            .as_ref()
            .is_none_or(|prefix| info.name.starts_with(prefix))
        {
            let kind = if info.kind == Kind::Secret {
                "secret"
            } else {
                "var"
            };
            println!("{kind:<6}  {}", info.name);
        }
    }
    Ok(())
}

fn delete(home: &Home, entry: &str) -> Result<()> {
    let (collection, name) = split_entry(entry)?;
    let mut vault = home.open()?;
    let id = vault.collection(collection)?;
    if !vault.delete(id, name)? {
        bail!("{collection}/{name} doesn't exist");
    }
    Ok(())
}

fn run(home: &Home, collection: &str, folder: &str, command: &[OsString]) -> Result<ExitCode> {
    let folder = folder.trim_end_matches('/');
    names::check_collection(collection)?;
    names::check_entry(folder)?;
    let entries = {
        let mut vault = home.open()?;
        let id = vault.collection(collection)?;
        vault.entries_in(id, folder)?
    };
    if entries.is_empty() {
        bail!("{collection}/{folder}/ has no secrets or variables");
    }

    let (program, args) = command.split_first().expect("clap requires a command");
    let mut child = process::Command::new(program);
    child.args(args);
    for entry in &entries {
        let var = &entry.name[folder.len() + 1..];
        if !is_env_name(var) {
            bail!(
                "{collection}/{} can't be an environment variable: the part after {folder}/ \
                 must be letters, digits and '_', not starting with a digit",
                entry.name
            );
        }
        child.env(
            var,
            env_value(&entry.value).with_context(|| format!("{collection}/{}", entry.name))?,
        );
    }
    exec(child, program)
}

/// Replaces this process with the command, so it keeps the terminal, signals and exit status,
/// and the decrypted values leave this process's memory with it.
#[cfg(unix)]
fn exec(mut child: process::Command, program: &OsStr) -> Result<ExitCode> {
    use std::os::unix::process::CommandExt;

    let error = child.exec();
    eprintln!("openvault: can't run {}: {error}", program.display());
    // The shell's codes for a command that wasn't found or couldn't be run.
    Ok(ExitCode::from(match error.kind() {
        io::ErrorKind::NotFound => 127,
        _ => 126,
    }))
}

#[cfg(not(unix))]
fn exec(mut child: process::Command, program: &OsStr) -> Result<ExitCode> {
    let status = child
        .status()
        .with_context(|| format!("can't run {}", program.display()))?;
    Ok(match status.code() {
        Some(0) => ExitCode::SUCCESS,
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::FAILURE,
    })
}

#[cfg(unix)]
fn env_value(value: &[u8]) -> Result<&OsStr> {
    use std::os::unix::ffi::OsStrExt;

    if value.contains(&0) {
        bail!("contains a NUL byte, which an environment variable can't hold");
    }
    Ok(OsStr::from_bytes(value))
}

#[cfg(not(unix))]
fn env_value(value: &[u8]) -> Result<&OsStr> {
    if value.contains(&0) {
        bail!("contains a NUL byte, which an environment variable can't hold");
    }
    let value = std::str::from_utf8(value).context("isn't UTF-8")?;
    Ok(OsStr::new(value))
}

fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Splits `<collection>/<name>` and checks both parts.
fn split_entry(entry: &str) -> Result<(&str, &str)> {
    let (collection, name) = entry
        .split_once('/')
        .ok_or_else(|| anyhow!("expected <collection>/<name>, such as latem/prod/SENTRY_DSN"))?;
    names::check_collection(collection)?;
    names::check_entry(name)?;
    Ok((collection, name))
}

/// Reads a value from stdin, either typed at a prompt (hidden for secrets) or piped. One
/// trailing newline is dropped, so `echo value | openvault set …` stores `value`.
fn read_value(kind: Kind) -> Result<Zeroizing<Vec<u8>>> {
    let stdin = io::stdin();
    let mut value = if stdin.is_terminal() {
        let line = if kind == Kind::Secret {
            Zeroizing::new(rpassword::prompt_password("Value (hidden): ")?)
        } else {
            eprint!("Value: ");
            let mut line = Zeroizing::new(String::new());
            stdin.read_line(&mut line)?;
            line
        };
        Zeroizing::new(line.as_bytes().to_vec())
    } else {
        // Sized up front so reading never reallocates and leaves copies behind. Two spare
        // bytes allow a trailing "\r\n"; anything longer fails the store's size check.
        let mut value = Zeroizing::new(Vec::with_capacity(MAX_VALUE_LEN + 3));
        stdin
            .lock()
            .take(MAX_VALUE_LEN as u64 + 3)
            .read_to_end(&mut value)?;
        value
    };
    if value.ends_with(b"\n") {
        value.pop();
        if value.ends_with(b"\r") {
            value.pop();
        }
    }
    Ok(value)
}

fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(path)
        .with_context(|| format!("can't create {}", path.display()))
}
