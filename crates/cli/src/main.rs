//! The `openvault` command (design §14).
//!
//! Everything for this device lives in one directory, `~/.openvault` unless `OPENVAULT_HOME`
//! names another: the key file (`keys`) and the vault database (`vault.db`).

mod env_file;

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use openvault_core::record::MAX_VALUE_LEN;
use openvault_core::{Kind, Vault, membership, names};
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
        /// This device's name in the vault [default: this computer's host name]
        #[arg(long)]
        name: Option<String>,
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
        /// Put this before every variable name, such as `LATEM_SECRET_` for latem:
        /// `prod/SENTRY_DSN` becomes `LATEM_SECRET_SENTRY_DSN`
        #[arg(long, default_value = "", hide_default_value = true)]
        prefix: String,
        /// The command to run, after `--`
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
    /// Import a NAME=value file, such as latem's secrets.env, into a folder. Every name is
    /// imported as a secret unless given with --var.
    ImportEnv {
        /// The file to read, or `-` for stdin
        file: PathBuf,
        #[arg(long)]
        collection: String,
        /// The folder to import into, such as `prod`: `SENTRY_DSN` becomes `prod/SENTRY_DSN`
        #[arg(long)]
        env: String,
        /// Import NAME as a variable instead of a secret; repeat for each one
        #[arg(long = "var", value_name = "NAME")]
        vars: Vec<String>,
        /// Replace entries that already exist, instead of stopping
        #[arg(long)]
        overwrite: bool,
    },
}

#[derive(Subcommand)]
enum CollectionsAction {
    /// Create a collection. Asks for the recovery phrase, which signs as admin until this
    /// device has an admin key of its own.
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
        Command::Init { keys, name } => {
            let backend = match keys {
                Some(KeysArg::SecureEnclave) => Backend::SecureEnclave,
                Some(KeysArg::Software) => Backend::Software,
                None => Backend::best(),
            };
            init(&home, backend, &name.unwrap_or_else(default_device_name))?;
        }
        Command::Collections { action: None } => {
            for collection in home.open()?.collections()? {
                println!("{}", collection.name);
            }
        }
        Command::Collections {
            action: Some(CollectionsAction::Create { name }),
        } => create_collection(&home, &name)?,
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
            prefix,
            command,
        } => return run(&home, &collection, &env, &prefix, &command),
        Command::ImportEnv {
            file,
            collection,
            env,
            vars,
            overwrite,
        } => import_env(&home, &file, &collection, &env, &vars, overwrite)?,
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

fn init(home: &Home, backend: Backend, name: &str) -> Result<()> {
    if home.vault().exists() {
        bail!("there is already a vault in {}", home.0.display());
    }
    create_private_dir(&home.0)?;
    let keys = Keys::create(&home.keys(), backend)?;
    let recovery = RecoveryKey::generate();
    let vault = Vault::create(&home.vault(), keys, &recovery, name).inspect_err(|_| {
        let _ = fs::remove_file(home.keys());
    })?;

    let keys = match backend {
        Backend::SecureEnclave => "Secure Enclave".to_owned(),
        Backend::Software => format!("software, in {}", home.keys().display()),
    };
    println!("Created a vault in {}.", home.0.display());
    println!();
    println!("  Vault   {}", vault.vault_id());
    println!("  Device  {name}, {}", vault.device_id());
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
    println!("device is lost. Until this device has an admin key of its own, creating a");
    println!("collection asks for them too.");
    Ok(())
}

/// Creates a collection. Its set_scope entry needs an admin signature, which for now comes
/// from the recovery key, since devices don't have admin keys of their own yet. A vault from
/// before the membership log starts its log first, with the same phrase.
fn create_collection(home: &Home, name: &str) -> Result<()> {
    names::check_collection(name)?;
    let mut vault = home.open()?;
    // Checked before asking for 24 words.
    if vault.collection(name).is_ok() {
        bail!("collection {name} already exists");
    }
    if io::stdin().is_terminal() {
        eprintln!("Creating a collection needs an admin signature. Until this device has an");
        eprintln!("admin key of its own, that comes from your recovery phrase.");
    }
    let recovery = read_recovery_phrase()?;
    if !vault.is_recovery_key(&recovery) {
        bail!("that recovery phrase belongs to another vault");
    }
    if vault.membership().is_none() {
        vault.start_log(&recovery, &default_device_name())?;
        println!("Started this vault's membership log.");
    }
    vault.create_collection(name, &recovery.admin_signing_key())?;
    Ok(())
}

/// Reads a recovery phrase: typed at a hidden prompt, or the first line of stdin.
fn read_recovery_phrase() -> Result<RecoveryKey> {
    // 24 words of at most 8 letters, with room for extra spaces.
    const MAX_LEN: usize = 1024;
    let stdin = io::stdin();
    let phrase = if stdin.is_terminal() {
        Zeroizing::new(rpassword::prompt_password("Recovery phrase (hidden): ")?)
    } else {
        // Sized up front so reading never reallocates and leaves copies behind.
        let mut line = Zeroizing::new(String::with_capacity(MAX_LEN + 1));
        stdin.lock().take(MAX_LEN as u64 + 1).read_line(&mut line)?;
        line
    };
    Ok(RecoveryKey::from_phrase(&phrase)?)
}

/// This computer's host name without `.local`, as the device's name in the membership log.
fn default_device_name() -> String {
    let host = hostname().unwrap_or_default();
    let host = host.strip_suffix(".local").unwrap_or(&host);
    let mut name = String::new();
    for c in host.chars().filter(|c| !c.is_control()) {
        if name.len() + c.len_utf8() > membership::MAX_NAME_LEN {
            break;
        }
        name.push(c);
    }
    if name.is_empty() {
        "device".to_owned()
    } else {
        name
    }
}

#[cfg(unix)]
fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the pointer and length describe `buf`, which gethostname writes into.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

#[cfg(not(unix))]
fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
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
            println!("{:<6}  {}", kind_label(info.kind), info.name);
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

fn run(
    home: &Home,
    collection: &str,
    folder: &str,
    prefix: &str,
    command: &[OsString],
) -> Result<ExitCode> {
    let folder = folder.trim_end_matches('/');
    names::check_collection(collection)?;
    names::check_entry(folder)?;
    if !prefix.is_empty() && !is_env_name(prefix) {
        bail!("--prefix must be letters, digits and '_', not starting with a digit");
    }
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
        // Checked without the prefix, so a name is usable the same way with or without one.
        let var = &entry.name[folder.len() + 1..];
        if !is_env_name(var) {
            bail!(
                "{collection}/{} can't be an environment variable: the part after {folder}/ \
                 must be letters, digits and '_', not starting with a digit",
                entry.name
            );
        }
        child.env(
            format!("{prefix}{var}"),
            env_value(&entry.value).with_context(|| format!("{collection}/{}", entry.name))?,
        );
    }
    exec(child, program)
}

fn import_env(
    home: &Home,
    file: &Path,
    collection: &str,
    folder: &str,
    vars: &[String],
    overwrite: bool,
) -> Result<()> {
    let folder = folder.trim_end_matches('/');
    names::check_collection(collection)?;
    names::check_entry(folder)?;
    let source = if file == Path::new("-") {
        "stdin".to_owned()
    } else {
        file.display().to_string()
    };
    let contents = read_env_file(file).with_context(|| format!("can't read {source}"))?;
    let lines = env_file::parse(&contents).with_context(|| source.clone())?;
    drop(contents);
    if lines.is_empty() {
        bail!("{source} has no NAME=value lines");
    }
    for var in vars {
        if !lines.iter().any(|line| line.name == *var) {
            bail!("--var {var}: {source} doesn't set {var}");
        }
    }
    let mut entries = Vec::with_capacity(lines.len());
    for line in &lines {
        // `run` couldn't pass it on, so refuse it now rather than then.
        if line.value.contains(&0) {
            bail!(
                "{source}: line {}: the value has a NUL byte, which an environment variable \
                 can't hold",
                line.number
            );
        }
        let name = format!("{folder}/{}", line.name);
        names::check_entry(&name)?;
        let kind = if vars.contains(&line.name) {
            Kind::Var
        } else {
            Kind::Secret
        };
        entries.push((name, kind, line.value.as_slice()));
    }

    let mut vault = home.open()?;
    let id = vault.collection(collection)?;
    let existing: HashMap<String, Kind> = vault
        .list(id)?
        .into_iter()
        .map(|info| (info.name, info.kind))
        .collect();
    let taken: Vec<&str> = entries
        .iter()
        .filter(|(name, ..)| existing.contains_key(name))
        .map(|(name, ..)| name.as_str())
        .collect();
    if !overwrite && !taken.is_empty() {
        bail!(
            "{collection} already has {}; pass --overwrite to replace {}",
            taken.join(", "),
            if taken.len() == 1 { "it" } else { "them" }
        );
    }
    // Rewriting a value that hasn't changed would only add a version for no reason.
    let mut unchanged = 0;
    let mut writes = Vec::with_capacity(entries.len());
    for (name, kind, value) in &entries {
        if existing.get(name) == Some(kind)
            && vault
                .get(id, name)?
                .is_some_and(|entry| entry.value.as_slice() == *value)
        {
            unchanged += 1;
        } else {
            writes.push((name.as_str(), *kind, *value));
        }
    }
    vault.set_all(id, writes.iter().copied())?;

    for (name, kind, _) in &writes {
        println!("{:<6}  {name}", kind_label(*kind));
    }
    let count = |n: usize| {
        if n == 1 {
            "1 entry".to_owned()
        } else {
            format!("{n} entries")
        }
    };
    print!(
        "Imported {} into {collection}/{folder}/",
        count(writes.len())
    );
    match unchanged {
        0 => println!("."),
        1 => println!("; 1 entry already had the same value."),
        n => println!("; {n} entries already had the same value."),
    }
    Ok(())
}

/// Reads the whole file, or stdin for `-`, up to latem's limit for `secrets.env`.
fn read_env_file(file: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let reader: Box<dyn Read> = if file == Path::new("-") {
        Box::new(io::stdin().lock())
    } else {
        Box::new(fs::File::open(file)?)
    };
    // Sized up front so reading never reallocates and leaves copies behind.
    let mut contents = Zeroizing::new(Vec::with_capacity(env_file::MAX_LEN + 1));
    reader
        .take(env_file::MAX_LEN as u64 + 1)
        .read_to_end(&mut contents)?;
    if contents.len() > env_file::MAX_LEN {
        bail!("it is larger than {} bytes", env_file::MAX_LEN);
    }
    Ok(contents)
}

fn kind_label(kind: Kind) -> &'static str {
    if kind == Kind::Secret {
        "secret"
    } else {
        "var"
    }
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
