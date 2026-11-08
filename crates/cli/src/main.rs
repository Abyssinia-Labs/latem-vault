//! The `openvault` command (design §14).
//!
//! Everything for this device lives in one directory, `~/.openvault` unless `OPENVAULT_HOME`
//! names another: the key file (`keys`), the vault database (`vault.db`) and, while
//! `openvault service` runs, its socket (`service.sock`). Commands go through the service when
//! it runs, and open the vault themselves otherwise.

mod env_file;
mod join;

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use openvault_core::membership::AdminKey as _;
use openvault_core::record::MAX_VALUE_LEN;
use openvault_core::{Kind, Vault, names};
use openvault_crypto::RecoveryKey;
use openvault_keystore::{AdminKey, Backend, Keys};
use openvault_service::api::{DeviceSummary, ErrorCode, Item, Listed, Request, Response, Value};
use openvault_service::handler::{self, unexpected};
use openvault_service::{ADMIN_KEY, KEYS, SOCKET, VAULT, default_device_name};
use zeroize::Zeroizing;

/// This build: its version, and the commit it was built from (README, versions).
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("OPENVAULT_COMMIT"),
    ")"
);

#[derive(Parser)]
#[command(
    name = "openvault",
    version = VERSION,
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
        /// Where this device's keys live [default: the Secure Enclave when this Mac has one,
        /// otherwise a key file protected by a passphrase]
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
    /// Join a vault on another device: shows a code to type into `openvault approve` there.
    Join {
        /// This device's name in the vault [default: this computer's host name]
        #[arg(long)]
        name: Option<String>,
        /// Where this device's keys live [default: the Secure Enclave when this Mac has one,
        /// otherwise a key file protected by a passphrase]
        #[arg(long, value_enum)]
        keys: Option<KeysArg>,
    },
    /// Let a device on this network join this vault, after checking the code it shows. Asks for
    /// Touch ID when this Mac has an admin key, and for the recovery phrase otherwise.
    Approve {
        /// Let it write a collection; repeat for each
        #[arg(long, value_name = "COLLECTION")]
        write: Vec<String>,
        /// Let it read a collection; repeat for each
        #[arg(long, value_name = "COLLECTION")]
        read: Vec<String>,
        /// Let it store a collection without reading it; repeat for each
        #[arg(long, value_name = "COLLECTION")]
        hold: Vec<String>,
    },
    /// List this vault's devices, and which of them are on this network.
    Devices,
    /// Hold the vault open, find this vault's other devices on the local network, and answer
    /// other commands, so a passphrase is typed once. Runs until Ctrl-C.
    Service,
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
    /// Create a collection. Asks for Touch ID when this Mac has an admin key, and for the
    /// recovery phrase otherwise.
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
    /// A key file protected by a passphrase, asked for by every command
    Passphrase,
    /// A key file protected only by its permissions, for devices that open the vault with
    /// nobody there to type a passphrase
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
            init(
                &home,
                backend(keys),
                &name.unwrap_or_else(default_device_name),
            )?;
        }
        Command::Join { name, keys } => {
            join::join(
                &home,
                backend(keys),
                name.unwrap_or_else(default_device_name),
            )?;
        }
        Command::Approve { write, read, hold } => join::approve(&home, &write, &read, &hold)?,
        Command::Devices => devices(&home)?,
        Command::Service => service(&home)?,
        Command::Collections { action: None } => {
            for name in home.access()?.collections()? {
                println!("{name}");
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

fn backend(keys: Option<KeysArg>) -> Backend {
    match keys {
        Some(KeysArg::SecureEnclave) => Backend::SecureEnclave,
        Some(KeysArg::Passphrase) => Backend::Passphrase,
        Some(KeysArg::Software) => Backend::Software,
        None => Backend::best(),
    }
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
        self.0.join(KEYS)
    }

    fn vault(&self) -> PathBuf {
        self.0.join(VAULT)
    }

    fn admin(&self) -> PathBuf {
        self.0.join(ADMIN_KEY)
    }

    fn require_vault(&self) -> Result<()> {
        if !self.vault().exists() {
            bail!(
                "no vault in {}; run `openvault init` first",
                self.0.display()
            );
        }
        Ok(())
    }

    /// The running service if there is one, or the vault opened in this process.
    fn access(&self) -> Result<Access> {
        self.require_vault()?;
        #[cfg(unix)]
        {
            let socket = self.0.join(SOCKET);
            if openvault_service::client::is_running(&socket) {
                return Ok(Access::Service(socket));
            }
        }
        let keys = load_keys(&self.keys())?;
        Ok(Access::Local {
            vault: Box::new(Vault::open(&self.vault(), keys)?),
            admin_key: self.admin(),
        })
    }
}

/// Where requests go: to the running service, or to the vault in this process. Both run the
/// same handler (service.md, the CLI).
enum Access {
    #[cfg(unix)]
    Service(PathBuf),
    Local {
        vault: Box<Vault<Keys>>,
        admin_key: PathBuf,
    },
}

impl Access {
    fn call(&mut self, request: Request) -> Result<Response> {
        Ok(match self {
            #[cfg(unix)]
            Self::Service(socket) => openvault_service::client::call(socket, &request)
                .context("can't reach the service")?
                .context("the service stopped")?,
            Self::Local { vault, admin_key } => handler::handle(
                &mut handler::Context {
                    vault,
                    admin_key,
                    visible: None,
                },
                request,
            ),
        })
    }

    fn is_service(&self) -> bool {
        !matches!(self, Self::Local { .. })
    }

    fn collections(&mut self) -> Result<Vec<String>> {
        match self.call(Request::Collections)? {
            Response::Names(names) => Ok(names),
            other => Err(unexpected(&other)),
        }
    }

    /// Fails unless `collection` exists, before anything is typed or read for it.
    fn require_collection(&mut self, collection: &str) -> Result<()> {
        if !self.collections()?.iter().any(|name| name == collection) {
            bail!("no collection {collection}");
        }
        Ok(())
    }

    fn get(&mut self, collection: &str, name: &str) -> Result<Option<Value>> {
        match self.call(Request::Get {
            collection: collection.into(),
            name: name.into(),
        })? {
            Response::Entry(value) => Ok(value),
            other => Err(unexpected(&other)),
        }
    }

    fn set(&mut self, collection: &str, entries: Vec<Item>) -> Result<()> {
        match self.call(Request::Set {
            collection: collection.into(),
            entries,
        })? {
            Response::Done => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    fn delete(&mut self, collection: &str, name: &str) -> Result<bool> {
        match self.call(Request::Delete {
            collection: collection.into(),
            name: name.into(),
        })? {
            Response::Deleted(existed) => Ok(existed),
            other => Err(unexpected(&other)),
        }
    }

    fn list(&mut self, collection: &str) -> Result<Vec<Listed>> {
        match self.call(Request::List {
            collection: collection.into(),
        })? {
            Response::Listing(listed) => Ok(listed),
            other => Err(unexpected(&other)),
        }
    }

    fn folder(&mut self, collection: &str, folder: &str) -> Result<Vec<Item>> {
        match self.call(Request::Folder {
            collection: collection.into(),
            folder: folder.into(),
        })? {
            Response::Entries(items) => Ok(items),
            other => Err(unexpected(&other)),
        }
    }

    fn devices(&mut self) -> Result<Vec<DeviceSummary>> {
        match self.call(Request::Devices)? {
            Response::Devices(devices) => Ok(devices),
            other => Err(unexpected(&other)),
        }
    }
}

/// Loads this device's keys, asking for the passphrase if the key file is protected by one.
fn load_keys(path: &Path) -> Result<Keys> {
    const ATTEMPTS: usize = 3;
    match Keys::load(path) {
        Err(openvault_keystore::Error::NeedsPassphrase) => {}
        keys => return Ok(keys?),
    }
    if !has_terminal() {
        bail!(
            "this device's keys are protected by a passphrase, and there's no terminal to type \
             it in"
        );
    }
    for attempt in 1..=ATTEMPTS {
        let passphrase = prompt_passphrase("Passphrase for this device's keys (hidden): ")?;
        match Keys::load_with_passphrase(path, &passphrase) {
            Err(openvault_keystore::Error::WrongPassphrase) if attempt < ATTEMPTS => {
                eprintln!("Wrong passphrase.");
            }
            keys => return Ok(keys?),
        }
    }
    unreachable!("the last attempt returns")
}

/// Asks for a new passphrase twice, before any keys are made.
fn read_new_passphrase() -> Result<Zeroizing<String>> {
    if !has_terminal() {
        bail!(
            "there's no terminal to type a passphrase in; `--keys software` makes keys without one"
        );
    }
    let passphrase = prompt_passphrase("New passphrase for this device's keys (hidden): ")?;
    openvault_keystore::check_passphrase(&passphrase)?;
    let again = prompt_passphrase("The same passphrase again (hidden): ")?;
    if *again != *passphrase {
        bail!("the passphrases don't match");
    }
    Ok(passphrase)
}

/// Asks on the terminal itself rather than stdin, so commands that read stdin, such as
/// `import-env -`, still work.
fn prompt_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

/// Whether there's a terminal to ask for a passphrase on, which jobs and containers lack.
fn has_terminal() -> bool {
    #[cfg(unix)]
    return fs::File::open("/dev/tty").is_ok();
    #[cfg(not(unix))]
    return true;
}

fn init(home: &Home, backend: Backend, name: &str) -> Result<()> {
    if home.vault().exists() {
        bail!("there is already a vault in {}", home.0.display());
    }
    let passphrase = match backend {
        Backend::Passphrase => Some(read_new_passphrase()?),
        _ => None,
    };
    create_private_dir(&home.0)?;
    let keys = match &passphrase {
        Some(passphrase) => Keys::create_with_passphrase(&home.keys(), passphrase)?,
        None => Keys::create(&home.keys(), backend)?,
    };
    let remove_files = || {
        let _ = fs::remove_file(home.keys());
        let _ = fs::remove_file(home.admin());
    };
    // The device that creates the vault administers it (design §14). A Mac with a Secure
    // Enclave gets an admin key that asks for Touch ID; anywhere else, the recovery phrase is
    // the only admin key.
    let admin = match backend {
        Backend::SecureEnclave => {
            Some(AdminKey::create(&home.admin()).inspect_err(|_| remove_files())?)
        }
        Backend::Software | Backend::Passphrase => None,
    };
    let recovery = RecoveryKey::generate();
    let admin_key = admin.as_ref().map(|admin| admin.verifying_key());
    let vault = Vault::create(&home.vault(), keys, &recovery, name, admin_key)
        .inspect_err(|_| remove_files())?;

    let (keys, admin) = match backend {
        Backend::SecureEnclave => (
            "Secure Enclave".to_owned(),
            "Secure Enclave, asks for Touch ID or your password",
        ),
        Backend::Passphrase => (
            format!("protected by a passphrase, in {}", home.keys().display()),
            "your recovery phrase only",
        ),
        Backend::Software => (
            format!("software, in {}", home.keys().display()),
            "your recovery phrase only",
        ),
    };
    println!("Created a vault in {}.", home.0.display());
    println!();
    println!("  Vault   {}", vault.vault_id());
    println!("  Device  {name}, {}", vault.device_id());
    println!("  Keys    {keys}");
    println!("  Admin   {admin}");
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
    if backend != Backend::SecureEnclave {
        println!("This device has no admin key, so creating a collection asks for them too.");
    }
    if backend == Backend::Passphrase {
        println!("If you forget this device's passphrase, treat the device as lost.");
    }
    Ok(())
}

/// Creates a collection. Its set_scope entry needs an admin signature: this device's admin key
/// when it has one, which asks for Touch ID, otherwise the recovery key. A vault from before the
/// membership log starts its log first, with the recovery phrase.
fn create_collection(home: &Home, name: &str) -> Result<()> {
    names::check_collection(name)?;
    let mut access = home.access()?;
    // Checked before asking for Touch ID or 24 words.
    if access
        .collections()?
        .iter()
        .any(|existing| existing == name)
    {
        bail!("collection {name} already exists");
    }
    if home.admin().exists() {
        eprintln!("Confirm with Touch ID or your password to create the collection {name}.");
    }
    let mut response = access.call(Request::CreateCollection {
        name: name.into(),
        recovery_phrase: None,
    })?;
    if let Response::Error {
        code: ErrorCode::RecoveryPhraseNeeded,
        ..
    } = response
    {
        if io::stdin().is_terminal() {
            eprintln!("Creating a collection needs an admin signature. This device has no admin");
            eprintln!("key, so it comes from your recovery phrase.");
        }
        response = access.call(Request::CreateCollection {
            name: name.into(),
            recovery_phrase: Some(read_recovery_phrase()?),
        })?;
    }
    match response {
        Response::Done => Ok(()),
        other => Err(unexpected(&other)),
    }
}

/// Reads a recovery phrase: typed at a hidden prompt, or the first line of stdin.
fn read_recovery_phrase() -> Result<Zeroizing<String>> {
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
    Ok(phrase)
}

/// Lists the log's devices. Only the service knows which are on this network.
fn devices(home: &Home) -> Result<()> {
    let mut access = home.access()?;
    let devices = access.devices()?;
    if devices.is_empty() {
        println!("This vault has no membership log yet. Creating a collection starts it.");
        return Ok(());
    }
    let rows: Vec<(String, String, &str, String)> = devices
        .iter()
        .map(|device| {
            let (platform, name) = device
                .name
                .clone()
                .unwrap_or_else(|| ("?".into(), device.id.to_string()));
            let keys = if device.hardware { "hardware" } else { "file" };
            let mut notes = Vec::new();
            if device.this {
                notes.push("this device");
            }
            if device.revoked {
                notes.push("revoked");
            } else if device.visible {
                notes.push("visible");
            }
            (name, platform, keys, notes.join(", "))
        })
        .collect();
    let width = rows
        .iter()
        .map(|row| row.0.chars().count())
        .max()
        .unwrap_or(0);
    for (name, platform, keys, notes) in &rows {
        let line = format!("{name:<width$}  {platform:<8}  {keys:<8}  {notes}");
        println!("{}", line.trim_end());
    }
    if !access.is_service() {
        println!();
        println!("Run `openvault service` to see which of them are on this network.");
    }
    Ok(())
}

/// Runs the service in the foreground until Ctrl-C (service.md).
#[cfg(unix)]
fn service(home: &Home) -> Result<()> {
    use tracing_subscriber::EnvFilter;

    home.require_vault()?;
    let keys = load_keys(&home.keys())?;
    let filter = EnvFilter::try_from_env("OPENVAULT_LOG").unwrap_or_else(|_| {
        EnvFilter::new("info,iroh=warn,iroh_mdns_address_lookup=warn,swarm_discovery=warn")
    });
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(filter)
        .with_target(false)
        .init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(openvault_service::run(&home.0, keys, VERSION))
}

#[cfg(not(unix))]
fn service(_: &Home) -> Result<()> {
    bail!("`openvault service` doesn't run on Windows yet")
}

fn set(home: &Home, entry: &str, kind: Kind) -> Result<()> {
    let (collection, name) = split_entry(entry)?;
    let mut access = home.access()?;
    access.require_collection(collection)?;
    let value = read_value(kind)?;
    access.set(
        collection,
        vec![Item {
            name: name.into(),
            kind,
            value,
        }],
    )
}

fn get(home: &Home, entry: &str) -> Result<()> {
    let (collection, name) = split_entry(entry)?;
    let entry = home
        .access()?
        .get(collection, name)?
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
    let listed = home.access()?.list(collection)?;
    let prefix = folder.map(|folder| format!("{folder}/"));
    for info in listed {
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
    if !home.access()?.delete(collection, name)? {
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
    let entries = home.access()?.folder(collection, folder)?;
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

    let mut access = home.access()?;
    let existing: HashMap<String, Kind> = access
        .list(collection)?
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
            && access
                .get(collection, name)?
                .is_some_and(|entry| entry.value.as_slice() == *value)
        {
            unchanged += 1;
        } else {
            writes.push(Item {
                name: name.clone(),
                kind: *kind,
                value: Zeroizing::new(value.to_vec()),
            });
        }
    }
    let written: Vec<(String, Kind)> = writes
        .iter()
        .map(|item| (item.name.clone(), item.kind))
        .collect();
    access.set(collection, writes)?;

    for (name, kind) in &written {
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
        count(written.len())
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
