//! The `openvault` command (design §14).
//!
//! Everything for this device lives in one directory, `~/.openvault` unless `OPENVAULT_HOME`
//! names another: the key file (`keys`), the vault database (`vault.db`) and, while
//! `openvault service` runs, its socket (`service.sock`). Commands go through the service when
//! it runs, and open the vault themselves otherwise.

mod files;
#[cfg(feature = "coordinator")]
mod grandfather;
mod join;
mod keys;
mod log;
#[cfg(unix)]
mod login;

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use openvault_core::file::Manifest;
use openvault_core::membership::Scope;
use openvault_core::names::is_env_name;
use openvault_core::record::MAX_VALUE_LEN;
use openvault_core::{Kind, Placement, Vault, env_file, names};
use openvault_keystore::{Backend, Keys};
use openvault_service::api::{DeviceSummary, ErrorCode, Item, Listed, Request, Response, Value};
use openvault_service::files::size_label;
use openvault_service::handler::{self, unexpected};
use openvault_service::{ADMIN_KEY, KEYS, SOCKET, VAULT, default_device_name, setup};
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
    /// Print the value of a secret or variable, or write out a file.
    Get {
        /// `<collection>/<name>`
        entry: String,
        /// Write it to this path instead of stdout, readable only by you
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Open a copy of a file in its app. Each save becomes a new version; Enter here ends it and
    /// deletes the copy.
    Open {
        /// `<collection>/<name>`
        entry: String,
    },
    /// List the names in a collection, or in one folder of it, with files' sizes. Values aren't
    /// shown.
    List {
        /// `<collection>` or `<collection>/<folder>`
        path: String,
    },
    /// Delete a secret, variable or file.
    Delete {
        /// `<collection>/<name>`
        entry: String,
    },
    /// Run a command with a folder's secrets and variables as environment variables. Its files
    /// are written to a private temporary folder while the command runs, each path in a variable
    /// named after the file: `prod/upload.jks` sets `UPLOAD_JKS`.
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
    Devices {
        #[command(subcommand)]
        action: Option<DevicesAction>,
    },
    /// Change what a device may do with a collection. Taking away read or write gives the
    /// collection a new key. Asks for Touch ID when this Mac has an admin key, and for the
    /// recovery phrase otherwise.
    Scope {
        /// The device's name, or the start of its id
        device: String,
        collection: String,
        #[arg(value_enum)]
        scope: ScopeArg,
    },
    /// Hold the vault open, find this vault's other devices on the local network, and answer
    /// other commands, so a passphrase is typed once. Runs until Ctrl-C, or have the system start
    /// it at login with `install`.
    #[command(args_conflicts_with_subcommands = true)]
    Service {
        #[command(subcommand)]
        action: Option<ServiceAction>,
        /// Append the log to FILE instead of writing it to stderr. A leading `~/` is the home
        /// directory, for a LaunchAgent that can't name it.
        #[arg(long, value_name = "FILE")]
        log: Option<PathBuf>,
    },
    /// Say how this device's keys are kept: in the Secure Enclave, or in a key file with or
    /// without a passphrase.
    Keys {
        #[command(subcommand)]
        action: Option<KeysAction>,
    },
    /// Show the grandfather this device uses to reach the vault's other devices away from home,
    /// or set it.
    #[cfg(feature = "coordinator")]
    Coordinator {
        #[command(subcommand)]
        action: Option<CoordinatorAction>,
    },
    /// Run this vault's relay and coordinator on its always-on machine, so its devices reach each
    /// other away from home. Prints the address to give them with `openvault coordinator set`.
    /// Runs until Ctrl-C.
    #[cfg(feature = "coordinator")]
    Grandfather(grandfather::Args),
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
    /// Import a file, or a folder's files, as file entries. A file already there with the same
    /// contents is left as it is. The originals are left in place.
    Import {
        /// A file or a folder
        path: PathBuf,
        #[arg(long)]
        collection: String,
        /// The folder to import into [default: a folder's own name; a file goes at the top]
        #[arg(long, value_name = "FOLDER")]
        into: Option<String>,
        /// Import even though this device's disk isn't encrypted (FileVault, or dm-crypt on
        /// Linux), so what's read may stay on it in the clear
        #[arg(long)]
        disk_not_encrypted: bool,
    },
    /// Show or set which of a collection's file chunks this device keeps.
    Placement {
        collection: String,
        #[arg(value_enum)]
        placement: Option<PlacementArg>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum PlacementArg {
    /// Every current file's chunks
    Keep,
    /// Chunks of files read lately, up to 2 GiB
    OnDemand,
}

#[derive(Subcommand)]
enum CollectionsAction {
    /// Create a collection. Asks for Touch ID when this Mac has an admin key, and for the
    /// recovery phrase otherwise.
    Create { name: String },
}

#[derive(Clone, Copy, ValueEnum)]
enum ScopeArg {
    /// No access
    None,
    /// Store and serve the collection without reading it
    Hold,
    Read,
    Write,
}

#[derive(Subcommand)]
enum DevicesAction {
    /// Remove a device from the vault: it stops syncing, and each collection it can read gets a
    /// new key. Shows what it can read and wrote last first. Asks for Touch ID when this Mac has
    /// an admin key, and for the recovery phrase otherwise.
    Revoke {
        /// The device's name, or the start of its id
        device: String,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Have the system start the service at login, and again if it stops: a LaunchAgent on
    /// macOS, a systemd user unit on Linux. Run it again after installing a new build.
    Install,
    /// Stop the service and remove what `install` wrote. The vault is untouched.
    Uninstall,
    /// Whether the service is installed and running, and which build it runs.
    Status,
}

#[cfg(feature = "coordinator")]
#[derive(Subcommand)]
enum CoordinatorAction {
    /// Use the grandfather at this address, as `openvault grandfather` prints it: its relay, and
    /// its coordinator
    Set { address: String },
    /// Stop using a grandfather: find other devices on the local network only
    Unset,
}

#[derive(Subcommand)]
enum KeysAction {
    /// Give the key file a passphrase, or change the one it has. The keys stay the same, so the
    /// device does too.
    Passphrase {
        /// Take the passphrase away, so the keys open with nobody there to type it
        #[arg(long)]
        remove: bool,
    },
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
        Command::Devices { action: None } => devices(&home)?,
        Command::Devices {
            action: Some(DevicesAction::Revoke { device }),
        } => revoke(&home, &device)?,
        Command::Scope {
            device,
            collection,
            scope,
        } => set_scope(
            &home,
            &device,
            &collection,
            match scope {
                ScopeArg::None => Scope::None,
                ScopeArg::Hold => Scope::Hold,
                ScopeArg::Read => Scope::Read,
                ScopeArg::Write => Scope::Write,
            },
        )?,
        Command::Service { action: None, log } => service(&home, log.as_deref())?,
        Command::Service {
            action: Some(action),
            ..
        } => service_action(&home, action)?,
        #[cfg(feature = "coordinator")]
        Command::Coordinator { action: None } => grandfather::show(&home)?,
        #[cfg(feature = "coordinator")]
        Command::Coordinator {
            action: Some(CoordinatorAction::Set { address }),
        } => grandfather::set(&home, &address)?,
        #[cfg(feature = "coordinator")]
        Command::Coordinator {
            action: Some(CoordinatorAction::Unset),
        } => grandfather::unset(&home)?,
        #[cfg(feature = "coordinator")]
        Command::Grandfather(args) => grandfather::run(&home, args)?,
        Command::Keys { action: None } => keys::show(&home)?,
        Command::Keys {
            action: Some(KeysAction::Passphrase { remove: false }),
        } => keys::set_passphrase(&home)?,
        Command::Keys {
            action: Some(KeysAction::Passphrase { remove: true }),
        } => keys::remove_passphrase(&home)?,
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
        Command::Get { entry, output } => get(&home, &entry, output.as_deref())?,
        Command::Open { entry } => open(&home, &entry)?,
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
        Command::Import {
            path,
            collection,
            into,
            disk_not_encrypted,
        } => files::import(
            &home,
            &path,
            &collection,
            into.as_deref(),
            disk_not_encrypted,
        )?,
        Command::Placement {
            collection,
            placement,
        } => files::placement(
            &home,
            &collection,
            placement.map(|placement| match placement {
                PlacementArg::Keep => Placement::Keep,
                PlacementArg::OnDemand => Placement::OnDemand,
            }),
        )?,
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
    let setup::Created {
        vault, recovery, ..
    } = setup::create(
        &home.0,
        backend,
        passphrase.as_deref().map(String::as_str),
        name,
    )?;

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
    let rows: Vec<(String, String, &str, String, String)> = devices
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
            let id = device.id.to_string()[..8].to_owned();
            (name, platform, keys, id, notes.join(", "))
        })
        .collect();
    let width = rows
        .iter()
        .map(|row| row.0.chars().count())
        .max()
        .unwrap_or(0);
    for (name, platform, keys, id, notes) in &rows {
        let line = format!("{name:<width$}  {platform:<8}  {keys:<8}  {id}  {notes}");
        println!("{}", line.trim_end());
    }
    if !access.is_service() {
        println!();
        println!("Run `openvault service` to see which of them are on this network.");
    }
    Ok(())
}

/// Revokes a device, after showing what it can read and what it wrote last (sync.md,
/// reviewing), and then lists the secrets to change at their providers.
fn revoke(home: &Home, query: &str) -> Result<()> {
    let mut access = home.access()?;
    let devices = access.devices()?;
    let device = find_device(&devices, query)?;
    let (platform, name) = device
        .name
        .clone()
        .unwrap_or_else(|| ("?".into(), device.id.to_string()));
    if device.this {
        bail!("{name} is this device; revoke it from another one");
    }
    if device.revoked {
        bail!("{name} is already revoked");
    }
    let review = match access.call(Request::Review { device: device.id })? {
        Response::Review(review) => review,
        other => return Err(unexpected(&other)),
    };

    let id = device.id.to_string();
    println!("Device    {name} ({platform})");
    println!("Id        {}…", &id[..8]);
    let reads: Vec<String> = review
        .secrets
        .iter()
        .map(|(collection, secrets)| match secrets.len() {
            1 => format!("{collection} (1 secret)"),
            n => format!("{collection} ({n} secrets)"),
        })
        .collect();
    if reads.is_empty() {
        println!("Reads     nothing");
    } else {
        println!("Reads     {}", reads.join(", "));
    }
    let written: Vec<String> = review
        .wrote_last
        .iter()
        .flat_map(|(collection, entries)| {
            entries.iter().map(move |entry| {
                let deleted = if entry.deleted { " (deleted)" } else { "" };
                format!("{collection}/{}{deleted}", entry.name)
            })
        })
        .collect();
    match written.split_first() {
        None => println!("Wrote     nothing that is current"),
        Some((first, rest)) => {
            println!("Wrote     {first}");
            for entry in rest {
                println!("          {entry}");
            }
        }
    }
    println!();
    println!("It will stop syncing with this vault, and each collection it reads gets a new key.");
    if !join::confirm(&format!("Revoke {name}? [y/N] "))? {
        bail!("not revoked");
    }

    if home.admin().exists() {
        eprintln!("Confirm with Touch ID or your password to remove {name} from your vault.");
    }
    let mut response = access.call(Request::Revoke {
        device: device.id,
        recovery_phrase: None,
    })?;
    if let Response::Error {
        code: ErrorCode::RecoveryPhraseNeeded,
        ..
    } = response
    {
        if io::stdin().is_terminal() {
            eprintln!("Revoking a device needs an admin signature. This device has no admin key,");
            eprintln!("so it comes from your recovery phrase.");
        }
        response = access.call(Request::Revoke {
            device: device.id,
            recovery_phrase: Some(read_recovery_phrase()?),
        })?;
    }
    let Response::Revoked { rotated, carried } = response else {
        return Err(unexpected(&response));
    };
    println!("Revoked {name}.");
    if !rotated.is_empty() {
        println!(
            "New keys for {}: what is written from now on is sealed with keys it doesn't have.",
            rotated.join(", ")
        );
    }
    if carried > 0 {
        println!(
            "Its last changes to {carried} entries were written again with the new keys, so they're kept."
        );
    }
    let secrets: Vec<String> = review
        .secrets
        .iter()
        .flat_map(|(collection, names)| {
            names.iter().map(move |name| format!("{collection}/{name}"))
        })
        .collect();
    if !secrets.is_empty() {
        println!();
        println!("It could read these secrets. Change them where they were issued:");
        for secret in secrets {
            println!("  {secret}");
        }
    }
    Ok(())
}

/// Changes a device's scope on a collection (sync.md, revoking and reducing scopes).
fn set_scope(home: &Home, query: &str, collection: &str, scope: Scope) -> Result<()> {
    let mut access = home.access()?;
    let devices = access.devices()?;
    let device = find_device(&devices, query)?;
    let name = device
        .name
        .as_ref()
        .map_or_else(|| device.id.to_string(), |(_, name)| name.clone());
    if device.this {
        bail!("{name} is this device; change its scope from another one");
    }
    if device.revoked {
        bail!("{name} is revoked");
    }
    access.require_collection(collection)?;
    let label = join::scope_label(scope);
    if home.admin().exists() {
        eprintln!("Confirm with Touch ID or your password to give {name} {label} on {collection}.");
    }
    let request = |recovery_phrase| Request::SetScope {
        device: device.id,
        collection: collection.into(),
        scope,
        recovery_phrase,
    };
    let mut response = access.call(request(None))?;
    if let Response::Error {
        code: ErrorCode::RecoveryPhraseNeeded,
        ..
    } = response
    {
        if io::stdin().is_terminal() {
            eprintln!("Changing a scope needs an admin signature. This device has no admin key,");
            eprintln!("so it comes from your recovery phrase.");
        }
        response = access.call(request(Some(read_recovery_phrase()?)))?;
    }
    let Response::ScopeSet {
        rotated,
        granted,
        carried,
    } = response
    else {
        return Err(unexpected(&response));
    };
    if scope == Scope::None {
        println!("{name} no longer has a scope on {collection}.");
    } else {
        println!("{name} now has {label} on {collection}.");
    }
    if granted > 0 {
        println!("{collection}'s keys reach {name} the next time the two sync.");
    }
    if rotated {
        if scope >= Scope::Read {
            println!(
                "{collection} has a new key, so what {name} signs with the old one no longer counts."
            );
        } else {
            println!("{collection} has a new key, so nothing written from now on reaches {name}.");
        }
    }
    if carried > 0 {
        println!(
            "Its last changes to {carried} entries were written again with the new key, so they're kept."
        );
    }
    Ok(())
}

/// The device `query` names: by its name, or by the start of its id.
fn find_device<'a>(devices: &'a [DeviceSummary], query: &str) -> Result<&'a DeviceSummary> {
    let named: Vec<&DeviceSummary> = devices
        .iter()
        .filter(|device| device.name.as_ref().is_some_and(|(_, name)| name == query))
        .collect();
    let found = if named.is_empty() && query.len() >= 4 {
        let prefix = query.to_ascii_lowercase();
        devices
            .iter()
            .filter(|device| device.id.to_string().starts_with(&prefix))
            .collect()
    } else {
        named
    };
    match found.as_slice() {
        [device] => Ok(device),
        [] => bail!("no device is called {query}; `openvault devices` lists them"),
        several => {
            let ids: Vec<String> = several
                .iter()
                .map(|device| device.id.to_string()[..8].to_owned())
                .collect();
            bail!(
                "{} devices are called {query}; give the start of its id instead: {}",
                several.len(),
                ids.join(", ")
            )
        }
    }
}

/// Runs the service in the foreground until Ctrl-C (service.md).
#[cfg(unix)]
fn service(home: &Home, log: Option<&Path>) -> Result<()> {
    if let Some(file) = log {
        log_to(file)?;
    }
    home.require_vault()?;
    let keys = load_keys(&home.keys())?;
    log::to_stderr(
        "info,iroh=warn,iroh_relay=warn,iroh_mdns_address_lookup=warn,swarm_discovery=warn",
    );
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(openvault_service::run(&home.0, keys, VERSION))
}

/// Points stdout and stderr at the end of `file`, so whatever the service prints goes there,
/// errors before its log starts included (service.md, running it).
#[cfg(unix)]
fn log_to(file: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;

    let file = match file.strip_prefix("~") {
        Ok(rest) if file.starts_with("~/") => std::env::home_dir()
            .context("can't find your home directory for --log")?
            .join(rest),
        _ => file.to_owned(),
    };
    let opened = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)
        .with_context(|| format!("can't open {} for the log", file.display()))?;
    for fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: both descriptors are open; dup2 replaces the second with a copy of the first.
        if unsafe { libc::dup2(opened.as_raw_fd(), fd) } == -1 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("can't log to {}", file.display()));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn service(_: &Home, _: Option<&Path>) -> Result<()> {
    bail!("`openvault service` doesn't run on Windows yet")
}

/// Starting the service at login (service.md, starting at login).
#[cfg(unix)]
fn service_action(home: &Home, action: ServiceAction) -> Result<()> {
    match action {
        ServiceAction::Install => login::install(home),
        ServiceAction::Uninstall => login::uninstall(),
        ServiceAction::Status => login::status(home),
    }
}

#[cfg(not(unix))]
fn service_action(_: &Home, _: ServiceAction) -> Result<()> {
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

fn open(home: &Home, entry: &str) -> Result<()> {
    let (collection, name) = split_entry(entry)?;
    let mut access = home.access()?;
    let entry = access
        .get(collection, name)?
        .ok_or_else(|| anyhow!("{collection}/{name} doesn't exist"))?;
    if entry.kind != Kind::File {
        bail!(
            "{collection}/{name} is a {}; open opens files. `openvault get` shows it",
            kind_label(entry.kind)
        );
    }
    let manifest = Manifest::decode(&entry.value)?;
    #[cfg(unix)]
    return files::open(&mut access, collection, name, &manifest);
    #[cfg(not(unix))]
    bail!("open needs macOS or Linux")
}

fn get(home: &Home, entry: &str, output: Option<&Path>) -> Result<()> {
    let (collection, name) = split_entry(entry)?;
    let mut access = home.access()?;
    let entry = access
        .get(collection, name)?
        .ok_or_else(|| anyhow!("{collection}/{name} doesn't exist"))?;
    if entry.kind == Kind::File {
        let manifest = Manifest::decode(&entry.value)?;
        return files::get(&mut access, collection, name, &manifest, output);
    }
    if let Some(path) = output {
        return openvault_service::files::write_out(path, false, now_secs(), |file| {
            Ok(file.write_all(&entry.value)?)
        });
    }
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
            if info.kind == Kind::File {
                let here = match info.missing {
                    0 => String::new(),
                    1 => ", 1 chunk not here".into(),
                    n => format!(", {n} chunks not here"),
                };
                println!("file    {}  {}{here}", info.name, size_label(info.size));
            } else {
                println!("{:<6}  {}", kind_label(info.kind), info.name);
            }
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
    let mut access = home.access()?;
    let (files, entries): (Vec<Item>, Vec<Item>) = access
        .folder(collection, folder)?
        .into_iter()
        .partition(|item| item.kind == Kind::File);
    if entries.is_empty() && files.is_empty() {
        bail!("{collection}/{folder}/ has no secrets, variables or files");
    }

    let (program, args) = command.split_first().expect("clap requires a command");
    let mut child = process::Command::new(program);
    child.args(args);
    let mut taken = HashSet::new();
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
        taken.insert(var.to_owned());
    }
    if files.is_empty() {
        return exec(child, program);
    }
    #[cfg(unix)]
    return files::run_with_files(
        &mut access,
        collection,
        folder,
        prefix,
        &files,
        &taken,
        child,
    );
    #[cfg(not(unix))]
    bail!("`run` with files needs a Unix system for now")
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
    match kind {
        Kind::Secret => "secret",
        Kind::File => "file",
        Kind::Var | Kind::Collection => "var",
    }
}

/// Seconds since 1970, for a value written out with `get -o`.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(0))
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
