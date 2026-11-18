//! Files (files.md, commands): `import`, `get` for a file, `open`, `run` with a folder's files,
//! and `placement`. This process reads and writes the user's files itself; only chunks cross to
//! the service, one to a message.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use latem_vault_core::file::{Content, Manifest};
use latem_vault_core::membership::Scope;
use latem_vault_core::names::{self, is_env_name};
use latem_vault_core::{Kind, Placement};
use latem_vault_service::api::{Item, Request, Response};
use latem_vault_service::files::{
    Caller, disk_encryption, seal_file, size_label, write_contents, write_file, write_out,
};
use latem_vault_service::handler::unexpected;

use crate::{Access, Home};

/// Files' manifests go to the service in batches of at most this many bytes.
const BATCH_BYTES: usize = 4 << 20;
/// How long `open`'s copy stays unchanged after a save before it becomes a new version, so an
/// app that writes a file in several steps saves one version (files.md, open).
const SETTLE: Duration = Duration::from_secs(2);
/// How often `open` looks at its copy for a save: one `stat` each time, nothing more.
const LOOK: Duration = Duration::from_millis(500);

impl Caller for Access {
    fn call(&mut self, request: Request) -> Result<Response> {
        Access::call(self, request)
    }
}

impl Access {
    /// Gets the chunks of the file `collection`/`name` that aren't on this device from the
    /// devices that share its collection (files.md, asking). Only the service can, since it
    /// holds the endpoint; without it this fails if any are missing.
    fn fetch(&mut self, collection: &str, name: &str) -> Result<()> {
        let missing = match self.call(Request::Fetch {
            collection: collection.into(),
            name: name.into(),
        })? {
            Response::Fetched { missing } => missing,
            other => return Err(unexpected(&other)),
        };
        if missing == 0 {
            return Ok(());
        }
        let chunks = if missing == 1 { "chunk" } else { "chunks" };
        if self.is_service() {
            bail!(
                "{missing} {chunks} of {collection}/{name} aren't on this device, and none of \
                 your devices that could be reached had them"
            );
        }
        bail!(
            "{missing} {chunks} of {collection}/{name} aren't on this device; start the service \
             (`latem-vault service`) to fetch them from your other devices"
        )
    }

    /// Whether this device may write to `collection`. A vault from before the membership log
    /// lists nobody's scopes, and its one device writes.
    fn can_write(&mut self, collection: &str) -> Result<bool> {
        let device = match self.call(Request::Vault)? {
            Response::Vault(info) => info.device,
            other => return Err(unexpected(&other)),
        };
        let summaries = match self.call(Request::CollectionSummaries)? {
            Response::CollectionSummaries(summaries) => summaries,
            other => return Err(unexpected(&other)),
        };
        let summary = summaries
            .iter()
            .find(|summary| summary.name == collection)
            .ok_or_else(|| anyhow!("no collection {collection}"))?;
        Ok(summary.devices.is_empty()
            || summary
                .devices
                .iter()
                .any(|&(id, scope)| id == device && scope == Scope::Write))
    }

    fn placement(&mut self, collection: &str, set: Option<Placement>) -> Result<Placement> {
        match self.call(Request::Placement {
            collection: collection.into(),
            set,
        })? {
            Response::Placement(placement) => Ok(placement),
            other => Err(unexpected(&other)),
        }
    }
}

/// A file to import, and the entry it becomes.
struct Source {
    path: PathBuf,
    name: String,
}

/// Something in a folder that isn't imported, and why.
type Skipped = (PathBuf, String);

pub fn import(
    home: &Home,
    path: &Path,
    collection: &str,
    into: Option<&str>,
    disk_not_encrypted: bool,
) -> Result<()> {
    names::check_collection(collection)?;
    let into = into.map(|folder| folder.trim_end_matches('/'));
    if let Some(folder) = into {
        names::check_entry(folder)?;
    }
    match disk_encryption() {
        Ok(()) => {}
        Err(why) if disk_not_encrypted => {
            eprintln!("Importing anyway: {why}. What this reads may stay on the disk in the");
            eprintln!("clear, even after the originals are deleted.");
        }
        Err(why) => bail!(
            "{why}, so what this reads could stay on the disk in the clear after the originals \
             are deleted. Turn disk encryption on, or pass --disk-not-encrypted to import anyway"
        ),
    }

    let (sources, skipped) = sources(path, into)?;
    if sources.is_empty() {
        bail!("{} has no files to import", path.display());
    }
    let mut access = home.access()?;
    access.require_collection(collection)?;
    let existing: HashMap<String, Kind> = access
        .list(collection)?
        .into_iter()
        .map(|info| (info.name, info.kind))
        .collect();
    for source in &sources {
        if let Some(kind) = existing.get(&source.name)
            && *kind != Kind::File
        {
            bail!(
                "{collection}/{} is a {}; a file can't take its name",
                source.name,
                crate::kind_label(*kind)
            );
        }
    }

    let (mut written, mut unchanged, mut bytes) = (0, 0, 0u64);
    let mut batch: Vec<Item> = Vec::new();
    let mut batch_bytes = 0;
    for source in &sources {
        let manifest = seal_file(&mut access, collection, &source.path)
            .with_context(|| format!("can't import {}", source.path.display()))?;
        let value = manifest.encode();
        if existing.contains_key(&source.name)
            && access
                .get(collection, &source.name)?
                .is_some_and(|current| current.kind == Kind::File && current.value == value)
        {
            unchanged += 1;
            continue;
        }
        println!("file    {}  {}", source.name, size_label(manifest.size));
        written += 1;
        bytes += manifest.size;
        batch_bytes += value.len();
        batch.push(Item {
            name: source.name.clone(),
            kind: Kind::File,
            value,
        });
        if batch_bytes >= BATCH_BYTES {
            access.set(collection, std::mem::take(&mut batch))?;
            batch_bytes = 0;
        }
    }
    if !batch.is_empty() {
        access.set(collection, batch)?;
    }

    let files = |n: usize| {
        if n == 1 {
            "1 file".to_owned()
        } else {
            format!("{n} files")
        }
    };
    let place = match into {
        Some(folder) => format!("{collection}/{folder}/"),
        None => collection.to_owned(),
    };
    print!(
        "Imported {} ({}) into {place}",
        files(written),
        size_label(bytes)
    );
    match unchanged {
        0 => println!("."),
        n => println!("; {} already had the same contents.", files(n)),
    }
    for (path, why) in &skipped {
        println!("Skipped {}: {why}", path.display());
    }
    if written > 0 {
        println!(
            "The originals are still in {}. Delete them once `latem-vault list {collection}` \
             shows what you expect.",
            path.display()
        );
    }
    Ok(())
}

/// The files under `path` and the entry each becomes, and what was skipped and why. A folder's
/// files keep their paths within it, under `into` or else the folder's own name; a single file
/// goes under `into`, or at the top of the collection.
fn sources(path: &Path, into: Option<&str>) -> Result<(Vec<Source>, Vec<Skipped>)> {
    let metadata = fs::metadata(path).with_context(|| format!("can't read {}", path.display()))?;
    let own_name = |path: &Path| -> Result<String> {
        let canonical = fs::canonicalize(path)?;
        canonical
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("{} has no name to import it under", path.display()))
    };
    let join = |folder: Option<&str>, name: &str| match folder {
        Some(folder) => format!("{folder}/{name}"),
        None => name.to_owned(),
    };
    if metadata.is_file() {
        let name = join(into, &own_name(path)?);
        names::check_entry(&name)?;
        return Ok((
            vec![Source {
                path: path.to_owned(),
                name,
            }],
            Vec::new(),
        ));
    }
    if !metadata.is_dir() {
        bail!("{} isn't a file or a folder", path.display());
    }
    let folder = match into {
        Some(folder) => folder.to_owned(),
        None => own_name(path)?,
    };
    let (mut sources, mut skipped) = (Vec::new(), Vec::new());
    let mut pending = vec![(path.to_owned(), folder)];
    while let Some((dir, prefix)) = pending.pop() {
        let mut children: Vec<fs::DirEntry> = fs::read_dir(&dir)
            .with_context(|| format!("can't read {}", dir.display()))?
            .collect::<io::Result<_>>()?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            let child_path = child.path();
            let file_name = child.file_name();
            let Some(file_name) = file_name.to_str() else {
                skipped.push((child_path, "its name isn't UTF-8".into()));
                continue;
            };
            if file_name == ".DS_Store" || file_name.starts_with("._") {
                skipped.push((child_path, "it's Finder's, not yours".into()));
                continue;
            }
            let kind = child.file_type()?;
            let name = format!("{prefix}/{file_name}");
            if kind.is_symlink() {
                skipped.push((child_path, "it's a symbolic link".into()));
            } else if kind.is_dir() {
                pending.push((child_path, name));
            } else if !kind.is_file() {
                skipped.push((child_path, "it isn't a regular file".into()));
            } else if let Err(e) = names::check_entry(&name) {
                skipped.push((child_path, e.to_string()));
            } else {
                sources.push(Source {
                    path: child_path,
                    name,
                });
            }
        }
    }
    sources.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((sources, skipped))
}

/// Reads a file in 1 MiB pieces, has the service seal each, and returns its manifest. A file of
/// at most 64 KiB is kept in the manifest instead.
/// Writes a file entry to stdout, or to `output` with mode 0600 (0700 if it's executable) and
/// its modification time.
pub fn get(
    access: &mut Access,
    collection: &str,
    name: &str,
    manifest: &Manifest,
    output: Option<&Path>,
) -> Result<()> {
    let context = || format!("can't read {collection}/{name}");
    if matches!(manifest.content, Content::Chunks { .. }) {
        access.fetch(collection, name)?;
    }
    match output {
        None => write_contents(access, collection, manifest, &mut io::stdout().lock())
            .with_context(context),
        Some(path) => write_out(path, manifest.executable, manifest.mtime, |file| {
            write_contents(access, collection, manifest, file).with_context(context)
        }),
    }
}

/// `run` with files: each of the folder's files is written to a private directory for the
/// command's lifetime, and its path set in a variable named after the last part of its name.
#[cfg(unix)]
pub fn run_with_files(
    access: &mut Access,
    collection: &str,
    folder: &str,
    prefix: &str,
    files: &[Item],
    taken: &HashSet<String>,
    mut child: process::Command,
) -> Result<ExitCode> {
    let dir = PrivateDir::create("run")?;
    let mut set: HashMap<String, &str> = HashMap::new();
    for item in files {
        let value = access
            .get(collection, &item.name)?
            .filter(|value| value.kind == Kind::File)
            .ok_or_else(|| anyhow!("{collection}/{} changed while run read it", item.name))?;
        let manifest = Manifest::decode(&value.value)?;
        let within = &item.name[folder.len() + 1..];
        let last = within.rsplit('/').next().expect("split gives one part");
        let var = file_var(last);
        if !is_env_name(&var) {
            bail!(
                "{collection}/{} would set {var}, which can't be an environment variable: it \
                 starts with a digit",
                item.name
            );
        }
        if taken.contains(&var) {
            bail!(
                "{collection}/{} and a secret or variable would both set {var}",
                item.name
            );
        }
        if let Some(other) = set.insert(var.clone(), &item.name) {
            bail!(
                "{collection}/{other} and {collection}/{} would both set {var}",
                item.name
            );
        }
        if matches!(manifest.content, Content::Chunks { .. }) {
            access.fetch(collection, &item.name)?;
        }
        let path = dir.0.join(within);
        if let Some(parent) = path.parent() {
            private_dirs(parent)?;
        }
        write_out(&path, manifest.executable, manifest.mtime, |file| {
            write_contents(access, collection, &manifest, file)
                .with_context(|| format!("can't read {collection}/{}", item.name))
        })?;
        child.env(format!("{prefix}{var}"), &path);
    }
    let status = wait(child)?;
    drop(dir);
    Ok(status)
}

/// `open` (files.md, open): a copy of the file in a private directory, under its own name, opened
/// in its app. Each save becomes a new version once the copy has been unchanged for [`SETTLE`].
/// Enter or Ctrl-C ends it; a save that hasn't become a version yet is written first, and then
/// the copy is deleted. If that write fails, the copy stays, and this says where.
#[cfg(unix)]
pub fn open(access: &mut Access, collection: &str, name: &str, manifest: &Manifest) -> Result<()> {
    use std::io::BufRead;
    use tokio::signal::unix::{SignalKind, signal};

    let entry = format!("{collection}/{name}");
    if matches!(manifest.content, Content::Chunks { .. }) {
        access.fetch(collection, name)?;
    }
    let writable = access.can_write(collection)?;
    let dir = PrivateDir::create("open")?;
    let file_name = name.rsplit('/').next().expect("split gives one part");
    let path = dir.0.join(file_name);
    write_out(&path, manifest.executable, manifest.mtime, |file| {
        write_contents(access, collection, manifest, file)
            .with_context(|| format!("can't read {entry}"))
    })?;
    if !writable {
        // So its app shows it can't be changed.
        use std::os::unix::fs::PermissionsExt;
        let mode = if manifest.executable { 0o500 } else { 0o400 };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    }
    match launch(&path) {
        Ok(Launched::Opened) => println!(
            "Opened {entry} in its app, from a copy at {}",
            path.display()
        ),
        Ok(Launched::Asked) => println!(
            "Asked xdg-open to open {entry}, from a copy at {}. If no app opens it, open the \
             copy yourself.",
            path.display()
        ),
        Err(e) => println!(
            "Can't open {entry} in its app ({e}). Open the copy yourself: {}",
            path.display()
        ),
    }
    if writable {
        println!(
            "Each save becomes a new version of {entry} once the copy has been unchanged for 2 \
             seconds."
        );
    } else {
        println!(
            "This device can read {collection} but not write to it, so the copy is read-only and \
             nothing is saved."
        );
    }
    println!(
        "Press Enter here when you're done, and the copy is deleted. Closing the app doesn't end \
         this: there's no general way to tell when an app is done with a file."
    );

    // Enter, read on a thread of its own: a read left waiting on stdin would hold up a runtime's
    // shutdown. At the end of stdin, only a signal ends it.
    let (enter, mut entered) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            if line.is_err() || enter.send(()).is_err() {
                return;
            }
        }
    });
    // A save whose contents are the current version's writes nothing (files.md, open).
    let mut save = |path: &Path| -> Result<()> {
        if let Some(saved) = write_file(access, collection, name, path)? {
            println!(
                "Saved a new version of {entry}, {}.",
                size_label(saved.size)
            );
        }
        Ok(())
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let unsaved: Option<anyhow::Error> = runtime.block_on(async {
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let mut hangup = signal(SignalKind::hangup())?;
        let mut look = tokio::time::interval(LOOK);
        look.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // What the copy looks like now, since when, and when it last became a version.
        let mut seen = signature(&path);
        let mut since = tokio::time::Instant::now();
        let mut saved = seen;
        let mut failed: Option<anyhow::Error> = None;
        loop {
            tokio::select! {
                Some(()) = entered.recv() => break,
                _ = interrupt.recv() => break,
                _ = terminate.recv() => break,
                _ = hangup.recv() => break,
                _ = look.tick() => {
                    let now = signature(&path);
                    if now != seen {
                        seen = now;
                        since = tokio::time::Instant::now();
                    } else if writable && seen.is_some() && seen != saved && since.elapsed() >= SETTLE {
                        saved = seen;
                        failed = save(&path).err();
                        if let Some(e) = &failed {
                            eprintln!("latem-vault: can't save {entry}: {e:#}");
                        }
                    }
                }
            }
        }
        // A save that hasn't settled yet still counts.
        let now = signature(&path);
        if writable && now.is_some() && now != saved {
            failed = save(&path).err();
        }
        anyhow::Ok(failed)
    })?;
    // The runtime's only tasks are done; the stdin thread goes with the process.
    drop(runtime);
    if let Some(error) = unsaved {
        let kept = dir.keep();
        bail!(
            "can't save the last changes to {entry}: {error:#}. The copy is still at {}; delete \
             it once they're somewhere safe",
            kept.join(file_name).display()
        );
    }
    drop(dir);
    println!("Deleted the copy.");
    Ok(())
}

/// What a save changes: the file's length, modification time, change time and inode, which a
/// save that replaces the file changes too. `None` while it isn't there, as in the middle of
/// some apps' saves.
#[cfg(unix)]
fn signature(path: &Path) -> Option<(u64, i64, i64, i64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path).ok()?;
    Some((
        metadata.len(),
        metadata.mtime_nsec() + metadata.mtime() * 1_000_000_000,
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.ino(),
    ))
}

/// What opening a copy in its app came to.
#[cfg(unix)]
enum Launched {
    /// The app has it: macOS's `open` says so.
    Opened,
    /// `xdg-open` took it without failing, which doesn't mean an app did: with no app for the
    /// file's type, it can exit 0 after its last fallback, a browser, isn't found.
    Asked,
}

/// Opens `path` in its default app: `open` on macOS, which returns once the app has it, or
/// `xdg-open` elsewhere, which may stay with it, so it's waited for only 2 seconds.
#[cfg(unix)]
fn launch(path: &Path) -> Result<Launched> {
    let mut command = process::Command::new(if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    });
    command
        .arg(path)
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::null());
    if cfg!(target_os = "macos") {
        let status = command.status().context("can't run open")?;
        if !status.success() {
            bail!("open found no app for it");
        }
        return Ok(Launched::Opened);
    }
    // It may run the app itself and stay until the app quits, so it gets 2 seconds, and a
    // failure it reports in that time is said. Its own complaints stay on stderr, since it
    // doesn't report every failure.
    let mut child = command.spawn().context("can't run xdg-open")?;
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_secs(2) {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("xdg-open failed, {status}");
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Ok(Launched::Asked)
}

/// `UPLOAD_JKS` for `upload.jks`: upper case, with everything but A–Z and 0–9 turned into `_`.
pub fn file_var(name: &str) -> String {
    name.chars()
        .map(|c| {
            let c = c.to_ascii_uppercase();
            if c.is_ascii_uppercase() || c.is_ascii_digit() {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A directory only this user can open, deleted with what's in it when dropped.
struct PrivateDir(PathBuf);

impl PrivateDir {
    /// `latem-vault-<purpose>-<random>` in the user's temporary directory.
    fn create(purpose: &str) -> Result<Self> {
        let name = format!(
            "latem-vault-{purpose}-{}",
            hex(&latem_vault_crypto::random_bytes::<8>()[..])
        );
        let path = std::env::temp_dir().join(name);
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(&path)
            .with_context(|| format!("can't make {}", path.display()))?;
        Ok(Self(path))
    }
}

impl PrivateDir {
    /// Leaves it in place, for what couldn't be saved.
    #[cfg(unix)]
    fn keep(self) -> PathBuf {
        let path = self.0.clone();
        std::mem::forget(self);
        path
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.0) {
            eprintln!("latem-vault: can't delete {}: {e}", self.0.display());
        }
    }
}

fn private_dirs(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    Ok(builder.create(path)?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Runs the command and waits for it, passing on SIGTERM and SIGHUP so its files are deleted
/// however it ends. Ctrl-C reaches it from the terminal; this process waits it out. Exits as the
/// command did, with 128 plus the signal's number if a signal ended it.
#[cfg(unix)]
fn wait(child: process::Command) -> Result<ExitCode> {
    use std::os::unix::process::ExitStatusExt;
    use tokio::signal::unix::{SignalKind, signal};

    let program = child.get_program().to_owned();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let status = runtime.block_on(async {
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let mut hangup = signal(SignalKind::hangup())?;
        let mut child = match tokio::process::Command::from(child).spawn() {
            Ok(child) => child,
            Err(e) => return Ok(Err(e)),
        };
        let pid = child.id();
        let forward = |signal: libc::c_int| {
            if let Some(pid) = pid {
                // SAFETY: kill has no memory effects; a pid that has gone only fails.
                unsafe { libc::kill(pid as libc::pid_t, signal) };
            }
        };
        loop {
            tokio::select! {
                status = child.wait() => return status.map(Ok),
                _ = interrupt.recv() => {}
                _ = terminate.recv() => forward(libc::SIGTERM),
                _ = hangup.recv() => forward(libc::SIGHUP),
            }
        }
    })?;
    let status = match status {
        Ok(status) => status,
        Err(error) => {
            eprintln!("latem-vault: can't run {}: {error}", program.display());
            return Ok(ExitCode::from(match error.kind() {
                io::ErrorKind::NotFound => 127,
                _ => 126,
            }));
        }
    };
    Ok(match (status.code(), status.signal()) {
        (Some(code), _) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        (None, Some(signal)) => ExitCode::from(u8::try_from(128 + signal).unwrap_or(1)),
        (None, None) => ExitCode::FAILURE,
    })
}

pub fn placement(home: &Home, collection: &str, set: Option<Placement>) -> Result<()> {
    names::check_collection(collection)?;
    let placement = home.access()?.placement(collection, set)?;
    match placement {
        Placement::Keep => println!("{collection}: keep. Every current file's chunks stay here."),
        Placement::OnDemand => {
            println!("{collection}: on demand. Chunks of files read lately stay here, up to 2 GiB.")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_variables_are_named_after_the_last_part() {
        assert_eq!(file_var("upload.jks"), "UPLOAD_JKS");
        assert_eq!(file_var("google-services.json"), "GOOGLE_SERVICES_JSON");
        assert_eq!(file_var("AuthKey_ABC123.p8"), "AUTHKEY_ABC123_P8");
        assert_eq!(file_var("ç.txt"), "__TXT");
        assert!(!is_env_name(&file_var("2fa.txt")));
    }

    #[test]
    fn a_folder_keeps_its_paths_and_skips_what_isnt_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("keys");
        fs::create_dir_all(root.join("ios")).unwrap();
        fs::write(root.join("upload.jks"), b"jks").unwrap();
        fs::write(root.join("ios/AuthKey.p8"), b"p8").unwrap();
        fs::write(root.join(".DS_Store"), b"").unwrap();
        fs::write(root.join("ios/._AuthKey.p8"), b"").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("upload.jks"), root.join("link.jks")).unwrap();

        let (found, skipped) = sources(&root, None).unwrap();
        let names: Vec<&str> = found.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["keys/ios/AuthKey.p8", "keys/upload.jks"]);
        assert_eq!(skipped.len(), if cfg!(unix) { 3 } else { 2 });

        let (found, _) = sources(&root, Some("release")).unwrap();
        assert_eq!(found[1].name, "release/upload.jks");
        let (found, _) = sources(&root.join("upload.jks"), None).unwrap();
        assert_eq!(found[0].name, "upload.jks");
        let (found, _) = sources(&root.join("upload.jks"), Some("prod")).unwrap();
        assert_eq!(found[0].name, "prod/upload.jks");
    }
}
