//! Files (files.md, commands): `import`, `get` for a file, `run` with a folder's files, and
//! `placement`. This process reads and writes the user's files itself; only chunks cross to the
//! service, one to a message.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use openvault_core::file::{CHUNK_SIZE, ChunkId, Content, MAX_INLINE, MAX_SIZE, Manifest};
use openvault_core::names::{self, is_env_name};
use openvault_core::{Kind, Placement};
use openvault_service::api::{ChunkData, Item, Request, Response};
use openvault_service::handler::unexpected;
use zeroize::Zeroizing;

use crate::{Access, Home, size_label};

/// Files' manifests go to the service in batches of at most this many bytes.
const BATCH_BYTES: usize = 4 << 20;

impl Access {
    fn write_chunk(&mut self, collection: &str, data: &[u8]) -> Result<(ChunkId, u32)> {
        match self.call(Request::WriteChunk {
            collection: collection.into(),
            data: ChunkData(Zeroizing::new(data.to_vec())),
        })? {
            Response::ChunkWritten { id, epoch } => Ok((id, epoch)),
            other => Err(unexpected(&other)),
        }
    }

    fn read_chunk(&mut self, collection: &str, epoch: u32, id: ChunkId) -> Result<ChunkData> {
        match self.call(Request::ReadChunk {
            collection: collection.into(),
            epoch,
            id,
        })? {
            Response::Chunk(data) => Ok(data),
            other => Err(unexpected(&other)),
        }
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
            "The originals are still in {}. Delete them once `openvault list {collection}` \
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
fn seal_file(access: &mut Access, collection: &str, path: &Path) -> Result<Manifest> {
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_SIZE {
        bail!("files are at most {}", size_label(MAX_SIZE));
    }
    let mtime = match metadata.modified()?.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
    };
    #[cfg(unix)]
    let executable = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o111 != 0;
    #[cfg(not(unix))]
    let executable = false;

    let mut piece = Zeroizing::new(vec![0; CHUNK_SIZE]);
    let first = fill(&mut file, &mut piece)?;
    if first <= MAX_INLINE {
        return Ok(Manifest {
            size: first as u64,
            executable,
            mtime,
            content: Content::Inline(Zeroizing::new(piece[..first].to_vec())),
        });
    }
    let (mut ids, mut size, mut epoch) = (Vec::new(), 0u64, None);
    let mut len = first;
    while len > 0 {
        if ids.len() * CHUNK_SIZE >= MAX_SIZE as usize {
            bail!("files are at most {}", size_label(MAX_SIZE));
        }
        let (id, sealed_under) = access.write_chunk(collection, &piece[..len])?;
        if *epoch.get_or_insert(sealed_under) != sealed_under {
            bail!("{collection} got a new key while this file was read; import it again");
        }
        ids.push(id);
        size += len as u64;
        if len < CHUNK_SIZE {
            break;
        }
        len = fill(&mut file, &mut piece)?;
    }
    Ok(Manifest {
        size,
        executable,
        mtime,
        content: Content::Chunks {
            epoch: epoch.expect("a chunked file has a chunk"),
            ids,
        },
    })
}

/// Reads until `buf` is full or the file ends.
fn fill(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Writes a file's bytes to `out`, a chunk at a time.
fn write_contents(
    access: &mut Access,
    collection: &str,
    manifest: &Manifest,
    out: &mut impl Write,
) -> Result<()> {
    match &manifest.content {
        Content::Inline(bytes) => out.write_all(bytes)?,
        Content::Chunks { epoch, ids } => {
            let mut written = 0u64;
            for id in ids {
                let data = access.read_chunk(collection, *epoch, *id)?;
                written += data.0.len() as u64;
                out.write_all(&data.0)?;
            }
            if written != manifest.size {
                bail!("its chunks don't add up to its size");
            }
        }
    }
    Ok(out.flush()?)
}

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
    match output {
        None => write_contents(access, collection, manifest, &mut io::stdout().lock())
            .with_context(context),
        Some(path) => write_out(path, manifest.executable, manifest.mtime, |file| {
            write_contents(access, collection, manifest, file).with_context(context)
        }),
    }
}

/// Writes `path` through a private file beside it, renamed into place once it's whole.
pub fn write_out(
    path: &Path,
    executable: bool,
    mtime: i64,
    contents: impl FnOnce(&mut fs::File) -> Result<()>,
) -> Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} isn't a file name", path.display()))?;
    let mut partial = OsString::from(".");
    partial.push(file_name);
    partial.push(".openvault-partial");
    let partial = dir.join(partial);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, if executable { 0o700 } else { 0o600 });
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&partial)
            .with_context(|| format!("can't write {}", partial.display()))?;
        contents(&mut file)?;
        if let Some(time) = system_time(mtime) {
            file.set_modified(time)?;
        }
        file.sync_all()?;
        fs::rename(&partial, path).with_context(|| format!("can't write {}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

fn system_time(secs: i64) -> Option<SystemTime> {
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
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
    let dir = PrivateDir::create()?;
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
    fn create() -> Result<Self> {
        let name = format!(
            "openvault-run-{}",
            hex(&openvault_crypto::random_bytes::<8>()[..])
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

impl Drop for PrivateDir {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.0) {
            eprintln!("openvault: can't delete {}: {e}", self.0.display());
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
            eprintln!("openvault: can't run {}: {error}", program.display());
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

/// `Ok` if this device's disk is encrypted, otherwise why not, or why it can't tell (design §13).
fn disk_encryption() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let output = process::Command::new("/usr/bin/fdesetup")
            .arg("isactive")
            .output()
            .map_err(|e| format!("can't ask fdesetup whether FileVault is on: {e}"))?;
        match String::from_utf8_lossy(&output.stdout).trim() {
            "true" => Ok(()),
            "false" => Err("FileVault is off".into()),
            other => Err(format!("fdesetup says {other:?} about FileVault")),
        }
    }
    #[cfg(target_os = "linux")]
    {
        linux_root_encrypted()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("openvault can't tell whether this disk is encrypted".into())
    }
}

/// Whether the root file system is on dm-crypt, directly or under LVM.
#[cfg(target_os = "linux")]
fn linux_root_encrypted() -> Result<(), String> {
    let mounts = fs::read_to_string("/proc/self/mounts")
        .map_err(|e| format!("can't read /proc/self/mounts: {e}"))?;
    // The last mount on / is the one in use.
    let device = mounts
        .lines()
        .rev()
        .find_map(|line| {
            let mut fields = line.split(' ');
            let (source, target) = (fields.next()?, fields.next()?);
            (target == "/").then_some(source)
        })
        .ok_or("can't find the root file system")?;
    let resolved = fs::canonicalize(device).unwrap_or_else(|_| PathBuf::from(device));
    let Some(name) = resolved
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.starts_with("dm-"))
    else {
        return Err(format!("the root file system ({device}) isn't on dm-crypt"));
    };
    if dm_crypt(name, 4) {
        Ok(())
    } else {
        Err(format!("the root file system ({device}) isn't on dm-crypt"))
    }
}

/// Whether device-mapper device `name`, or one it's built on, is a dm-crypt device.
#[cfg(target_os = "linux")]
fn dm_crypt(name: &str, depth: u8) -> bool {
    let block = Path::new("/sys/block").join(name);
    if fs::read_to_string(block.join("dm/uuid")).is_ok_and(|uuid| uuid.starts_with("CRYPT-")) {
        return true;
    }
    depth > 0
        && fs::read_dir(block.join("slaves")).is_ok_and(|slaves| {
            slaves.flatten().any(|slave| {
                slave
                    .file_name()
                    .to_str()
                    .is_some_and(|slave| slave.starts_with("dm-") && dm_crypt(slave, depth - 1))
            })
        })
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

    #[test]
    fn written_files_are_private_and_keep_their_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        write_out(&path, true, 1_000_000_000, |file| {
            Ok(file.write_all(b"data")?)
        })
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"data");
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(
            metadata.modified().unwrap(),
            UNIX_EPOCH + Duration::from_secs(1_000_000_000)
        );
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o777,
            0o700
        );
        // A failure leaves neither the file nor the partial one.
        let failed = dir.path().join("failed.bin");
        assert!(write_out(&failed, false, 0, |_| bail!("no")).is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
