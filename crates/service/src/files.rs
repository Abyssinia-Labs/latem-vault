//! What the CLI and the Mac app's bindings both do with files (files.md): seal a file on disk into
//! chunks and a manifest, write one out through a private partial file, write a new version only
//! when its contents changed, and tell whether the disk is encrypted. Each request goes through a
//! [`Caller`]: the service's socket, or the vault in the CLI's own process.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use openvault_core::Kind;
use openvault_core::file::{CHUNK_SIZE, ChunkId, Content, MAX_INLINE, MAX_SIZE, Manifest};
use zeroize::Zeroizing;

use crate::api::{ChunkData, Item, Request, Response};
use crate::handler::unexpected;

/// Where file requests go.
pub trait Caller {
    fn call(&mut self, request: Request) -> Result<Response>;
}

/// Seals a piece of a file and keeps it. Returns its id and the epoch it's sealed under.
pub fn write_chunk(
    caller: &mut impl Caller,
    collection: &str,
    data: &[u8],
) -> Result<(ChunkId, u32)> {
    match caller.call(Request::WriteChunk {
        collection: collection.into(),
        data: ChunkData(Zeroizing::new(data.to_vec())),
    })? {
        Response::ChunkWritten { id, epoch } => Ok((id, epoch)),
        other => Err(unexpected(&other)),
    }
}

/// A chunk a manifest names, opened.
pub fn read_chunk(
    caller: &mut impl Caller,
    collection: &str,
    epoch: u32,
    id: ChunkId,
) -> Result<ChunkData> {
    match caller.call(Request::ReadChunk {
        collection: collection.into(),
        epoch,
        id,
    })? {
        Response::Chunk(data) => Ok(data),
        other => Err(unexpected(&other)),
    }
}

/// Seals the file at `path` into `collection`: kept in its manifest if it's at most 64 KiB, or
/// in chunks sent one at a time. Unchanged chunks of a file written before have the same ids, so
/// they aren't stored again.
pub fn seal_file(caller: &mut impl Caller, collection: &str, path: &Path) -> Result<Manifest> {
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
        let (id, sealed_under) = write_chunk(caller, collection, &piece[..len])?;
        if *epoch.get_or_insert(sealed_under) != sealed_under {
            bail!("{collection} got a new key while this file was read; write it again");
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

/// Writes the file at `path` as `collection`/`name`, unless its contents and executable bit are
/// what the current version holds. Returns the new version's manifest, or `None` if nothing was
/// written. It fails if `name` is a secret or a variable.
pub fn write_file(
    caller: &mut impl Caller,
    collection: &str,
    name: &str,
    path: &Path,
) -> Result<Option<Manifest>> {
    let current = match caller.call(Request::Get {
        collection: collection.into(),
        name: name.into(),
    })? {
        Response::Entry(value) => value,
        other => return Err(unexpected(&other)),
    };
    let current = match current {
        Some(value) if value.kind != Kind::File => {
            bail!("{collection}/{name} isn't a file, so a file can't take its name")
        }
        Some(value) => Some(Manifest::decode(&value.value)?),
        None => None,
    };
    let manifest = seal_file(caller, collection, path)?;
    if current.is_some_and(|current| {
        current.content == manifest.content && current.executable == manifest.executable
    }) {
        return Ok(None);
    }
    match caller.call(Request::Set {
        collection: collection.into(),
        entries: vec![Item {
            name: name.into(),
            kind: Kind::File,
            value: manifest.encode(),
        }],
    })? {
        Response::Done => Ok(Some(manifest)),
        other => Err(unexpected(&other)),
    }
}

/// Reads until `buf` is full or the file ends.
pub fn fill(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
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

/// Writes a file's bytes to `out`, a chunk at a time, so no more than a chunk is in memory.
pub fn write_contents(
    caller: &mut impl Caller,
    collection: &str,
    manifest: &Manifest,
    out: &mut impl Write,
) -> Result<()> {
    match &manifest.content {
        Content::Inline(bytes) => out.write_all(bytes)?,
        Content::Chunks { epoch, ids } => {
            let mut written = 0u64;
            for id in ids {
                let data = read_chunk(caller, collection, *epoch, *id)?;
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

/// Writes `path` through a private file beside it (mode 0600, or 0700 if `executable`), renamed
/// into place once it's whole, with `mtime` as its modification time.
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

/// A size as people read it: `3 B`, `2.5 MiB`.
pub fn size_label(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut size = bytes as f64 / 1024.0;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.1} {}", UNITS[unit])
}

/// `Ok` if this device's disk is encrypted, otherwise why not, or why it can't tell (design §13).
/// A file read for an import may stay on the disk in the clear after its original is deleted.
pub fn disk_encryption() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/bin/fdesetup")
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
    let resolved = fs::canonicalize(device).unwrap_or_else(|_| std::path::PathBuf::from(device));
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

    #[test]
    fn sizes_read_as_people_say_them() {
        assert_eq!(size_label(3), "3 B");
        assert_eq!(size_label(5 << 19), "2.5 MiB");
        assert_eq!(size_label(1 << 30), "1.0 GiB");
    }
}
