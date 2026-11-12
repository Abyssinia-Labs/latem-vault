# Files spec, v1

Status: stage 1 built in 0.4.0, 2026-11-11: files on one device, with the manifest, chunks, the local store, `import`, `get`, `list`, `run` and `placement`. Stage 2 built in 0.5.0, 2026-11-12: chunk sync over `openvault/chunks/1`, fetching, and the on-demand cache's limit. Stage 3 built in 0.5.1, 2026-11-12: `open`. Stage 4 built in 0.5.2 and the Mac app, 2026-11-12: files in the app (below). Builds on [records.md](records.md), [crypto.md](crypto.md) and [sync.md](sync.md). The design is in [design §13](../design.md#13-files), and it settles [§19, decision 3](../design.md#19-open-decisions).

A file is an entry like a secret: a name in a collection, with versions, written by devices with `write` and read by devices with `read`. Its record holds a manifest. A small file's bytes are in the manifest; a larger file's are in sealed chunks, which live outside the database and travel between devices only when a device needs them.

All integers are big-endian.

## Entries

- A file is kind `0x03` (records.md, records). Its name follows the entry name rules, so a folder is a name prefix: `docs/2026/passport.pdf`, `release/upload.jks`.
- The record's value is the file's manifest (below). Versions, deletion, the write rule and recounting are as for secrets and variables.
- Devices before 0.4 keep and sync file records but can't decode them (sync.md, opening the body). They never become current there, so those devices don't list files. Upgrading to 0.4 opens them again (records.md, local store).

## Manifest

```
format   u8    0x01
size     u64   the file's length in bytes
mode     u8    bit 0: executable; other bits must be 0
mtime    i64   the file's modification time when it was written, seconds since 1970 UTC
layout   u8    0x00 inline, 0x01 chunks
inline   the file's size bytes
chunks   epoch (u32) ‖ count (u32) ‖ chunk ids, 32 bytes each
```

- **Inline:** a file of at most 64 KiB, such as a `.p8` key, a `.jks` keystore or `google-services.json`. It syncs with its record and needs no chunks.
- **Chunks:** a larger file is cut into 1 MiB pieces, the last one shorter, so `count` is the size divided by 1 MiB, rounded up. `epoch` is the collection key they're sealed under (below).
- A record's value is at most 1 MiB, which allows 32 767 chunks: a file of up to 32 GiB less 1 MiB. Larger files are refused when written.
- A reader rejects a manifest whose format, mode bits or layout are unknown, whose inline bytes aren't `size` long or are more than 64 KiB, whose chunk count doesn't match `size`, or whose chunks are sealed under a later key than its record.
- `mtime` is shown and given back to a file when it's written out. Nothing compares it.

## Chunks

**Sealing.** A chunk is sealed under the collection key of the epoch its manifest names:

```
chunk key    BLAKE3.derive_key("openvault v1 chunk key", collection key)
nonce key    BLAKE3.derive_key("openvault v1 chunk nonce key", collection key)
nonce        first 24 bytes of BLAKE3.keyed_hash(nonce key, plaintext)
aad          "openvault v1 chunk" ‖ 0x00 ‖ vault id ‖ collection id ‖ epoch (u32)
sealed       nonce (24) ‖ XChaCha20-Poly1305(chunk key, nonce, plaintext, aad) ‖ tag (16)
chunk id     BLAKE3.derive_key("openvault v1 chunk id", sealed)
```

- **The same piece is stored once.** The nonce comes from the plaintext, so the same 1 MiB in the same collection and epoch seals to the same bytes and id. An unchanged chunk of an edited file, or a file imported twice, isn't stored or sent again.
- **What that reveals.** Anyone holding sealed chunks can see which of them are equal. In v1 only devices that can read the collection hold its chunks (not in v1, below), and they can read the plaintext anyway. A copy of a device's chunk directory shows equal chunks to whoever took it, and nothing else without the key.
- Chunks from different collections or epochs never share an id: the keys and the AAD differ.
- **Checking.** Anyone can check a sealed chunk against its id without a key, so a device checks every chunk it receives before keeping it. A reader also checks the tag when it opens one.
- **After a key change,** a new version seals all its chunks under the new epoch. Chunks of earlier versions keep theirs, as other entries do (sync.md, no blanket re-encryption).
- **Why the manifest names the epoch.** When a revoke writes again the entries a revoked device wrote last (sync.md, revoking and reducing scopes), the new record is sealed under the new key, but its file's chunks needn't be: the manifest still names the old epoch, whose key every reader keeps. Carrying a file forward costs one record, not its whole size.

**Why 1 MiB pieces at fixed offsets (decision 3).** Content-defined chunking would find unchanged data after an insert in the middle of a file. But its cut points depend on the content, and the chunk sizes then say something about it. With fixed offsets the only size anyone sees is the file's. Most files here are small, inline or a few chunks. A large file edited near its start is sent again from the edit on, which costs bandwidth and not secrecy.

## Local store

- **Where chunks live.** Each chunk is a file `chunks/<first two hex digits>/<id in hex>` in the openvault directory, mode 0600, directories 0700. They stay out of SQLite, so the database holds only small rows and a chunk is written once.
- **What the store keeps of them.** Store version 7 adds:
  - a `chunks` table of each chunk this device holds: its id, collection, epoch, size, the day it was last written or read, and the time it stopped being referenced, if it has;
  - a `file_chunks` table of the chunks each current file version names, whether this device holds them or not, so it knows which chunks are missing and which no version names any more;
  - a `placements` table (below).
- **The index.** A file's entry label holds its size too, so `list` shows sizes without opening records (records.md, local store).
- **Writing a chunk.** The device seals it under the collection's current key, and keeps it unless it already holds it. Its row comes first, marked unreferenced, then the file, written under a temporary name, synced and renamed, so a crash never leaves part of a chunk under its id, or a chunk file without a row. An import that stops halfway leaves chunks no manifest names, and the sweep deletes them.
- **Writing a file.** The chunks first, then the manifest record. The write checks that this device holds every chunk the manifest names, in that collection and under the epoch it says. A device never writes a manifest naming a chunk it doesn't hold.
- **Reading a file.** One record read, then each chunk in turn: read it, check its id, open it. Reading holds one chunk in memory at a time, whatever the file's size. A read moves the chunk's `used` day forward at most once a day, so reading doesn't write to the store each time.

**Placement.** Each device chooses, per collection, which chunks it keeps:

| Placement | Keeps | Default |
| --- | --- | --- |
| keep | every chunk of every current version | Macs and Linux |
| on demand | chunks of files read lately, up to 2 GiB per vault, least recently used dropped first | the iPhone (M5) |

**The cache limit.** After a fetch stores chunks, the device adds up the chunks it holds for its on-demand collections. While they take more than 2 GiB, it deletes the least recently used, by the day they were last read, sparing the file just fetched. They go at once rather than after 30 days, since a current file names them and they can be fetched again. A device with no on-demand collection reads nothing for this.

**Dropping chunks.**
- A chunk that no current version references stops counting when that happens: on a write, a received record or a recount (records.md, versions). One named again before it's deleted counts again.
- It's deleted 30 days later. Until then an older version can still be read from this device, and a file deleted by mistake can be put back.
- A sweep deletes what's due, at most 1000 chunks at a time: the files first, then their rows, so a crash leaves only rows that the next sweep deletes. It uses a partial index on the time chunks stopped being referenced, so it reads only what's due.
- The service sweeps when it starts, a batch at a time until none are due, letting requests in between. A set or delete that leaves chunks unreferenced sweeps one batch after it, through the service or not. A received record that leaves chunks unreferenced waits for the next of those. Nothing runs on a timer.
- So a device stores its current files once, plus at most a month of what changed.

## Sync

Chunks aren't in any reconciled set. A device that can read a collection finds the chunks it needs in the manifests, and asks peers that share the collection for them.

**Protocol.** Chunks have their own ALPN, `openvault/chunks/1`, on the same iroh endpoint. `openvault/sync/1` doesn't change, so devices on 0.3 keep syncing records and grants with newer ones. A peer that doesn't accept the ALPN has no chunks to give.

Each request is one bidirectional stream, with sync.md's framing. The asker sends hello and one want; the answer is the chunks, then one missing message, which ends it, empty if nothing is missing.

| Type | Message | Body |
| --- | --- | --- |
| `0x01` | hello | vault id (16) |
| `0x02` | want | collection id (16) ‖ count (u16, at most 64) ‖ ids |
| `0x03` | chunk | collection id (16) ‖ id (32) ‖ sealed chunk |
| `0x04` | missing | collection id (16) ‖ count (u16) ‖ ids |
| `0x7f` | error | as sync.md |

- **Answering.** The answering device first checks, as for sync, that the asker is a member that isn't revoked; otherwise it ends the stream with "wrong vault" or "not a member". It then answers a want with each chunk it holds, one message each, and one missing message for the rest. It answers only for collections where both devices have read or write: for any other, every chunk is missing. It never fetches a chunk for another device.
- **Asking.**
  - With keep placement, a manifest that becomes current from sync has its missing chunks asked for at once: when the session that brought it goes quiet (sync.md, quiet), or ends. A collection set to keep through the service gets its missing chunks then too.
  - `get`, `open` and `run` ask for the chunks of the file they read, whatever the placement.
  - A device asks the peers that read the collection, one after another, until none are missing: those on the local network first, then, with a coordinator configured, the others through its relay. Connecting to one may take 15 seconds before the next is asked.
- **Missing chunks.** A chunk no peer that was asked holds leaves its file waiting. For a kept collection, the device asks again when a session with any peer goes quiet or ends, backing off as sync.md's retries do: at the earliest 30 seconds later, doubling to an hour. Nothing asks on a timer alone. A file read on demand is asked for again when it's next read.
- **Bad chunks.** A chunk whose id doesn't match is dropped, and the stream ends with "bad message".
- **Connections.** A connection lasts while chunks are being asked for, and closes after 60 seconds without a message, as sync's do.

## Commands

```
openvault import <path> --collection <c> [--into <folder>] [--disk-not-encrypted]   a file, or a folder's files
openvault get <collection>/<name> [-o <path>]                  a file to stdout, or to a path
openvault open <collection>/<name>                             open a copy; each save writes a new version
openvault run --collection <c> --env <folder> -- <command>     the folder's files as temporary paths too
openvault placement <collection> [keep|on-demand]
openvault list <collection>[/<folder>]                         files show their size, and whether they're here
```

**import**
- It needs full-disk encryption on this device (design §13): FileVault on macOS (`fdesetup isactive`), or a root file system on dm-crypt on Linux, directly or under LVM. Otherwise it stops, since the plaintext it read may survive on the disk. `--disk-not-encrypted` imports anyway and says why that's a risk.
- A folder's files become `<folder>/<path within it>`, where `<folder>` is `--into` or else the folder's own name: `import ~/keys --collection latem` gives `keys/upload.jks`. A single file goes into `--into`, or at the top of the collection. Symbolic links, `.DS_Store`, `._*` files, anything that isn't a regular file, and names that aren't UTF-8 or break the name rules are skipped and listed.
- A name already taken by a secret or variable stops the import before anything is written.
- A file whose manifest would be the same as its current version's isn't written again. Its chunks are sealed anyway, to find out, but they're already held, so nothing is stored twice.
- Manifests go to the service in batches of up to 4 MiB, each one transaction.
- It leaves the originals in place and says where they are, so they're deleted only once someone has checked the import.

**get** writes a file's bytes to stdout, or to `-o <path>` with mode 0600 (0700 if it's executable) and its `mtime`. The path is written through a private file beside it, renamed into place once whole. `-o` also writes a secret's or variable's value; without it they print as before.

**open**
- It fetches the file's chunks if any aren't here, as `get` does. It then writes the file to a private directory (0700) in the user's temporary directory, under the file's own name, and opens it with its default app (`open` on macOS, `xdg-open` on Linux). If that fails, it says where the copy is.
- It stays in the foreground. Each time the copy is saved, it writes a new version, once the file has been unchanged for 2 seconds, so an app that saves in several steps makes one version. A save is noticed by the copy's length, modification and change times, and inode, looked at every half second. A save whose contents are the same as the last version's, as when only the time changed, writes nothing.
- On a device that can read the collection but not write to it, the copy is read-only (0400), so its app shows it can't be changed, and nothing is saved.
- It ends on Enter or Ctrl-C (or SIGTERM or SIGHUP). A save that hasn't become a version yet is written first, then the copy and its directory are deleted. If that write fails, the copy stays, and it says where. There is no general way to see an app close a document, so it says so when it starts.

**run** also writes the folder's files to a private temporary directory (0700) for the command's lifetime, keeping their paths within the folder. Each file's path is set in a variable named after the last part of its name, upper-cased with every character but A–Z and 0–9 turned into `_`: `prod/upload.jks` becomes `UPLOAD_JKS` (with `--prefix`, `LATEM_SECRET_UPLOAD_JKS`). A name that would start with a digit is an error, and so are a file and a secret or variable, or two files, that would set the same variable.
- Without files, `run` replaces itself with the command, as before. With files it starts the command and waits, so it can delete the directory when the command exits. It passes SIGTERM and SIGHUP on to the command, and waits out Ctrl-C, which the terminal sends the command too. It exits as the command did, or with 128 plus the signal's number.
- A `run` killed with SIGKILL leaves the directory in the user's temporary directory.

**placement** shows or sets this device's placement for a collection. Switching to on demand doesn't delete anything at once; the cache's limit does that over time. Switching to keep through the service fetches what's missing at once. Only a placement other than the device's default is stored.

## The service

- Files cross the local socket one chunk to a message, in both directions, so neither process holds more than a chunk (service.md, files). The CLI reads and writes the user's files itself. On macOS that matters: a LaunchAgent reading `~/Documents` would need its own permission.
- Without a service, the CLI runs the same requests on the vault itself.
- The service holds the endpoint, so it fetches chunks. The fetch request (service.md, files) asks for a file's chunks: the service fetches the missing ones and answers once they're all here, or with how many no peer had. `get` and `run` send it before they read a file; without a service they fail if chunks are missing, and say to start it.
- When a fetch stores chunks, the watch sends an entries event for the collection, so an app can show its files as here.

## The Mac app

Since 0.5.2 the Swift bindings list files with their sizes and how many of their chunks aren't here, and fetch, write out and write files through the shared code the CLI uses (`openvault_service::files`). The app (`openvault-apple`):

- **Lists** a collection's files among its entries, with their sizes, and "not here" while chunks are missing. Counts include files.
- **Opens** a file as `open` does: it fetches what's missing, writes a copy to a private directory and opens it in its app. A save becomes a new version once nothing has changed in the copy's directory for 2 seconds, which the app learns from FSEvents rather than by looking. Done, on the file or in Needs you, writes a save that hasn't settled and deletes the copy; quitting the app does that for every open file first. A copy whose last save can't be written stays, and the app says where. On a Mac that can't write the collection, the copy is read-only and nothing is saved.
- **Saves a copy** where you pick, as `get -o` does.
- **Imports** files and folders, from the file picker or dropped on a collection, with `import`'s rules for names, what's left out and disk encryption; the sheet lists what it will write before it does. A file whose contents haven't changed isn't written again.
- **Shows and sets placement** for a collection with files: keep all, or on demand.
- ⌘K finds secrets and variables only, since it copies values.

## Cost

| Case | Cost |
| --- | --- |
| Storage | Each device that keeps a collection stores its current files once, plus up to 30 days of changed chunks. An on-demand device stores at most 2 GiB. |
| Writing a 10 MiB file | 10 chunks sealed and stored, each a request over the local socket and one row; one record with a 347-byte manifest, and 10 `file_chunks` rows. |
| Syncing it | The record to every peer that shares the collection, then 10 chunk messages (10 MiB) to each that keeps it. |
| Editing it near the end | The record, and only the chunks from the edit on. |
| A file nobody holds | One want to each peer that reads the collection, then, if it's kept, retries with backoff. |
| A session that catches up | A flag and a map. If a received record named chunks that aren't here, one query per kept collection for the files missing chunks, and one record opened for each. |
| Fetching on demand | After it, the sizes of the on-demand collections' chunks added up, from their rows: at most about 2 000 rows at the limit. |
| Listing a collection | Its index rows, as before. With files, one more query counts the chunks that aren't here, over the collection's `file_chunks` rows. |
| `open` | While it runs, one `stat` of the copy every half second. A save seals the file again: unchanged chunks have the same ids, so only the changed ones are stored and sent. |
| Idle | Nothing. No sweep or fetch runs on a timer. |

**What to watch once it runs:**
- The `chunks` directory's size against the size of the current files. It should stay within a month of changes of it.
- Chunk bytes sent per device per day. They should follow writes.
- Files waiting for chunks, and how long they wait.

## Not in v1

- **Chunks on `hold` devices.** A device that can't read a collection can't read its manifests either. It can't tell which chunks are current, so it couldn't drop old ones. In v1 it keeps the records and no chunks, and a grandfather can't yet serve files to a phone while the Macs are off. A later version can give holders a keyed tag per name in the record header, or have readers list the current chunks.
- **Re-sealing chunks after a revoke.** Only on request, later (design §19, decision 2).
- **Reading an older version** (`get --version`), and putting a deleted file back, beyond the 30 days its chunks stay.
- **Reading part of a file**, which the File Provider (M5) will want for large files.
- Empty folders, symbolic links, extended attributes, and permissions other than the executable bit.
- The local web UI, the File Provider and a FUSE mount, which build on this.
