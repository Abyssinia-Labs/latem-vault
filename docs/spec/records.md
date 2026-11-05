# Records and local store spec, v1

Status: draft, 2026-11-04. Implemented by `crates/core`. Builds on [crypto.md](crypto.md); the data model is [design §6](../design.md#6-data-model).

All integers are big-endian.

## Identifiers

Vault, device and collection ids are 16 random bytes, shown as 32 lowercase hex characters. A device id is assigned when the device's keys are created and doesn't change if its keys are rotated.

## Names

**Collection names** are 1–64 characters from `A–Z a–z 0–9 . _ -`, starting with a letter or digit, such as `latem-cloud` or `ssh`. They are unique within a vault.

**Entry names** are paths within a collection, such as `prod/SENTRY_DSN` or `release/upload.jks`: 1–512 bytes of UTF-8, `/`-separated segments that are non-empty and not `.` or `..`, with no control characters. Names are case-sensitive and compared byte for byte.

## Collection keys

Each collection has a key epoch, starting at 0. Each epoch has a random 32-byte collection key, wrapped (crypto.md, key wrapping) once for each device that can read the collection and once for the recovery key. The wrap context is:

```
vault_id (16) ‖ collection_id (16) ‖ epoch (u32)
```

## Records

Every entry version, deletion and collection rename is an immutable record:

```
header (78 bytes, cleartext)
  format      u8      0x01
  collection  16      collection id
  epoch       u32     key epoch the body is sealed under
  lamport     u64     Lamport clock
  device      16      author device id
  flags       u8      bit 0: deleted; other bits must be 0
  body_hash   32      BLAKE3 of the sealed body
signature (65)        author's signature over the 78 header bytes, context "record"
sealed body           XChaCha20-Poly1305 under the epoch's collection key
```

The body's AAD is the first 46 header bytes (everything before `body_hash`), so a body can't be moved under another header. `body_hash` then binds the body to the signature.

**Record id** = `BLAKE3.derive_key("openvault v1 record id", header)`. It covers the body through `body_hash` and never covers the signature (crypto.md, signatures). Record ids are what peers reconcile in sync.

**Body** (plaintext):

```
kind    u8      0x01 secret, 0x02 var, 0x10 collection; 0x03 file is reserved for M4
name    u16 length ‖ UTF-8
value   u32 length ‖ bytes
```

- A **deleted** record (flag bit 0) has the entry's kind and name and an empty value.
- Each collection has one **collection** entry, with an empty name, whose value is the collection's name. It's written when the collection is created; a rename is a new version.

A reader rejects a record if any check fails: format, flags, body hash, signature by a known device key, the collection key for its epoch, AEAD, body encoding, name rules, or a deleted record with a value.

## Versions

A record's version is `(lamport, device)`, compared in that order; the greatest version of a name is current. A device keeps one Lamport clock per vault. A new record gets `clock + 1`, and the clock advances to every version it writes or receives, so a local write is always newer than anything the device has seen. A deleted record stays current until a newer version replaces it, so an older version arriving later can't bring a deleted entry back.

## Local store

Each device keeps one SQLite database per vault, readable only by its user (mode 0600). It holds:

- the vault id, this device's id, the Lamport clock and the recovery wrapping key;
- known devices and their public keys;
- collections, their current epochs and wrapped keys;
- every record, as received;
- an index of each entry's current version;
- the membership log and the state it leads to ([membership.md](membership.md#keeping-the-log)).

The database's `user_version` is the store version: 1 in M1, 2 since the membership log. Opening a version 1 store upgrades it by adding the empty log table.

The index never stores a name in the clear. Each device has a 32-byte **local key**, kept by its keystore and never shared, from which it derives:

| Key | Derivation | Use |
| --- | --- | --- |
| Index key | `BLAKE3.derive_key("openvault v1 local index key", local key)` | `name_tag` = `BLAKE3.keyed_hash(index key, "entry" ‖ 0x00 ‖ collection_id ‖ name)`, or `"collection" ‖ 0x00 ‖ name` for collection names |
| Cache key | `BLAKE3.derive_key("openvault v1 local cache key", local key)` | seals the kind and name in the index, so listing doesn't need collection keys |
| Transport key | Ed25519 with seed `BLAKE3.derive_key("openvault v1 transport key", local key)` | the device's iroh identity, named in its add_device entry (design §7) |

Looking up an entry costs one index read and one record read. Listing a collection reads its index rows and decrypts their names with the cache key. Neither scans history.

## Not in v1

History pruning (N versions or D days), files and chunks, and receiving records from other devices. The format leaves room for each: pruning works on headers alone, files are kind `0x03`, and received records go through the same version rule as local writes.
