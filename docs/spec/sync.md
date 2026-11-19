# Sync spec, v1

Status: draft, 2026-11-07. Implemented on the local network: the sets, grants and accepting records in `crates/core` (`sets`, `grant`, the store's `sync` module), revoking in the store's `revoke` module, sessions and reconciliation in `crates/net` (`sync`), and starting sessions in `crates/service`. Builds on [records.md](records.md) and [membership.md](membership.md). The design is in [design §9](../design.md#9-sync) and [§10](../design.md#10-networking).

Devices in a vault exchange three things directly, over iroh:
- **the membership log;**
- **grants**, which carry wrapped collection keys;
- **records**, one set per collection.

This spec covers devices on the same local network (M2). Devices with a coordinator also reach each other through the grandfather's relay ([coordinator.md](coordinator.md)), and files and chunks come with M4.

All integers are big-endian.

## Connections

**Endpoints and discovery.**
- Each device runs one iroh endpoint. Its node id is the device's transport key (records.md, local store).
- It finds other devices with iroh's mDNS discovery, and recognizes members by their transport keys in the log. It ignores every other endpoint.

**Protocols.** Sync uses ALPN `openvault/sync/1`, joining uses `openvault/join/1` (join.md), and files' chunks use `openvault/chunks/1` (files.md, sync). A new protocol version gets a new ALPN.

**Who connects.**
- Either device may connect.
- iroh authenticates the transport keys at both ends (OV-7), and the log decides what each device may do.
- If two devices connect to each other at the same time, they keep the connection opened by the device with the smaller endpoint id, compared bytewise, and close the other. Endpoint ids are known before the logs are exchanged, which device ids aren't always.
- The connection that isn't kept is closed with QUIC application error code 1, "already syncing". The device that opened it doesn't count this as a failure and doesn't retry: the kept connection carries the session. A session that ends normally closes with code 0.

**Lifetime.** A device opens a connection when there is something to sync (below) and closes it after 60 seconds without a message. It keeps no idle connections.

**Quiet.** No message says a session is done, since a settled reply isn't sent (answering). So a session counts as quiet once 2 seconds pass without a message either way: it has caught up and only waits for more work. A message after that, received or sent for a notice, ends the quiet. A device shows a peer as syncing only while its session isn't quiet (service.md, peers).

### Framing

A session is one bidirectional QUIC stream. Each message is:

```
length  u32   of type and body, at most 2 MiB
type    u8
body
```

A message that is too long, has an unknown type or doesn't decode ends the session with error "bad message".

**`0x7f` error:** `reason u8 ‖ u16 length ‖ UTF-8 detail`. It is sent just before closing; the detail is for logs only.

| Reason | Meaning |
| --- | --- |
| `0x01` | wrong vault |
| `0x02` | not a member |
| `0x03` | fork |
| `0x04` | bad message |
| `0x05` | wrong code (join.md) |
| `0x06` | join refused (join.md) |

## When devices sync

There are no timers and no periodic scans.

**Starting a session.** A device starts one with a peer:
- when mDNS shows a member that wasn't visible before, which includes every member visible when it starts;
- after a local write, with every visible member that shares the collection;
- after its log grows, with every visible member. The entries may be its own, the coordinator's (coordinator.md), or taken from a peer in a session. Only entries the device didn't have count, so passing them on stops at devices that have them.

`pinkvault service` starts them (service.md). A write made through the service is a local write. So is a log entry `approve` appends, which it reports to the service with a changed request.

**During a session.** After a local write, a device sends the changed set's root at once (roots), and the opener reconciles that set again; the new records follow as items. A device announces a new log head by sending hello again. That costs one extra round trip compared with pushing the records themselves, and sends nothing a reconciliation wouldn't.
- Every running session announces it, whatever brought the entries: a local change, the coordinator, or another session.
- A session that has already sent that head sends nothing, as the session that took the entries does when it hears of them. Its roots started over when it sent it. Starting them over again would drop roots the peer has sent since, and the opener wouldn't reconcile again in that session.
- Before 0.5.7, entries a session took reached neither the device's other running sessions nor its other visible members. They waited until something else started a session: a write, mDNS seeing a device again, or a session closing and a later one starting. A second notice of the same head also started the roots over.

**Retries.**
- If a session with a visible peer fails, the device logs why and retries after 30 seconds, doubling up to an hour.
- Retries stop when the peer is no longer visible. They start over when it reappears or a sync succeeds.
- A peer that isn't visible is never dialed.

## Session

1. **Hello.** Both sides send hello. If the vault ids differ, the session ends with "wrong vault".
2. **Log.** The side that is behind requests entries until both heads are equal (below).
3. **Membership.** Each side checks that the other's transport key belongs to a device in its log that isn't revoked. If not, it closes with "not a member".
4. **Roots.** Each side sends the count and fingerprint of every set it shares with the peer.
5. **Reconcile.** For each set whose roots differ, the device that opened the connection starts range reconciliation (below). Items and wants flow both ways until every range is settled.

The session then idles until it closes or more work arrives.

**After a log change.** When a device's log grows during a session, from a local change, from entries the peer sent, or from entries another session or the coordinator brought (during a session, above), it sends hello again and the session goes back through steps 2 to 5. It does this once per new head. The peer's membership is checked again, both sides send their roots again, and the opener reconciles every set whose roots differ, since records dropped before may pass now (dropped records).
- Until the logs are level again, the peer may still be answering under the older log, so the two can disagree on what they share. A reconcile, want or items message is therefore checked against the device's current log, not the roots. It is answered or taken only if the device shares the set with the peer now.
- A message about a set the device doesn't share is ignored: not answered, not stored, and the session goes on. The peer may not yet have heard that the set was taken away.
- A peer that the change revoked ends the session with "not a member" at its next such message, or once the logs are level.
- Before the logs are first level in a session, such a message is a bad message.
- Before 0.5.6, any such message between a log change and the logs coming level again ended the session as a bad message. A scope change during a live session therefore ended it, until the retry 30 seconds later.

### Log exchange

| Type | Message | Body |
| --- | --- | --- |
| `0x01` | hello | vault id (16) ‖ log head seq (u64) ‖ head hash (32) |
| `0x02` | log request | from seq (u64) ‖ max (u16, at most 64) |
| `0x03` | log entries | count (u16) ‖ entries, each `u32 length ‖ entry` |

The answer to a log request is the entries from that seq on, in order, at most `max` of them.

**Who may request.**
- A device answers log requests only from devices in its log that aren't revoked.
- It requests entries from any peer whose head is ahead of its own. That includes a peer it doesn't know yet, which may have been added in entries it hasn't seen.
- It takes at most 4096 entries in one session.
- A revoked peer gets "not a member" right after hello, and nothing else.

**Checking entries.**
- Each entry is checked as it arrives, as membership.md says.
- An entry that doesn't extend the chain means the logs have diverged. The device requests earlier entries, 64 at a time, to find the first seq where they differ, then applies the fork rule (membership.md, forks).
- In v1, an entry with a seq the device already has is checked against its own: the same entry is skipped, and a different one is a fork if it would have been accepted in that place. An entry after the head that doesn't follow it ends the session as a bad message; finding where the logs diverged is not in v1 yet.
- A fork stops all sync until an admin resolves it.

## Sets

| Set | Id (17 bytes) | Items | Shared with a peer when |
| --- | --- | --- | --- |
| Records | `0x01 ‖ collection id` | record ids (records.md) | neither device's scope on the collection is none |
| Grants | `0x02 ‖ 16 zero bytes` | grant ids | always |

Both sides work out what they share from the same log, so they agree.

Each device keeps the count and the sum of the item ids for every set. It updates them in the same transaction as each insert, so reading a set's root costs one row.

### Fingerprints

Item ids are 32-byte BLAKE3 outputs, ordered bytewise. For a range of items:

```
fingerprint  first 16 bytes of BLAKE3.derive_key("openvault v1 sync fingerprint", sum ‖ count)
sum          the ids added as 256-bit big-endian integers, mod 2^256 (32 bytes)
count        u64
```

### Range reconciliation

This is range-based set reconciliation as in negentropy, with item ids as range bounds.

| Type | Message | Body |
| --- | --- | --- |
| `0x04` | roots | count (u16) ‖ for each set: set id (17) ‖ item count (u64) ‖ fingerprint (16) |
| `0x05` | reconcile | set id (17) ‖ range count (u16) ‖ ranges |
| `0x06` | want | set id (17) ‖ count (u16) ‖ ids |
| `0x07` | items | set id (17) ‖ count (u16) ‖ items, each `u32 length ‖ item` |

**Ranges.** A reconcile's ranges cover the whole id space, in order. Each range starts where the previous one ended (the first starts at zero) and runs up to, but not including, its upper bound:

```
upper   0x00 ‖ id (32), or 0x01 for the end of the id space
mode    0x00 skip           settled
        0x01 fingerprint    count (u64) ‖ fingerprint (16)
        0x02 ids            count (u16) ‖ ids (32 each)
```

**The first reconcile.** The device that opened the session sends one range covering everything. If it has at most 32 items it sends them as ids; otherwise it sends a fingerprint.

**Answering.** Each side then answers each reconcile it receives, range by range:

| Mode received | Answer |
| --- | --- |
| skip | skip |
| fingerprint | skip if it equals its own for that range. Otherwise send its ids if it has at most 32 in the range, or split its items in the range into 16 ranges of nearly equal count and send each one's fingerprint. |
| ids | It now knows both sides of the range: it sends the items the peer lacks (items), asks for the ones it lacks (want), and answers skip. |

**Settling.**
- A set is settled when a reconcile has only skips. Such a reconcile is never sent: a side that would answer with only skips sends nothing.
- Adjacent skips may be merged into one range.
- Each round splits the unsettled ranges sixteen ways. A set of n items with d differences therefore settles in about log₁₆ n rounds, using O(d log n) bytes.

**Items.**
- An items message holds as many whole items as fit in 2 MiB. A record is at most about 1 MiB (records.md).
- A device sends items only from sets it shares with the peer under its current log (after a log change), and only items the peer asked for (want), items it found missing (ids), or records it just wrote.

## Accepting records

A device keeps a record in its set only if every header check passes:

1. The format, flags and lengths are valid, and `lamport` is below 2⁶³.
2. The collection has appeared in the log, and the record's epoch is at most the collection's current epoch.
3. The author is a device in the log, revoked or not, that had `write` on the collection at some point while the collection was at the record's epoch.
4. `body_hash` matches the sealed body, and the signature verifies with the author's verifying key.

**Why only header checks.** These checks use only the header, the hash of the sealed body and the log. So devices with `hold` scope, which can't decrypt, make the same decisions as readers, and every device's sets converge to the same items.

**Opening the body.**
- A device that can read the collection then opens the body. If its key for the record's epoch hasn't arrived, the record waits for it, and is opened when the grant arrives (records.md, waiting records).
- A record that passes the header checks but fails to decrypt or decode is still kept and synced, so the sets still converge.
- It never becomes an entry's current version, and the device logs it with its author.

**Dropped records.** A record that fails a header check is dropped. It may pass later, once the log has grown (to a newer epoch, say), and reconciliation will offer it again.

## Grants

A grant carries one collection key, for one epoch, wrapped to one recipient:

```
unsigned part
  format      u8          0x01
  vault       16
  collection  16
  epoch       u32
  recipient   16          device id; 16 zero bytes for the recovery key
  signer      33 or 66    verifying key
  wrapped     82 or 115   the collection key, wrapped to the recipient's wrapping key
                          with the records.md context (collection keys)
signature     65          context "key grant"
```

**Grant id** = `BLAKE3.derive_key("openvault v1 grant id", unsigned part)`.

**Accepting grants.** A device keeps a grant only if every check passes:

1. The vault is its own, and the collection has reached the grant's epoch in the log.
2. The recipient is the recovery key, or a device that had `read` or `write` on the collection at that epoch or a later one. The wrapped key's KEM matches the recipient's wrapping key.
3. The signer is the verifying key of a device that had `read` or `write` at that epoch or a later one, or an admin key that was an admin at the entry that began the epoch. That entry is the collection's first set_scope for epoch 0, and its rotate_epoch for later epochs.
4. The signature verifies.

**Why later epochs count.** A device that may read a collection needs its earlier keys too: there's no blanket re-encryption (below), so most entries stay sealed with the key they were written under. An earlier key opens only what was written while it was current, which a device allowed to read the collection now may read. Builds before 0.2.1 checked only the grant's own epoch, so they drop these grants, and a device joining a collection whose key had changed couldn't finish its join.

**Who stores grants.**
- Every member keeps every grant. Grants are small, and only their recipients can open them.
- A recipient that can't unwrap a grant ignores it.
- A wrong key from a signer who could read the collection gives an attacker nothing they didn't already have.

**Who writes grants.**
- **Creating a collection:** the creating device writes grants for itself and for the recovery key, at epoch 0.
- **Joining:** the approving admin writes grants for the collections the new device may read (join.md).
- **A new read or write scope:** a device holding the collection's keys sees the set_scope and finds no grant for that device and epoch. It writes grants for every epoch it holds. If two devices both do it, the duplicates are harmless. In v1, as with joining, only the device that signs the set_scope does this, in the same transaction, so it must hold the collection's keys.
- **A new epoch:** the device whose admin signs the rotation generates the new key. It signs the grants with its own key, since it can read the collection, for every device with `read` or `write` and for the recovery key, in the same transaction as the log entries.

## Revoking and reducing scopes

Revoking a device, or removing its `read` or `write` on a collection, rotates the collection's epoch. What is written from then on is sealed under a key the device doesn't have.

**The admin signs, in one Touch ID prompt:**
1. revoke_device, or the set_scope;
2. rotate_epoch for every collection affected;
3. grants of each new key to every remaining reader and to the recovery key.

The device doing this makes the new keys and signs the grants, so it must be able to read every collection affected; otherwise it refuses before anything is signed. It can't revoke itself.

**Recounting.** Each device that applies a rotate_epoch recounts that collection's entries (records.md, versions): a current version from an older epoch whose author no longer has `write` stops counting, and the newest version of its name that still counts takes its place. Only those entries' records are read, unless one stopped counting; then the collection's records are read once, to find the versions that take their place.

**Sessions.** A running session checks the peer's membership again whenever the log changes: at each message about a set, and once the two logs are level (after a log change). A session with a device that has just been revoked therefore ends with "not a member", even when the revoked device already has the newest log.

**Versions from a removed writer.**
- A device that has lost `write` keeps its signing key and the old collection keys. It can still sign records under old epochs, with any name and any Lamport clock, and they pass the header checks.
- So when choosing an entry's current version, a reader ignores every version whose epoch is older than the collection's current one and whose author no longer has `write` on the collection (records.md, versions).
- Nothing that device signs, before or after its removal, can then become current. That includes new names: `pinkvault run` turns entries into environment variables, so an injected one could change what a build runs.

**Keeping its real writes.**
- The removed device's earlier writes were legitimate, so each device that still has `write` carries them forward.
- For every entry whose current version, just before it applied the rotation, was written by the removed device, it writes the same value again under the new epoch, deletions included.
- Duplicates from several devices are harmless.
- If no device with `write` remains, those entries stay in history only, until a device is given `write` and restores them.
- **In v1,** only the device that signs the revocation does this, where it has `write`. Other writers learn of the rotation before they hold the new key, and until then they'd have to remember the entries to write again. Until the carried versions arrive, a device that applied the rotation shows each such entry's previous version, or none.

**Reviewing.** `pinkvault devices revoke` lists the entries the device wrote last, for review, and the secrets it could read, to rotate at their providers (design §7). Since 0.5.3 it also lists the files it could read, to replace any that hold a key, such as a keystore. A file is listed whether or not the device fetched its chunks, since it could have. Since 0.5.4, a collection with more than 10 files lists each folder at its top as one line with its file count, as `documents/sample/ (12 files)`, so a documents folder doesn't make the list as long as the folder; files at the top of a collection, and a folder's only file, are still named.

**A gap.** A writer that received a forged version from the removed device before it learned of the removal can carry the forgery forward. Sessions exchange the log before records, so the gap closes at that writer's first sync with a device that knows of the removal.

**No blanket re-encryption (design §19, decision 2).**
- Re-encrypting the other secrets and variables under the new epoch wouldn't hide anything, since the removed device has already read them.
- Writes made under an old epoch by devices that still have `write`, such as offline writes during a rotation, keep counting as usual.
- In M4, files follow the same rules for their manifest records. Their chunks are re-encrypted only on request.

## Cost

| Case | Cost |
| --- | --- |
| Idle | No connections, no traffic and no database reads. |
| Session with nothing to do | Hello (61 bytes each way, framing included), plus roots: 41 bytes and one database read per shared set. Under 2 KB for 20 collections. |
| After a local write | One session per visible peer that shares the collection: a hello, the roots, then the record itself (about 1 KB for a secret). |
| After a log change | In each running session: a hello each way, one log request per 64 new entries, then the roots again as for a session with nothing to do, and a reconcile of each set whose roots differ. |
| After log entries from a peer | As after a log change, in each of the device's other running sessions, and a session with each visible member that has none. A peer that already has the entries costs a session with nothing to do. Each device passes a batch of entries on once, when they are new to it, and nothing runs on a timer. |
| Reconciling a set that differs | About log₁₆ n rounds. Each round reads at most the set's n ids from the local index; n is in the thousands for secrets and variables. Each message about a set also looks up the peer's membership and the shared sets, which are in memory, so no database read. |
| Retries | Only to visible peers, from 30 seconds doubling to an hour. |

**What to watch once it runs:**
- Sessions per device per hour. They should follow writes, log changes and network changes, not the clock. A log change should start at most one session between each pair of visible devices.
- Bytes per session.
- Retries per peer.

## Not in v1

- **Deleting a collection's records** from a device whose scope becomes none. It stops syncing the collection but keeps its copy.
- **Two connections to the same peer.** Sets are reconciled one after another on one stream.
- **History pruning** (records.md).
- **Finding where diverged logs part**, described under checking entries.
- **Sessions on a network change.** iroh notices one, but nothing starts sessions on it yet; mDNS shows peers again after the change.
