# Membership log spec, v1

Status: draft, 2026-11-05. Implemented by `crates/core`: the format and rules in `membership`, and keeping the log in the local store in `store`. Exchanging entries between devices is in [sync.md](sync.md#log-exchange), and adding a device in [join.md](join.md). Builds on [crypto.md](crypto.md) and [records.md](records.md); the design is in [design §7](../design.md#membership-log) and [§8](../design.md#8-joining).

Changed 2026-11-07: device names and platforms are sealed with the vault's names key (below). A store whose log was written before the change (store version 2, records.md) refuses to open, and its vault is created again.

The membership log decides who is in a vault:

- which keys are admins;
- which devices exist, with their public keys, and which have been revoked;
- what each device may do with each collection (its scope);
- each collection's current key epoch;
- the recovery wrapping key that every collection key is also wrapped to.

A device believes nothing about membership that the log doesn't say (OV-3). The coordinator stores and forwards the log but can't change it (OV-2), because every entry is signed by an admin and chained to the one before it.

All integers are big-endian.

## Entries

```
unsigned part
  format    u8          0x01
  vault     16          vault id
  seq       u64         0 for genesis, then one more than the entry before
  prev      32          hash of the entry before; 32 zero bytes for genesis
  signer    33 or 66    the signing admin's verifying key (crypto.md encoding)
  type      u8          see below
  payload   u32 length ‖ bytes, at most 1024 bytes
signature   65          the signer's signature over the unsigned part, context "log entry"
```

**Entry hash** = `BLAKE3.derive_key("openvault v1 log entry hash", unsigned part)`. Like a record id, it never covers the signature (crypto.md, signatures). The genesis entry's hash identifies the vault in joins (design §8).

Keys inside payloads use the crypto.md encodings, whose first bytes give their length: verifying keys are 33 bytes (Ed25519) or 66 (P-256), wrapping keys 34 (X25519) or 67 (P-256).

**Test vector.** The genesis entry of vault `01` × 16, made with the crypto.md recovery key test vector (secret = 32 zero bytes), lists only the recovery admin key and is signed by it.
- Its names key is `02` × 32. HPKE wrapping is randomized, so the vector fixes the wrapped names key: `00205bb0d4242e0a76d9ae61bd757c40c3151583ceb47c685b0ac5b305357c8a5153f00bdc8e12a46c0770fc09ee0f383361335f34424132898bacea2cb71e4e12cd8c5c4175a02bde50f4deeb790144ffa3`. It unwraps with the recovery key.
- The entry is 310 bytes long, with hash `761c2db1a367fecf09cb6ebaa3ea6d9589968d0ea2365d0331f000f9b2e50e14`.
- Like the crypto.md vectors, it comes from this implementation and is pinned in its tests.

## Types

| Code | Type | Payload |
| --- | --- | --- |
| `0x01` | genesis | recovery wrapping key ‖ admin count (u8) ‖ admin verifying keys ‖ names key wrapped to the recovery key |
| `0x02` | add_device | device id (16) ‖ verifying key ‖ wrapping key ‖ transport key ‖ sealed name (122) ‖ names key wrapped to this device |
| `0x03` | set_scope | device id (16) ‖ collection id (16) ‖ scope (u8) |
| `0x04` | revoke_device | device id (16) |
| `0x05` | rotate_epoch | collection id (16) ‖ epoch (u32) |
| `0x06` | add_admin | verifying key |
| `0x07` | remove_admin | verifying key |

- **Scopes:** `0x00` none, `0x01` hold, `0x02` read, `0x03` write (design §3).
- **Transport key:** the device's Ed25519 iroh identity (design §7), as a verifying key; it must be Ed25519.
- **Platform**, inside the sealed name: 1–16 bytes of `a–z 0–9`, such as `macos`, `ios`, `linux`, `windows`, `wsl` or `docker`. It is shown to people and means nothing to the protocol.
- **Name**, inside the sealed name: 1–64 bytes of UTF-8 with no control characters, such as `MacBook`.
- **Wrapped names key:** 82 bytes (X25519) or 115 (P-256), matching the wrapping key it is wrapped to (names key, below).

## Names key

Device names and platforms are sealed, so that the coordinator's copy of the log (from M3) doesn't show them. Default names are host names, which often contain the owner's name.

**The key.**
- `pinkvault init` generates the vault's **names key**: 32 random bytes.
- Genesis carries it wrapped to the recovery wrapping key, and each add_device carries it wrapped to the device being added.
- So each device gets the key from its own entry, which an admin signed, and recovery gets it from genesis.
- Wrapping is crypto.md key wrapping, with context `"names key" ‖ 0x00 ‖ vault id`.

**The sealed name.** It uses XChaCha20-Poly1305 under the names key, with AAD `vault id ‖ device id`, so a sealed name can't be moved to another device's entry.

```
plaintext  platform (u8 length ‖ ASCII) ‖ name (u8 length ‖ UTF-8), zero-padded to 82 bytes
sealed     nonce (24) ‖ ciphertext (82) ‖ tag (16): 122 bytes
```

The padding hides the name's length.

**Reading names.**
- Accepting an entry doesn't need the names key: the checks below cover lengths and the wrapped key's KEM.
- A device opens names only to show them.
- A name that doesn't open, or that breaks the rules above, is shown as the device id.

**What stays visible.**
- The coordinator still sees how many devices a vault has and their key types: P-256 for hardware keys, Ed25519 and X25519 for key files.
- The names key isn't rotated when a device is revoked. A revoked device that gets later entries, from the coordinator's copy for example, can read the names of devices added after it.

## Accepting an entry

A device accepts an entry only if every check passes:

1. **Encoding.** The format is `0x01`, the type is known, the payload is within its limit and decodes with no bytes left over.
2. **Chain.** The vault id is this vault's, `seq` is one more than the last accepted entry, and `prev` is that entry's hash. Genesis is accepted only as the first entry, with `seq` 0 and a zero `prev`.
3. **Signer.** The signer is a current admin, and the signature verifies. A genesis entry's signer must be one of the admins it lists.
4. **Type rules.**

| Type | Rule |
| --- | --- |
| genesis | Only at `seq` 0. 1–8 admins, no repeats. |
| add_device | The device id is new, revoked devices included. No other device, revoked or not, has the same verifying, wrapping or transport key. The wrapped names key's KEM matches the device's wrapping key. |
| set_scope | The device exists and isn't revoked. The scope differs from its current one, so the log holds no entries that change nothing. |
| revoke_device | The device exists and isn't already revoked. All its scopes become none. |
| rotate_epoch | The collection has appeared in a set_scope, and the epoch is its current epoch plus one. |
| add_admin | The key isn't already an admin, and there are fewer than 8. |
| remove_admin | The key is an admin and isn't the last one. An admin may remove itself. |

A collection becomes known to the log with its first set_scope, at epoch 0. Creating a collection is therefore an admin action: the admin signs a set_scope that gives the creating device `write`.

Revoking a device, or removing its `read` or `write` on a collection, is followed in the same approval by a rotate_epoch for each collection affected ([sync.md](sync.md#revoking-and-reducing-scopes)).

## Forks

Two different entries with the same `seq`, each valid against the log before it, are a fork. They can only come from admins signing concurrently, or from a compromised admin key.

When a device receives an entry whose `seq` it already has and whose hash differs from its own, it checks the entry against its own log up to `seq − 1`. If the entry passes, the device has found a fork: it keeps its own chain, stops syncing and shows both entries to an admin (design §7). An entry that fails the checks is rejected and is not a fork, since anyone can make an invalid entry.

## Keeping the log

Each device keeps every accepted entry, in order, and never deletes one. It checks each entry once, when it arrives, and keeps the resulting state (admins, devices, scopes and epochs) next to the entries, so opening a vault doesn't replay the log. Only fork checks replay it, up to the conflicting `seq`.

In the local store (records.md) that is:

- a `log` table of `seq`, entry hash and entry bytes;
- the state, encoded by `Membership::to_state_bytes`, in the `membership` row of `meta`. It's written in the same transaction as the entries it follows from, and only this device reads it.
- The state includes each collection epoch's history: the admins at the entry that began it, and every device that had `read` or `write`, and `write`, at some point during it. Checking a grant or a record signed under an old epoch needs these (sync.md), and the log is read once to find them.

On open, the state's head must equal the hash of the last row in `log`, and this device must be in it with the keys it opened the vault with. Otherwise the store is corrupt. Both checks are single-row reads.

A device's **transport key** comes from its local key (records.md, local store), so `add_device` can name it without the key file holding one.

The log grows with membership changes, not with data. A vault with 10 devices and 20 collections has a few hundred entries of under 1.2 KB each.

## Creating a vault

`pinkvault init` generates the recovery key, then signs two entries with the recovery admin key while it is still in memory:

1. genesis, listing the recovery admin key, this device's admin key if it has one (keystore.md, admin key), the recovery wrapping key, and a new names key wrapped to it;
2. add_device for this device, with its sealed name and the names key wrapped to it.

The recovery key is then dropped. It's needed again only to recover, or to sign as an admin on a device that has no admin key. So `pinkvault collections create` asks for Touch ID on a Mac that has an admin key, and for the recovery phrase on any other device, including Macs whose vaults were created before admin keys existed.

Vaults created in M1 have no log. Opening one adds the empty `log` table (store version 2) and nothing else, so reading keeps working. The first time an admin signature is needed, which today means creating a collection, `pinkvault` asks for the recovery phrase. It checks that the phrase derives the vault's recovery wrapping key, then writes, in one transaction:

1. genesis and add_device for the existing device;
2. a set_scope giving it `write` on each existing collection, plus rotate_epoch entries for any epoch past 0.

This also proves the phrase was written down correctly.

## Not in v1

- Rotating a device's keys. A device with new keys joins as a new device, and the old one is revoked.
- Changing the recovery key. That needs an entry that replaces the recovery wrapping key, and every collection key wrapped again.
- An entry that resolves a fork. In v1 an admin chooses a side by hand.
- Removing collections from the log. A collection whose scopes are all none is simply unused.
