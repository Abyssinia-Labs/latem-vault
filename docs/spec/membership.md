# Membership log spec, v1

Status: draft, 2026-11-05. The format and rules are implemented by `crates/core` (`membership`); keeping the log in the local store comes next. Builds on [crypto.md](crypto.md) and [records.md](records.md); the design is in [design §7](../design.md#membership-log) and [§8](../design.md#8-joining).

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

Test vector: the genesis entry of vault `01` × 16, made with the crypto.md recovery key test vector (secret = 32 zero bytes), which lists only the recovery admin key and is signed by it, is 228 bytes long and has hash `77b53378f73774df461b6e6444fdaf4a3f796dce377bb13372aeaee33d1d3cc5`. Like the crypto.md vectors, it comes from this implementation and is pinned in its tests.

## Types

| Code | Type | Payload |
| --- | --- | --- |
| `0x01` | genesis | recovery wrapping key ‖ admin count (u8) ‖ admin verifying keys |
| `0x02` | add_device | device id (16) ‖ verifying key ‖ wrapping key ‖ transport key ‖ platform (u8 length ‖ ASCII) ‖ name (u8 length ‖ UTF-8) |
| `0x03` | set_scope | device id (16) ‖ collection id (16) ‖ scope (u8) |
| `0x04` | revoke_device | device id (16) |
| `0x05` | rotate_epoch | collection id (16) ‖ epoch (u32) |
| `0x06` | add_admin | verifying key |
| `0x07` | remove_admin | verifying key |

- **Scopes:** `0x00` none, `0x01` hold, `0x02` read, `0x03` write (design §3).
- **Transport key:** the device's Ed25519 iroh identity (design §7), as a verifying key; it must be Ed25519.
- **Platform:** 1–16 bytes of `a–z 0–9`, such as `macos`, `ios`, `linux`, `windows`, `wsl` or `docker`. It is shown to people and means nothing to the protocol.
- **Name:** 1–64 bytes of UTF-8 with no control characters, such as `MacBook`.

## Accepting an entry

A device accepts an entry only if every check passes:

1. **Encoding.** The format is `0x01`, the type is known, the payload is within its limit and decodes with no bytes left over.
2. **Chain.** The vault id is this vault's, `seq` is one more than the last accepted entry, and `prev` is that entry's hash. Genesis is accepted only as the first entry, with `seq` 0 and a zero `prev`.
3. **Signer.** The signer is a current admin, and the signature verifies. A genesis entry's signer must be one of the admins it lists.
4. **Type rules.**

| Type | Rule |
| --- | --- |
| genesis | Only at `seq` 0. 1–8 admins, no repeats. |
| add_device | The device id is new, revoked devices included. No other device, revoked or not, has the same verifying, wrapping or transport key. |
| set_scope | The device exists and isn't revoked. The scope differs from its current one, so the log holds no entries that change nothing. |
| revoke_device | The device exists and isn't already revoked. All its scopes become none. |
| rotate_epoch | The collection has appeared in a set_scope, and the epoch is its current epoch plus one. |
| add_admin | The key isn't already an admin, and there are fewer than 8. |
| remove_admin | The key is an admin and isn't the last one. An admin may remove itself. |

A collection becomes known to the log with its first set_scope, at epoch 0. Creating a collection is therefore an admin action: the admin signs a set_scope that gives the creating device `write`.

## Forks

Two different entries with the same `seq`, each valid against the log before it, are a fork. They can only come from admins signing concurrently, or from a compromised admin key.

When a device receives an entry whose `seq` it already has and whose hash differs from its own, it checks the entry against its own log up to `seq − 1`. If the entry passes, the device has found a fork: it keeps its own chain, stops syncing and shows both entries to an admin (design §7). An entry that fails the checks is rejected and is not a fork, since anyone can make an invalid entry.

## Keeping the log

Each device keeps every accepted entry, in order, and never deletes one. It checks each entry once, when it arrives, and keeps the resulting state (admins, devices, scopes and epochs) next to the entries, so opening a vault doesn't replay the log. Only fork checks replay it, up to the conflicting `seq`.

The log grows with membership changes, not with data. A vault with 10 devices and 20 collections has a few hundred entries of under 1.2 KB each.

## Creating a vault

`openvault init` generates the recovery key, then signs two entries with the recovery admin key while it is still in memory:

1. genesis, listing the recovery admin key (and, from M2, this device's admin key) and the recovery wrapping key;
2. add_device for this device.

The recovery key is then dropped. It's needed again only to recover, or to sign as an admin on a device that has no admin key.

Vaults created in M1 have no log. The first version that keeps one asks once for the recovery phrase, checks that it derives the vault's recovery wrapping key, and writes the genesis and add_device entries for the existing device. This also proves the phrase was written down correctly.

## Not in v1

- Rotating a device's keys. A device with new keys joins as a new device, and the old one is revoked.
- Changing the recovery key. That needs an entry that replaces the recovery wrapping key, and every collection key wrapped again.
- An entry that resolves a fork. In v1 an admin chooses a side by hand.
- Removing collections from the log. A collection whose scopes are all none is simply unused.
