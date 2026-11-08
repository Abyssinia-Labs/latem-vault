# Join spec, v1

Status: draft, 2026-11-07. Implemented on the local network: the PAKE in `crates/crypto` (`pake`), the request, approval and the joiner's store in `crates/core` (`join`, `Vault::approve_join`, `Vault::join`), the messages in `crates/net` (`join`), and the commands in `crates/cli`. Builds on [membership.md](membership.md), [keystore.md](keystore.md) and [sync.md](sync.md), whose connections and message framing it uses. The design is in [design §8](../design.md#8-joining).

A new device joins a vault in one sitting:

1. It shows a 6-digit code.
2. Someone types the code into an admin device and approves the device with Touch ID.
3. The new device receives the membership log and the keys for its collections.

In M2 the two devices talk directly on the local network. From M3 the same messages can go through the coordinator's mailbox (design §11).

All integers are big-endian.

## Commands

```
openvault join [--name <name>] [--keys <backend>]       on the new device
openvault approve [--write|--read|--hold <collection>]...   on an admin device
```

**join**
- Creates the device's keys (keystore.md) and a file `joining` in the openvault directory that holds its device id, so an interrupted join can resume with the same identity. The file goes once the store is written.
- Waits up to 10 minutes for an admin, showing the code.
- Running it again on the same device reuses the keys and the device id, and shows a new code.
- It runs its own endpoint, with ALPN `openvault/join/1`. There is no vault yet for a service to hold.

**approve**
- Looks for devices waiting to join on the local network for up to 15 seconds. It picks the device itself if there is only one, and otherwise asks which.
- Asks for that device's code and shows the device for review.
- Scopes come from its flags. A device approved without any has none until `openvault scope` sets them.
- It opens the vault itself and runs its own endpoint, which mDNS doesn't announce, even while `openvault service` runs. The service sees the new entries on its next request (service.md, the store).
- A vault without a membership log yet can't approve anyone. Creating a collection starts the log (membership.md, creating a vault).

## Finding the device

While it waits, the joiner announces itself on the local network with mDNS. The announcement carries:
- its transport key, which is its iroh node id;
- its platform and name.

These are hints for picking it from the list, and nothing in them is trusted. The admin connects to that node id over iroh with ALPN `openvault/join/1`.

The announcement is mDNS user data: `join:<platform>:<name>`, at most 86 bytes. The admin drops control characters from it before showing it.

## The code

- Six decimal digits, chosen uniformly by the joiner from the OS random generator and shown as `123 456`. It is used for one join and never sent over the network.
- **When the join ends:** the joiner ends it after the code has been shown for 10 minutes, or after three PAKE sessions that didn't finish with both confirmations, whichever comes first.
- **Guessing:** each session gives an attacker one guess, so an attacker on the network gets the code right with probability at most 3 in a million per join.
- **Cancelling:** anyone on the network can also use up the three attempts and cancel a join. The user then starts it again.
- **The admin's limit:** `approve` also stops after three wrong codes. Someone posing as the joiner gets one guess each time the user tries, so without this limit retries would give them as many guesses as they liked.

## PAKE

SPAKE2 over Ed25519, as implemented by the RustCrypto `spake2` crate (compatible with python-spake2 and magic-wormhole). It is pinned to 0.5.0-pre.0, the release that shares the workspace's curve25519-dalek 5:

| Input | Value |
| --- | --- |
| Password | `"openvault v1 join code" ‖ 0x00 ‖ the six ASCII digits` |
| idA | the admin's transport key, as a crypto.md verifying key (33 bytes) |
| idB | the joiner's transport key, encoded the same way |
| Sides | the admin is side A (`start_a`), the joiner side B (`start_b`) |

**Binding to the connection.**
- iroh authenticates both ends' transport keys, and the PAKE binds those same keys to the code.
- A man in the middle has a different transport key toward each side, so its two sessions derive different keys even if it relays every message.

Let `K` be the 32-byte key that `finish` returns. From it:

| Value | Derivation |
| --- | --- |
| Joiner confirmation | `BLAKE3.derive_key("openvault v1 join confirm joiner", K)` |
| Admin confirmation | `BLAKE3.derive_key("openvault v1 join confirm admin", K)` |
| Session id | `BLAKE3.derive_key("openvault v1 join session", K)` |

**Audit.**
- No Rust PAKE crate has had an independent audit, including this one.
- It is one of two exceptions to the audited-libraries rule in design §7. The other is `argon2`, for passphrases (crypto.md, passphrases).
- The external audit planned before the hosted launch covers it.

## Messages

In order, on one stream (sync.md, framing):

| Step | From | Message | Body |
| --- | --- | --- | --- |
| 1 | admin | `0x20` pake | SPAKE2 message (33 bytes) |
| 2 | joiner | `0x20` pake | SPAKE2 message (33 bytes) |
| 3 | joiner | `0x21` confirm | joiner confirmation (32) |
| 4 | admin | `0x21` confirm | admin confirmation (32) |
| 5 | joiner | `0x22` request | below |
| 6 | admin | `0x23` accepted | vault id (16) ‖ log head seq (u64) ‖ head hash (32) |
| 7 | both | log request, log entries (sync.md) | until the joiner has the log up to that head |
| 8 | admin | items (sync.md), grants set | the joiner's grants |
| 9 | joiner | `0x24` joined | empty |

**Timing.** Each message must arrive within 30 seconds, except accepted (step 6), which waits for the admin to review and sign, up to the end of the join's 10 minutes. The admin sends the grants (step 8) as soon as it has answered the log request that reaches the head.

**Checking the confirmations.**
- Each side compares the confirmation it receives in constant time.
- If it's wrong, the side closes with error "wrong code" (sync.md).
- The admin sends its confirmation only after checking the joiner's, so an attacker posing as the joiner learns nothing from the admin.

**The request** (step 5):

```
device id       16
verifying key   33 or 66
wrapping key    34 or 67
transport key   33        must be the joiner's iroh node id
platform        u8 length ‖ ASCII
name            u8 length ‖ UTF-8
signature       65        by the joiner's signing key, context "join request",
                          over session id ‖ the fields above
```

The admin builds the add_device entry from these fields (membership.md). It seals the platform and name, and wraps the names key to the joiner's wrapping key (membership.md, names key). The signature shows that the joiner holds the signing key it names, in this session.

## Approval

The admin checks the request against the add_device rules (membership.md), then shows it:

```
Device    Desktop
Platform  linux
Keys      file
Id        3f2a9c41…
Scopes    read latem
```

`Keys` is `hardware` for P-256 keys (Secure Enclave or TPM) and `file` otherwise.

**Signing.** When the user confirms, the admin signs, with one Touch ID prompt (keystore.md, admin key):
1. add_device with the request's fields;
2. a set_scope for each scope given.

**Storing and grants.**
- It appends the entries to its log in one transaction.
- It writes grants (sync.md, grants) for each collection the joiner may read, for every epoch whose key it holds, signed with its device signing key.
- Grants for collections whose keys it doesn't hold come from a device that does, the next time that device syncs.

**Other cases.**
- **No admin key:** on a device without one, the recovery phrase signs instead, as for `collections create`. A vault created in M1 starts its log first (membership.md, creating a vault).
- **Resuming:** if the joiner's device id is already in the log with the same keys, an approved join was interrupted. The admin skips signing and continues from step 6.
- **Refused:** a device id that is in the log with other keys, or that is revoked, is refused with error "join refused".

## Joining

The joiner accepts the vault only if both of these hold:
- the log verifies from genesis (membership.md, accepting an entry) and ends at the head from step 6;
- the log contains an add_device with its device id and keys, whose names key unwraps with its wrapping key, and whose sealed name opens to the platform and name it sent.

**Why the log can't be swapped:** the head arrived over the channel the PAKE authenticated, and its hash covers every entry before it. So a relay, and from M3 the coordinator, can't substitute another vault's log.

**Finishing.**
- The joiner checks its grants (sync.md) and unwraps each one.
- It writes its store in one transaction: the vault id, the log and its state, and the grants.
- It sends joined.
- From then on it is an ordinary device and syncs records with any peer (sync.md).
- Until its first sync it has no records, so no collection names either: `openvault collections` lists none, while `openvault devices` already lists the vault's devices.

## Not in v1

- **Joining through the coordinator's mailbox** comes with M3. The messages are the same, but they need protection that iroh gives here, so M3 defines it.
- **Approval notifications** (design §8) come with the Apple apps in M5. Until then `approve` is run by hand.
- **Making a joined device an admin** is an add_admin entry (membership.md), signed separately.
- QR codes.
