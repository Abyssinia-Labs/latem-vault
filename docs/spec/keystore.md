# Keystore spec, v1

Status: draft, 2026-11-04. Implemented by `crates/keystore`. Builds on [crypto.md](crypto.md); the device keys are in [design §7](../design.md#device-keys).

Changed 2026-11-07: passphrase-protected key files (kind `0x03`), the default where there's no Secure Enclave.

All integers are big-endian.

## Backends

A device keeps its keys in one of three backends:

| Key | Software | Passphrase | Secure Enclave (macOS) |
| --- | --- | --- | --- |
| Wrapping | X25519, in the key file | X25519, sealed in the key file | P-256, in the Secure Enclave |
| Signing | Ed25519, in the key file | Ed25519, sealed in the key file | P-256, in the Secure Enclave |
| Local key ([records.md](records.md#local-store)) | In the key file | Sealed in the key file | In the key file, wrapped to the Secure Enclave wrapping key |

`openvault init` uses the Secure Enclave when the Mac has one, and a passphrase otherwise: Linux, Windows and WSL until TPM support (design §12). Software keys are for a device that must open the vault with nobody there to type a passphrase, such as a container. A device's backend is fixed when its keys are created. Moving to another backend means new device keys.

| Threat | Software | Passphrase | Secure Enclave |
| --- | --- | --- | --- |
| Someone copies the key file, or a backup of it | They have the keys | They need the passphrase, and each guess costs an Argon2id run | Useless on any other Mac |
| Malware running as you | Can copy the keys | Can copy the file and record the passphrase as you type it | Can use the keys while it runs on this Mac, but can't copy them |

## Key file

Each device has one key file, separate from the vault database. It is created only if it doesn't already exist, with mode 0600. Loading refuses a file that the group or other users can read, as `ssh` does, and any file over 16 KiB.

```
magic  "openvault v1 keys" ‖ 0x00   18 bytes
kind                                 1 byte
body
```

**Kind `0x01`, software keys.** The body has fixed lengths, using the private-key encodings in crypto.md:

| Field | Length |
| --- | --- |
| Wrapping private key (`kem_id ‖ key`) | 34 |
| Signing private key (`alg ‖ key`) | 33 |
| Local key | 32 |

**Kind `0x02`, Secure Enclave keys.** The body is three fields, each written as `u16 length ‖ bytes`:

| Field | Length |
| --- | --- |
| Wrapping key blob | about 280 |
| Signing key blob | about 280 |
| Local key, wrapped | 115 |

The local key is wrapped with HPKE as in crypto.md, to the Secure Enclave wrapping key, with context `"device local key"`. Collection contexts are always 36 bytes, so this context can't be confused with one.

**Kind `0x03`, passphrase-protected software keys.** The body has fixed lengths:

| Field | Length |
| --- | --- |
| Argon2id memory in KiB (u32) | 4 |
| Argon2id passes (u32) | 4 |
| Argon2id lanes (u32) | 4 |
| Salt | 16 |
| Sealed keys | 139 |

- The sealed keys are a kind `0x01` body (99 bytes), sealed as in crypto.md under the key derived from the passphrase, the cost and the salt (crypto.md, passphrases).
- The AAD is everything before the sealed keys: the magic, the kind, the cost and the salt, 47 bytes. Changing the cost or the salt makes the file fail to open.
- The file is 186 bytes. New files use the default cost in crypto.md.
- A cost over crypto.md's limits is refused before the passphrase is asked for.
- A wrong passphrase and a damaged file fail in the same way, and can't be told apart.

Creating a key file writes it and then loads it back. A key that won't restore is caught before anything is encrypted to it.

## Passphrases

**Choosing one.**
- `openvault init` asks for the passphrase twice, before it creates anything.
- It must be at least 12 characters and at most 1024 bytes of UTF-8.
- It's used as typed, with no Unicode normalization. It never leaves the device, so it's always typed on the same keyboard and system.

**Unlocking.**
- `openvault` asks for the passphrase on the terminal itself (`/dev/tty`), not on stdin, so commands that read stdin, such as `import-env -`, still work.
- After three wrong passphrases the command stops.
- With no terminal, the command fails and says so. Nothing reads a passphrase from an environment variable or a file, where it would sit next to the key file it protects.
- For now every command asks. Once `openvault service` runs (M2), it asks once and keeps the keys while it runs.

**Forgetting it.** A forgotten passphrase can't be recovered, so the device is treated as lost. Its collections are still on the other devices and wrapped to the recovery key. It joins again as a new device, and the old one is revoked.

## Secure Enclave

**Keys.**
- Created with `SecKeyCreateRandomKey`:
  - `kSecAttrTokenID` is `kSecAttrTokenIDSecureEnclave`.
  - The key is not permanent.
  - Access control is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` with `privateKeyUsage`.
- No user presence is required. Device keys are used on every read, and Touch ID is kept for the admin key (below).
- The keys work only after the first unlock since boot. They then keep working while the screen is locked, so `openvault run` works in jobs on a locked Mac mini.

**Storage.**
- The keys aren't in the keychain. A Secure Enclave key there needs the data protection keychain and a `keychain-access-groups` entitlement, which needs a signed app with a provisioning profile.
- A binary built with cargo gets `errSecMissingEntitlement` (-34018) instead.
- Each key's blob (its token object id) is encrypted by the Secure Enclave and useless on any other Mac, so it is stored in the key file.

**Restoring.**
- `SecKeyCreateWithData` restores a key from:
  - `kSecAttrTokenID` set to `kSecAttrTokenIDSecureEnclave`
  - the blob as `kSecAttrTokenOID` (`"toid"`)
- Apple declares `kSecAttrTokenOID` only in its private `SecItemPriv.h`.
- CryptoKit's `SecureEnclave.P256.*.PrivateKey(dataRepresentation:)` accepts the same blob, and its `dataRepresentation` restores here. Both directions were checked on macOS 26.
- If Apple changes the attribute, a small Swift shim using CryptoKit can read the same key files. The Apple apps (M5) can use CryptoKit directly.

**Signing.**
- `kSecKeyAlgorithmECDSASignatureMessageX962SHA256` over `signing_input` (crypto.md).
- The DER result is converted to `r ‖ s`.

**Unwrapping.**
- The Secure Enclave computes the ECDH x-coordinate (`kSecKeyAlgorithmECDHKeyExchangeStandard`).
- `openvault-crypto` runs the rest of HPKE (crypto.md, hardware keys).

## Admin key

The device that administers the vault, the MacBook in design §12, has an admin key that signs membership log entries (membership.md). `openvault init` creates one on a Mac with a Secure Enclave, and genesis lists it next to the recovery admin key. Devices without a Secure Enclave get none, and sign as admin with the recovery phrase.

**The key.**
- A P-256 Secure Enclave key, created and restored as above.
- Its access control is `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with `privateKeyUsage` and `userPresence`. Every signature needs Touch ID, an Apple Watch, or the Mac's password, and the Mac must be unlocked.
- `userPresence` rather than `biometryAny`, so a MacBook used closed, with a keyboard that has no Touch ID, can still sign with the password.

**What the dialog says.** Each signature restores the key with an `LAContext` passed as `kSecUseAuthenticationContext`. The context's `localizedReason` says what is being signed, such as "create the collection ssh", so a request nobody made stands out (design §4, known limits). Restoring the key and reading its public key don't ask for anything; only signing does.

**One approval, one prompt.**
- An approval that signs several things asks once. A join, for example, signs add_device and its set_scope entries; a revocation signs rotate_epoch entries and grants too.
- The `LAContext` is authenticated once, with a reason that names the whole approval, and is then passed to every signature in it.
- In `crates/keystore`, an `AdminKey` restores its key with one context on its first signature and signs every later one with that key, so one approval uses one `AdminKey`.
- Checked on a MacBook with macOS 26 on 2026-11-07: `cargo test -p openvault-keystore -- --ignored` signs three times and asks once.

**The admin key file.** It sits next to the key file, as `admin` in the `openvault` directory, with the same rules: created only if absent, mode 0600, refused if others can read it or if it's over 16 KiB.

```
magic  "openvault v1 admin key" ‖ 0x00   23 bytes
kind   0x02 (Secure Enclave)              1 byte
blob   u16 length ‖ bytes
```

It has its own file because only an administering device has one, and so the key file format stays as it is. Creating the file loads it back, as for key files.

## Not in v1

- Changing a key file's passphrase. Until then, a device that needs a new passphrase joins again as a new device.
- TPM and Windows Hello.
- Adding an admin key to a vault created without one, or making another device an admin. Both are an add_admin entry (membership.md), signed separately from a join (join.md, not in v1).
- The transport key is derived from the local key (records.md, local store), so the key file doesn't hold one.
