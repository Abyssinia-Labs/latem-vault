# Keystore spec, v1

Status: draft, 2026-11-04. Implemented by `crates/keystore`. Builds on [crypto.md](crypto.md); the device keys are in [design §7](../design.md#device-keys).

All integers are big-endian.

## Backends

A device keeps its keys in one of two backends:

| Key | Software | Secure Enclave (macOS) |
| --- | --- | --- |
| Wrapping | X25519, in the key file | P-256, in the Secure Enclave |
| Signing | Ed25519, in the key file | P-256, in the Secure Enclave |
| Local key ([records.md](records.md#local-store)) | In the key file | In the key file, wrapped to the Secure Enclave wrapping key |

`openvault init` uses the Secure Enclave when the Mac has one, and software keys otherwise. A device's backend is fixed when its keys are created. Moving to another backend means new device keys.

| Threat | Software | Secure Enclave |
| --- | --- | --- |
| Someone copies the key file, or a backup of it | They have the keys | Useless on any other Mac |
| Malware running as you | Can copy the keys | Can use the keys while it runs on this Mac, but can't copy them |

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

Creating a key file writes it and then loads it back. A key that won't restore is caught before anything is encrypted to it.

## Secure Enclave

**Keys.**
- Created with `SecKeyCreateRandomKey`:
  - `kSecAttrTokenID` is `kSecAttrTokenIDSecureEnclave`.
  - The key is not permanent.
  - Access control is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` with `privateKeyUsage`.
- No user presence is required. Device keys are used on every read, and Touch ID is kept for the admin key (M2).
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

## Not in v1

- **Passphrase-protected key files** for Linux, Windows and WSL (design §12). This will be a new kind whose body is sealed with a key derived from the passphrase with Argon2id. It comes with the first Linux device in M2.
- TPM and Windows Hello.
- The transport key and the admin key, both in M2.
