# Cryptography spec, v1

Status: draft, 2026-11-04. Implemented by `crates/crypto`. The design reasons are in [design §7](../design.md#7-cryptography).

Every format here is versioned by its labels (`openvault v1 …`). A change to any of them is a new version, never an edit.

## Algorithms

| Purpose | Algorithm | Crate |
| --- | --- | --- |
| Records | XChaCha20-Poly1305 | `chacha20poly1305` |
| Wrapping collection keys | HPKE (RFC 9180), base mode | `hpke` |
| Signatures | Ed25519 (strict verification); ECDSA P-256 with SHA-256 | `ed25519-dalek`, `p256` |
| Hashing, key derivation | BLAKE3 (`hash`, `derive_key`) | `blake3` |
| Recovery phrase | BIP-39, English, 24 words | `bip39` |

Key wrapping uses HPKE, as recommended in design §19.1.

Randomness comes from the operating system (`getrandom`). If the OS generator fails, the process stops; nothing continues without randomness.

## Encodings

All integers are big-endian.

| Value | Encoding | Length |
| --- | --- | --- |
| Symmetric key | raw | 32 |
| Sealed value | `nonce (24) ‖ ciphertext ‖ tag (16)` | plaintext + 40 |
| Wrapping public key | `kem_id (2) ‖ public key` | 34 (X25519), 67 (P-256) |
| Wrapping private key (file keystore) | `kem_id (2) ‖ private key (32)` | 34 |
| Wrapped key | `kem_id (2) ‖ enc ‖ ciphertext (48)` | 82 (X25519), 115 (P-256) |
| Verifying key | `alg (1) ‖ public key` | 33 (Ed25519), 66 (P-256) |
| Signing private key (file keystore) | `alg (1) ‖ private key (32)` | 33 |
| Signature | `alg (1) ‖ signature (64)` | 65 |

`kem_id` is the RFC 9180 KEM identifier: `0x0020` DHKEM(X25519, HKDF-SHA256), `0x0010` DHKEM(P-256, HKDF-SHA256). P-256 public keys and `enc` values are uncompressed SEC1 (65 bytes), which is also what Apple's `SecKeyCopyExternalRepresentation` returns.

`alg` is `0x01` for Ed25519 and `0x02` for ECDSA P-256 with SHA-256. ECDSA signatures are fixed-width `r ‖ s`; a hardware signer that returns DER converts before storing.

Decoders reject unknown identifiers, wrong lengths, and public keys that aren't valid points.

## Records

A record body is sealed with the collection key for its epoch. The AAD is the record's cleartext header, without the signature, so moving a body to another header fails to decrypt. The header encoding is part of the record spec (not written yet).

Nonces are random. 192 bits makes a repeat under one key negligible for any number of records a vault will hold.

## Key wrapping

Suite: KEM as above, KDF HKDF-SHA256 (`0x0001`), AEAD ChaCha20-Poly1305 (`0x0003`), mode base.

- `info` = `"openvault v1 wrap" ‖ 0x00 ‖ context`
- `aad` = empty
- plaintext = the 32-byte collection key

`context` identifies what is wrapped: vault id, collection id and key epoch. Its encoding is part of the record spec. Binding it into `info` means a wrapped key copied to another collection or epoch doesn't unwrap.

Devices with a Secure Enclave or TPM use P-256; devices without one, and the recovery key, use X25519.

## Signatures

The signed bytes are `label ‖ 0x00 ‖ message`:

| Context | Label |
| --- | --- |
| Record | `openvault v1 sig record` |
| Membership log entry | `openvault v1 sig log entry` |

Hardware signers sign exactly these bytes (`signing_input` in the crate). For ECDSA, the signer hashes them with SHA-256 (`ecdsaSignatureMessageX962SHA256` on Apple platforms).

Ed25519 verification is strict (`verify_strict`). ECDSA verification accepts both `s` and `n − s`, because the Secure Enclave doesn't normalize `s`. Signatures are therefore malleable, so no id or hash may cover signature bytes: record ids and log entry hashes are computed over the unsigned content.

## Recovery key

256 random bits. Shown as the 24-word BIP-39 English phrase of those bits; parsing ignores case and extra whitespace, requires exactly 24 words and checks the BIP-39 checksum. The BIP-39 seed function (PBKDF2) is not used.

It derives:

| Key | Derivation |
| --- | --- |
| Admin signing key (Ed25519) | seed = `BLAKE3.derive_key("openvault v1 recovery admin signing key", secret)` |
| Wrapping key (X25519) | `DeriveKeyPair(BLAKE3.derive_key("openvault v1 recovery wrapping key", secret))`, RFC 9180 §7.1.3 |

Test vector, secret = 32 zero bytes:

- phrase: `abandon` × 23, then `art`
- admin verifying key: `01f03753c8c8e8effcacd1f79e241ba3cde48deccd826954c7f8ccfa2a114a2557`
- wrapping public key: `0020cae8d02068d12207a480eb7c48b34cfdcd600bc5d279aaf86197e360e62ec20c`

The two key values come from this implementation and are pinned in its tests to catch accidental changes. They haven't been checked against a second implementation.

## Secrets in memory

Symmetric keys, the recovery key and private keys are zeroized on drop, and their `Debug` output is redacted. Decrypted plaintext is returned in `Zeroizing` buffers.

## Open questions

1. **Unwrapping with a Secure Enclave key.** HPKE decapsulation needs the ECDH step to run inside the Secure Enclave. The `hpke` crate expects the private key in memory, so the keystore needs either CryptoKit's HPKE (if it accepts Secure Enclave keys as recipients) or a decapsulation hook that calls `SecKeyCopyKeyExchangeResult` and runs the rest of RFC 9180 in Rust. To be decided in the keystore crate; the wire format above doesn't change either way.
2. **Post-quantum wrapping.** Wrapped collection keys pass through the coordinator and relays and live as long as the vault, so they can be recorded now and attacked later with a quantum computer. The `hpke` crate supports hybrid KEMs (X-Wing; ML-KEM-768 with P-256). The `kem_id` prefix leaves room to add one as a second wrapping per device without changing other formats. The Secure Enclave can't hold the ML-KEM half today.
