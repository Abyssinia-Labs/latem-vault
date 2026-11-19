# ADR 0001: HPKE for key wrapping

Status: accepted, 2026-11-04. Implemented in `crates/crypto` ([crypto.md](../spec/crypto.md#key-wrapping)). Settles [design §19.1](../design.md#19-open-decisions).

## Context

Every collection key is wrapped once for each device that can read the collection, and once for the recovery key. Devices with a Secure Enclave or TPM hold P-256 keys that never leave the hardware; other devices and the recovery key use X25519. The wrapped keys pass through the coordinator, so the wrapping has to be public-key encryption that an untrusted party can carry but not open.

The two candidates were HPKE (RFC 9180) and age.

## Decision

Use HPKE in base mode: DHKEM(P-256) or DHKEM(X25519), HKDF-SHA256 and ChaCha20-Poly1305. `info` binds the vault, collection and key epoch, so a wrapped key copied to another collection or epoch doesn't unwrap.

## Consequences

- One standard covers both curves. A device's keystore decides the curve, and the format records it in the `kem_id` prefix.
- Hardware keys work without a helper process. The Secure Enclave computes only the ECDH, and the crate does the rest of RFC 9180. That code decrypts RFC 9180 test vector A.5.1 and matches the `hpke` crate.
- age would have needed `age-plugin-se` for Secure Enclave keys, and a plugin protocol between PinkVault and a separate binary. It has no native P-256 recipient.
- Wrapped keys aren't age files, so the `age` command can't open them. That was never a goal.
- Post-quantum wrapping remains open ([crypto.md](../spec/crypto.md#open-questions)). The `hpke` crate supports hybrid KEMs, and the `kem_id` prefix leaves room to add one.
