//! Wire and storage identifiers that keep the name `openvault` for ever.
//!
//! These are not branding. Every signature, derived key, wrapped key, key file and chunk in
//! an existing vault is bound to one of the labels below, and devices find and speak to each
//! other by the protocol IDs and the mDNS service name. Changing any byte here silently makes
//! every existing vault unreadable, or splits updated devices from the rest.
//!
//! The rename of OpenVault to latem vault (plan:
//! <https://antescript.app/w/abyssinia-labs/p/jd70wt3fam8pjbq484wxksj03h8jdct5>, OV-10)
//! leaves all of them as they are, and so must any later rename. The mDNS name stays by
//! decision D4. The test at the bottom pins each value as hex, so a find-and-replace of the
//! name fails CI instead of breaking vaults.
//!
//! They live in this crate because every other crate depends on it. The places that use them
//! re-export them under their own names (`hash::contexts`, `net::sync::ALPN`,
//! `net::MDNS_SERVICE`, …).

/// Context strings for BLAKE3's key derivation mode ([`crate::hash::derive_key`]), re-exported
/// as [`crate::hash::contexts`]. Changing one changes every key derived from it.
pub mod contexts {
    pub const RECOVERY_ADMIN_SIGNING: &str = "openvault v1 recovery admin signing key";
    pub const RECOVERY_WRAPPING: &str = "openvault v1 recovery wrapping key";
    pub const RECORD_ID: &str = "openvault v1 record id";
    pub const LOG_ENTRY_HASH: &str = "openvault v1 log entry hash";
    pub const LOCAL_INDEX: &str = "openvault v1 local index key";
    pub const LOCAL_CACHE: &str = "openvault v1 local cache key";
    pub const TRANSPORT: &str = "openvault v1 transport key";
    pub const PASSPHRASE: &str = "openvault v1 passphrase key";
    pub const JOIN_CONFIRM_JOINER: &str = "openvault v1 join confirm joiner";
    pub const JOIN_CONFIRM_ADMIN: &str = "openvault v1 join confirm admin";
    pub const JOIN_SESSION: &str = "openvault v1 join session";
    pub const GRANT_ID: &str = "openvault v1 grant id";
    pub const SYNC_FINGERPRINT: &str = "openvault v1 sync fingerprint";
    pub const CHUNK_KEY: &str = "openvault v1 chunk key";
    pub const CHUNK_NONCE_KEY: &str = "openvault v1 chunk nonce key";
    pub const CHUNK_ID: &str = "openvault v1 chunk id";
}

/// Signature context labels: a signer signs `label || 0x00 || message`
/// ([`crate::sign::signing_input`]).
pub const SIG_RECORD: &[u8] = b"openvault v1 sig record";
pub const SIG_LOG_ENTRY: &[u8] = b"openvault v1 sig log entry";
pub const SIG_JOIN_REQUEST: &[u8] = b"openvault v1 sig join request";
pub const SIG_KEY_GRANT: &[u8] = b"openvault v1 sig key grant";

/// What an admin key signs to ask for Touch ID ahead of the signatures that need it. It is
/// not a signature context, so it can't pass for any of them.
pub const ADMIN_PRESENCE: &[u8] = b"openvault v1 admin presence";

/// The start of the HPKE `info` for a wrapped key: `WRAP_INFO || context` ([`crate::wrap`]).
pub const WRAP_INFO: &[u8] = b"openvault v1 wrap\0";

/// The start of the SPAKE2 password: `JOIN_CODE || code` ([`crate::pake`]).
pub const JOIN_CODE: &[u8] = b"openvault v1 join code\0";

/// The start of a file chunk's associated data: `CHUNK_AAD || vault || collection || epoch`.
pub const CHUNK_AAD: &[u8] = b"openvault v1 chunk\0";

/// The first bytes of a device's key file.
pub const KEYS_MAGIC: &[u8] = b"openvault v1 keys\0";

/// The first bytes of an admin key file.
pub const ADMIN_KEY_MAGIC: &[u8] = b"openvault v1 admin key\0";

/// The ALPN protocol IDs devices connect with.
pub const ALPN_SYNC: &[u8] = b"openvault/sync/1";
pub const ALPN_JOIN: &[u8] = b"openvault/join/1";
pub const ALPN_COORD: &[u8] = b"openvault/coord/1";
pub const ALPN_CHUNKS: &[u8] = b"openvault/chunks/1";

/// The mDNS service name: endpoints appear as `<endpoint id>._openvault._udp.local.`. Kept
/// through the rename by decision D4.
pub const MDNS_SERVICE: &str = "openvault";

#[cfg(test)]
mod tests {
    use super::contexts::*;
    use super::*;

    /// Every frozen value, pinned as hex rather than as text, so that replacing the name in
    /// the source changes the constant but not the pin. If this fails, put the constant back:
    /// don't change the pin.
    const PINNED: &[(&str, &[u8], &str)] = &[
        (
            "RECOVERY_ADMIN_SIGNING",
            RECOVERY_ADMIN_SIGNING.as_bytes(),
            "6f70656e7661756c74207631207265636f766572792061646d696e207369676e696e67206b6579",
        ),
        (
            "RECOVERY_WRAPPING",
            RECOVERY_WRAPPING.as_bytes(),
            "6f70656e7661756c74207631207265636f76657279207772617070696e67206b6579",
        ),
        (
            "RECORD_ID",
            RECORD_ID.as_bytes(),
            "6f70656e7661756c74207631207265636f7264206964",
        ),
        (
            "LOG_ENTRY_HASH",
            LOG_ENTRY_HASH.as_bytes(),
            "6f70656e7661756c74207631206c6f6720656e7472792068617368",
        ),
        (
            "LOCAL_INDEX",
            LOCAL_INDEX.as_bytes(),
            "6f70656e7661756c74207631206c6f63616c20696e646578206b6579",
        ),
        (
            "LOCAL_CACHE",
            LOCAL_CACHE.as_bytes(),
            "6f70656e7661756c74207631206c6f63616c206361636865206b6579",
        ),
        (
            "TRANSPORT",
            TRANSPORT.as_bytes(),
            "6f70656e7661756c74207631207472616e73706f7274206b6579",
        ),
        (
            "PASSPHRASE",
            PASSPHRASE.as_bytes(),
            "6f70656e7661756c742076312070617373706872617365206b6579",
        ),
        (
            "JOIN_CONFIRM_JOINER",
            JOIN_CONFIRM_JOINER.as_bytes(),
            "6f70656e7661756c74207631206a6f696e20636f6e6669726d206a6f696e6572",
        ),
        (
            "JOIN_CONFIRM_ADMIN",
            JOIN_CONFIRM_ADMIN.as_bytes(),
            "6f70656e7661756c74207631206a6f696e20636f6e6669726d2061646d696e",
        ),
        (
            "JOIN_SESSION",
            JOIN_SESSION.as_bytes(),
            "6f70656e7661756c74207631206a6f696e2073657373696f6e",
        ),
        (
            "GRANT_ID",
            GRANT_ID.as_bytes(),
            "6f70656e7661756c74207631206772616e74206964",
        ),
        (
            "SYNC_FINGERPRINT",
            SYNC_FINGERPRINT.as_bytes(),
            "6f70656e7661756c742076312073796e632066696e6765727072696e74",
        ),
        (
            "CHUNK_KEY",
            CHUNK_KEY.as_bytes(),
            "6f70656e7661756c74207631206368756e6b206b6579",
        ),
        (
            "CHUNK_NONCE_KEY",
            CHUNK_NONCE_KEY.as_bytes(),
            "6f70656e7661756c74207631206368756e6b206e6f6e6365206b6579",
        ),
        (
            "CHUNK_ID",
            CHUNK_ID.as_bytes(),
            "6f70656e7661756c74207631206368756e6b206964",
        ),
        (
            "SIG_RECORD",
            SIG_RECORD,
            "6f70656e7661756c7420763120736967207265636f7264",
        ),
        (
            "SIG_LOG_ENTRY",
            SIG_LOG_ENTRY,
            "6f70656e7661756c7420763120736967206c6f6720656e747279",
        ),
        (
            "SIG_JOIN_REQUEST",
            SIG_JOIN_REQUEST,
            "6f70656e7661756c7420763120736967206a6f696e2072657175657374",
        ),
        (
            "SIG_KEY_GRANT",
            SIG_KEY_GRANT,
            "6f70656e7661756c7420763120736967206b6579206772616e74",
        ),
        (
            "ADMIN_PRESENCE",
            ADMIN_PRESENCE,
            "6f70656e7661756c742076312061646d696e2070726573656e6365",
        ),
        (
            "WRAP_INFO",
            WRAP_INFO,
            "6f70656e7661756c74207631207772617000",
        ),
        (
            "JOIN_CODE",
            JOIN_CODE,
            "6f70656e7661756c74207631206a6f696e20636f646500",
        ),
        (
            "CHUNK_AAD",
            CHUNK_AAD,
            "6f70656e7661756c74207631206368756e6b00",
        ),
        (
            "KEYS_MAGIC",
            KEYS_MAGIC,
            "6f70656e7661756c74207631206b65797300",
        ),
        (
            "ADMIN_KEY_MAGIC",
            ADMIN_KEY_MAGIC,
            "6f70656e7661756c742076312061646d696e206b657900",
        ),
        ("ALPN_SYNC", ALPN_SYNC, "6f70656e7661756c742f73796e632f31"),
        ("ALPN_JOIN", ALPN_JOIN, "6f70656e7661756c742f6a6f696e2f31"),
        (
            "ALPN_COORD",
            ALPN_COORD,
            "6f70656e7661756c742f636f6f72642f31",
        ),
        (
            "ALPN_CHUNKS",
            ALPN_CHUNKS,
            "6f70656e7661756c742f6368756e6b732f31",
        ),
        (
            "MDNS_SERVICE",
            MDNS_SERVICE.as_bytes(),
            "6f70656e7661756c74",
        ),
    ];

    #[test]
    fn frozen_values_never_change() {
        for (name, value, pinned) in PINNED {
            assert_eq!(
                hex::encode(value),
                *pinned,
                "{name} is a wire/storage identifier and must never change (crypto/src/frozen.rs)"
            );
        }
    }

    #[test]
    fn frozen_values_are_distinct() {
        let mut values: Vec<&[u8]> = PINNED.iter().map(|(_, value, _)| *value).collect();
        values.sort();
        values.dedup();
        assert_eq!(values.len(), PINNED.len());
    }
}
