//! Keys derived from a passphrase with Argon2id (RFC 9106), for passphrase-protected key files
//! (crypto.md, passphrases).

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use crate::hash::{contexts, derive_key};
use crate::{Error, SymmetricKey};

pub const SALT_LEN: usize = 16;

/// Argon2id's cost, stored next to the salt so that new files can use a higher one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassphraseCost {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl PassphraseCost {
    /// RFC 9106's second recommended option: 64 MiB, 3 passes, 4 lanes.
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        passes: 3,
        lanes: 4,
    };

    /// The most a reader accepts, so a damaged file can't make opening it use unbounded memory
    /// or time.
    pub const MAX: Self = Self {
        memory_kib: 1024 * 1024,
        passes: 16,
        lanes: 16,
    };

    /// Fails if Argon2id can't run with this cost, or it's over [`MAX`](Self::MAX).
    pub fn check(self) -> Result<(), Error> {
        self.params().map(|_| ())
    }

    fn params(self) -> Result<Params, Error> {
        let max = Self::MAX;
        if self.memory_kib > max.memory_kib || self.passes > max.passes || self.lanes > max.lanes {
            return Err(Error::Encoding("passphrase cost"));
        }
        Params::new(self.memory_kib, self.passes, self.lanes, Some(32))
            .map_err(|_| Error::Encoding("passphrase cost"))
    }
}

/// `BLAKE3.derive_key("openvault v1 passphrase key", Argon2id(passphrase, salt, cost))`.
pub fn passphrase_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    cost: PassphraseCost,
) -> Result<SymmetricKey, Error> {
    let params = cost.params()?;
    // Our own memory, so that it's wiped afterwards: argon2 frees its own without wiping it.
    let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
    let mut output = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(passphrase, salt, output.as_mut(), &mut memory[..])
        .map_err(|_| Error::Encoding("passphrase"))?;
    Ok(SymmetricKey::from_bytes(*derive_key(
        contexts::PASSPHRASE,
        output.as_ref(),
    )))
}

#[cfg(test)]
mod tests {
    use argon2::{AssociatedData, ParamsBuilder};

    use super::*;

    /// RFC 9106 §5.3, which uses a secret and associated data that OpenVault doesn't.
    #[test]
    fn argon2id_matches_rfc_9106() {
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[4; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let mut memory = vec![Block::default(); params.block_count()];
        let argon2 =
            Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut tag = [0u8; 32];
        argon2
            .hash_password_into_with_memory(&[1; 32], &[2; 16], &mut tag, &mut memory[..])
            .unwrap();
        assert_eq!(
            hex::encode(tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    /// Pinned in crypto.md, so another implementation can check its derivation.
    #[test]
    fn passphrase_key_is_pinned() {
        let key = passphrase_key(
            b"correct horse battery staple",
            &[2; SALT_LEN],
            PassphraseCost::DEFAULT,
        )
        .unwrap();
        assert_eq!(
            hex::encode(key.as_bytes()),
            "2882f895c36955f501c6b434ce888dff79310a1fa7dce2a8b4f8292d0ba2b107"
        );
    }

    #[test]
    fn costs_are_bounded() {
        PassphraseCost::DEFAULT.check().unwrap();
        PassphraseCost::MAX.check().unwrap();
        let max = PassphraseCost::MAX;
        for cost in [
            PassphraseCost {
                memory_kib: max.memory_kib + 1,
                ..max
            },
            PassphraseCost {
                passes: max.passes + 1,
                ..max
            },
            PassphraseCost {
                lanes: max.lanes + 1,
                ..max
            },
            PassphraseCost {
                passes: 0,
                ..PassphraseCost::DEFAULT
            },
            PassphraseCost {
                lanes: 0,
                ..PassphraseCost::DEFAULT
            },
            PassphraseCost {
                memory_kib: 7,
                ..PassphraseCost::DEFAULT
            },
        ] {
            assert_eq!(
                cost.check(),
                Err(Error::Encoding("passphrase cost")),
                "{cost:?}"
            );
        }
    }

    #[test]
    fn salt_and_passphrase_change_the_key() {
        let cheap = PassphraseCost {
            memory_kib: 64,
            passes: 1,
            lanes: 1,
        };
        let key = |passphrase: &[u8], salt| {
            *passphrase_key(passphrase, &[salt; SALT_LEN], cheap)
                .unwrap()
                .as_bytes()
        };
        assert_eq!(key(b"a passphrase", 1), key(b"a passphrase", 1));
        assert_ne!(key(b"a passphrase", 1), key(b"a passphrase", 2));
        assert_ne!(key(b"a passphrase", 1), key(b"another passphrase", 1));
    }
}
