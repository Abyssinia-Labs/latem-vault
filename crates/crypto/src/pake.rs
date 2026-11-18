//! The join PAKE (join.md, PAKE): SPAKE2 over Ed25519, keyed by a 6-digit code and bound to
//! both devices' transport keys.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::hash::{contexts, derive_key};
use crate::{Error, VerifyingKey, random_bytes};

/// A SPAKE2 message: a side byte and a point.
pub const MESSAGE_LEN: usize = 33;

/// Which side of the PAKE this device is: the admin is SPAKE2's side A, the joiner side B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Admin,
    Joiner,
}

/// A PAKE in progress, waiting for the other side's message.
pub struct Pake(Spake2<Ed25519Group>);

/// What both sides derive from the PAKE's key when they used the same code.
pub struct JoinKeys {
    pub joiner_confirm: Zeroizing<[u8; 32]>,
    pub admin_confirm: Zeroizing<[u8; 32]>,
    pub session_id: Zeroizing<[u8; 32]>,
}

impl Pake {
    /// Starts the PAKE for `code` between the admin's and the joiner's transport keys. Returns
    /// the message to send.
    pub fn start(
        side: Side,
        code: &str,
        admin_transport: &VerifyingKey,
        joiner_transport: &VerifyingKey,
    ) -> Result<(Self, [u8; MESSAGE_LEN]), Error> {
        check_code(code)?;
        let password = Zeroizing::new([crate::frozen::JOIN_CODE, code.as_bytes()].concat());
        let password = Password::new(&*password);
        let id_a = Identity::new(admin_transport.as_bytes());
        let id_b = Identity::new(joiner_transport.as_bytes());
        let (pake, message) = match side {
            Side::Admin => Spake2::<Ed25519Group>::start_a(&password, &id_a, &id_b),
            Side::Joiner => Spake2::<Ed25519Group>::start_b(&password, &id_a, &id_b),
        };
        let message = message
            .try_into()
            .expect("SPAKE2 over Ed25519 messages are 33 bytes");
        Ok((Self(pake), message))
    }

    /// Finishes with the other side's message. A different code still finishes, with keys that
    /// don't match, which the confirmations reveal.
    pub fn finish(self, peer: &[u8]) -> Result<JoinKeys, Error> {
        let key = Zeroizing::new(
            self.0
                .finish(peer)
                .map_err(|_| Error::Encoding("PAKE message"))?,
        );
        Ok(JoinKeys {
            joiner_confirm: derive_key(contexts::JOIN_CONFIRM_JOINER, &key),
            admin_confirm: derive_key(contexts::JOIN_CONFIRM_ADMIN, &key),
            session_id: derive_key(contexts::JOIN_SESSION, &key),
        })
    }
}

/// Compares a received confirmation in constant time.
pub fn confirmation_matches(expected: &[u8; 32], received: &[u8]) -> bool {
    received.len() == 32 && bool::from(expected.ct_eq(received))
}

/// A new join code: six decimal digits, uniform, from the OS random generator.
pub fn new_code() -> String {
    // The largest multiple of a million that fits in a u32, so the remainder is uniform.
    const LIMIT: u32 = u32::MAX - u32::MAX % 1_000_000;
    loop {
        let value = u32::from_be_bytes(*random_bytes::<4>());
        if value < LIMIT {
            return format!("{:06}", value % 1_000_000);
        }
    }
}

fn check_code(code: &str) -> Result<(), Error> {
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(Error::Encoding("join code"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKey;

    fn keys() -> (VerifyingKey, VerifyingKey) {
        (
            SigningKey::from_ed25519_seed(&[1; 32]).verifying_key(),
            SigningKey::from_ed25519_seed(&[2; 32]).verifying_key(),
        )
    }

    fn run(admin_code: &str, joiner_code: &str) -> (JoinKeys, JoinKeys) {
        let (admin_key, joiner_key) = keys();
        let (admin, to_joiner) =
            Pake::start(Side::Admin, admin_code, &admin_key, &joiner_key).unwrap();
        let (joiner, to_admin) =
            Pake::start(Side::Joiner, joiner_code, &admin_key, &joiner_key).unwrap();
        (
            admin.finish(&to_admin).unwrap(),
            joiner.finish(&to_joiner).unwrap(),
        )
    }

    #[test]
    fn the_same_code_gives_the_same_keys() {
        let (admin, joiner) = run("123456", "123456");
        assert!(confirmation_matches(
            &admin.joiner_confirm,
            &joiner.joiner_confirm[..]
        ));
        assert!(confirmation_matches(
            &joiner.admin_confirm,
            &admin.admin_confirm[..]
        ));
        assert_eq!(*admin.session_id, *joiner.session_id);
        assert_ne!(*admin.joiner_confirm, *admin.admin_confirm);
        assert_ne!(*admin.session_id, *admin.joiner_confirm);
    }

    #[test]
    fn a_different_code_or_identity_gives_different_keys() {
        let (admin, joiner) = run("123456", "123457");
        assert!(!confirmation_matches(
            &admin.joiner_confirm,
            &joiner.joiner_confirm[..]
        ));

        // A man in the middle has its own transport key toward one side.
        let (admin_key, joiner_key) = keys();
        let other = SigningKey::from_ed25519_seed(&[3; 32]).verifying_key();
        let (admin, to_joiner) = Pake::start(Side::Admin, "123456", &admin_key, &other).unwrap();
        let (joiner, to_admin) =
            Pake::start(Side::Joiner, "123456", &admin_key, &joiner_key).unwrap();
        let (admin, joiner) = (
            admin.finish(&to_admin).unwrap(),
            joiner.finish(&to_joiner).unwrap(),
        );
        assert!(!confirmation_matches(
            &admin.joiner_confirm,
            &joiner.joiner_confirm[..]
        ));
    }

    #[test]
    fn rejects_bad_codes_and_messages() {
        let (admin_key, joiner_key) = keys();
        for code in ["12345", "1234567", "12345a", "١٢٣٤٥٦"] {
            assert!(
                Pake::start(Side::Admin, code, &admin_key, &joiner_key).is_err(),
                "{code}"
            );
        }
        let (admin, _) = Pake::start(Side::Admin, "000000", &admin_key, &joiner_key).unwrap();
        // A message from the same side, as a reflected message would be.
        let (_, also_admin) = Pake::start(Side::Admin, "000000", &admin_key, &joiner_key).unwrap();
        assert!(admin.finish(&also_admin).is_err());
        assert!(!confirmation_matches(&[0; 32], &[0; 31]));
    }

    #[test]
    fn codes_are_six_digits() {
        for _ in 0..100 {
            let code = new_code();
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
