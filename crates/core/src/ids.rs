use std::fmt;
use std::str::FromStr;

use crate::Error;

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            pub fn random() -> Self {
                Self(*openvault_crypto::random_bytes())
            }

            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                bytes.try_into().map(Self).map_err(|_| Error::InvalidId)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self, Error> {
                let mut bytes = [0u8; 16];
                hex::decode_to_slice(s, &mut bytes).map_err(|_| Error::InvalidId)?;
                Ok(Self(bytes))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self)
            }
        }
    };
}

id_type!(
    /// Identifies a vault: one person's membership log and collections.
    VaultId
);
id_type!(
    /// Identifies a device. Assigned when its keys are created; survives key rotation.
    DeviceId
);
id_type!(
    /// Identifies a collection.
    CollectionId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let id = CollectionId::random();
        assert_eq!(id.to_string().len(), 32);
        assert_eq!(id.to_string().parse::<CollectionId>().unwrap(), id);
        assert!("abc".parse::<CollectionId>().is_err());
        assert!(CollectionId::try_from(&[0u8; 15][..]).is_err());
    }
}
