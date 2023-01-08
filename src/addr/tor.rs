// TODO: Make a separate crate

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use base32::Alphabet;
use sha3::Digest;

const ALPHABET: Alphabet = Alphabet::RFC4648 { padding: false };
pub const ONION_V3_RAW_LEN: usize = 35;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(into = "String", try_from = "String")
)]
pub struct OnionAddrV3 {
    pk: ed25519::PublicKey,
    checksum: u16,
}

impl From<ed25519::PublicKey> for OnionAddrV3 {
    fn from(pk: ed25519::PublicKey) -> Self {
        let mut h = sha3::Sha3_256::default();
        h.update(b".onion checksum");
        h.update(&pk[..]);
        h.update(&[3u8]);
        let hash = h.finalize();
        let checksum = u16::from_le_bytes([hash[0], hash[1]]);
        Self { pk, checksum }
    }
}

impl From<OnionAddrV3> for ed25519::PublicKey {
    fn from(onion: OnionAddrV3) -> Self {
        onion.pk
    }
}

impl OnionAddrV3 {
    pub fn into_public_key(self) -> ed25519::PublicKey {
        self.pk
    }

    pub fn into_raw_bytes(self) -> [u8; ONION_V3_RAW_LEN] {
        let mut data = [0u8; ONION_V3_RAW_LEN];
        data[..32].copy_from_slice(self.pk.as_slice());
        data[32..34].copy_from_slice(&self.checksum.to_le_bytes());
        data[ONION_V3_RAW_LEN - 1] = 3;
        data
    }

    pub fn checksum(self) -> u16 {
        self.checksum
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[display(doc_comments)]
pub enum OnionAddrError {
    /// onion address {0} doesn't end with `.onion` suffix.
    NoSuffix(String),

    /// onion address {0} has an invalid base32 encoding.
    InvalidBase32(String),

    /// onion address {0} has an invalid length.
    InvalidLen(String),

    /// version {1} encoded in address {0} doesn't match V3.
    VersionMismatch(String, u8),

    /// onion address {addr} has an invalid checksum {found} instead of {expected}.
    InvalidChecksum {
        expected: u16,
        found: u16,
        addr: String,
    },
}

impl FromStr for OnionAddrV3 {
    type Err = OnionAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s
            .strip_suffix(".onion")
            .ok_or_else(|| OnionAddrError::NoSuffix(s.to_owned()))?;
        let data: Vec<u8> = base32::decode(ALPHABET, stripped)
            .ok_or_else(|| OnionAddrError::InvalidBase32(s.to_owned()))?;
        if data.len() != ONION_V3_RAW_LEN {
            return Err(OnionAddrError::InvalidLen(s.to_owned()));
        }
        let ver = data[ONION_V3_RAW_LEN - 1];
        if ver != 3 {
            return Err(OnionAddrError::VersionMismatch(s.to_owned(), ver));
        }
        let pk =
            OnionAddrV3::from(ed25519::PublicKey::from_slice(&data[..32]).expect("fixed length"));
        let checksum = u16::from_le_bytes([data[32], data[33]]);
        if pk.checksum != checksum {
            return Err(OnionAddrError::InvalidChecksum {
                expected: pk.checksum,
                found: checksum,
                addr: s.to_owned(),
            });
        }
        Ok(pk)
    }
}

impl Display for OnionAddrV3 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let b32 = base32::encode(ALPHABET, &self.into_raw_bytes());
        write!(f, "{}.onion", b32)
    }
}

impl From<OnionAddrV3> for String {
    fn from(other: OnionAddrV3) -> Self {
        other.to_string()
    }
}

impl TryFrom<String> for OnionAddrV3 {
    type Error = OnionAddrError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}
