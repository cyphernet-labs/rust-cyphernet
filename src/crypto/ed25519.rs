use ::ed25519::x25519;
use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

use super::*;

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref)]
pub struct SharedSecret([u8; 32]);

impl Ecdh for PrivateKey {
    type Secret = SharedSecret;
    type Err = ::ed25519::Error;

    fn ecdh(&self, pk: &PublicKey) -> Result<SharedSecret, ::ed25519::Error> {
        let xpk = x25519::PublicKey::from_ed25519(&pk.0)?;
        let xsk = x25519::SecretKey::from_ed25519(&self.0)?;
        let ss = xpk.dh(&xsk)?;
        Ok(SharedSecret(*ss))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(into = "String", try_from = "String")
)]
pub struct PublicKey(#[from] ::ed25519::PublicKey);

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.as_ref().partial_cmp(other.0.as_ref())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

impl PublicKey {
    /// Multicodec key type for Ed25519 keys.
    pub const MULTICODEC_TYPE: [u8; 2] = [0xED, 0x1];

    /// Encode public key in human-readable format.
    ///
    /// We use the format specified by the DID `key` method, which is described as:
    ///
    /// `did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))`
    ///
    pub fn to_human(&self) -> String {
        let mut buf = [0; 2 + ::ed25519::PublicKey::BYTES];
        buf[..2].copy_from_slice(&Self::MULTICODEC_TYPE);
        buf[2..].copy_from_slice(self.0.deref());

        multibase::encode(multibase::Base::Base58Btc, &buf)
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self, ::ed25519::Error> {
        ::ed25519::PublicKey::from_pem(pem).map(Self)
    }

    #[cfg(feature = "pem")]
    pub fn from_der(der: &[u8]) -> Result<Self, ::ed25519::Error> {
        ::ed25519::PublicKey::from_der(der).map(Self::from)
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> String {
        self.0.to_pem()
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(other: [u8; 32]) -> Self {
        Self(::ed25519::PublicKey::new(other))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = ::ed25519::Error;

    fn try_from(other: &[u8]) -> Result<Self, Self::Error> {
        ::ed25519::PublicKey::from_slice(other).map(Self)
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum PublicKeyError {
    /// invalid length {0}
    InvalidLength(usize),

    /// invalid multibase string {0}
    #[from]
    Multibase(multibase::Error),

    /// invalid multicodec prefix, expected {0:?}
    Multicodec([u8; 2]),

    /// invalid key {0}
    #[from]
    InvalidKey(::ed25519::Error),
}

impl EcPk for PublicKey {
    fn generator() -> Self {
        // TODO: Fixme
        PublicKey(::ed25519::PublicKey::new([0u8; 32]))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_human())
    }
}

impl FromStr for PublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, bytes) = multibase::decode(s)?;

        if let Some(bytes) = bytes.strip_prefix(&Self::MULTICODEC_TYPE) {
            let key = ::ed25519::PublicKey::from_slice(bytes)?;

            Ok(Self(key))
        } else {
            Err(PublicKeyError::Multicodec(Self::MULTICODEC_TYPE))
        }
    }
}

impl From<PublicKey> for String {
    fn from(other: PublicKey) -> Self {
        other.to_human()
    }
}

impl TryFrom<String> for PublicKey {
    type Error = PublicKeyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, From)]
pub struct PrivateKey(#[from] ::ed25519::SecretKey);

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrivateKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl EcSk for PrivateKey {
    type Pk = PublicKey;

    fn to_pk(&self) -> PublicKey {
        self.0.public_key().into()
    }
}

impl PrivateKey {
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self, ::ed25519::Error> {
        ::ed25519::SecretKey::from_pem(pem).map(Self::from)
    }

    #[cfg(feature = "pem")]
    pub fn from_der(der: &[u8]) -> Result<Self, ::ed25519::Error> {
        ::ed25519::SecretKey::from_der(der).map(Self::from)
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> String {
        self.0.to_pem()
    }

    #[cfg(feature = "rand")]
    pub fn test() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut key);
        ::ed25519::SecretKey::new(key).into()
    }
}

/// Cryptographic signature.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Signature(::ed25519::Signature);

impl From<::ed25519::Signature> for Signature {
    fn from(other: ::ed25519::Signature) -> Self {
        Self(other)
    }
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(::ed25519::Signature::new(bytes))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = ::ed25519::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ::ed25519::Signature::from_slice(bytes).map(Self)
    }
}

/*
impl EcSig for Signature {
    type Sk = PrivateKey;
    type Pk = PublicKey;

    fn sign(self, sk: &PrivateKey, msg: impl AsRef<[u8]>) -> Self {
        sk.0.sign(msg, None).into()
    }

    fn verify(self, pk: &PublicKey, msg: impl AsRef<[u8]>) -> bool {
        pk.0.verify(msg, &self.0).is_ok()
    }
}
*/

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SignatureError {
    /// invalid multibase string: {0}
    #[from]
    Multibase(multibase::Error),

    /// invalid signature: {0}
    #[from]
    Invalid(::ed25519::Error),
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let base = multibase::Base::Base58Btc;
        write!(f, "{}", multibase::encode(base, self.0))
    }
}

impl FromStr for Signature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, bytes) = multibase::decode(s)?;
        let sig = ::ed25519::Signature::from_slice(bytes.as_slice())?;

        Ok(Self(sig))
    }
}

#[cfg(test)]
mod test {
    use super::PublicKey;
    use quickcheck_macros::quickcheck;
    use std::str::FromStr;

    #[quickcheck]
    fn prop_encode_decode(input: PublicKey) {
        let encoded = input.to_string();
        let decoded = PublicKey::from_str(&encoded).unwrap();

        assert_eq!(input, decoded);
    }

    #[test]
    fn test_encode_decode() {
        let input = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let key = PublicKey::from_str(input).unwrap();

        assert_eq!(key.to_string(), input);
    }
}
