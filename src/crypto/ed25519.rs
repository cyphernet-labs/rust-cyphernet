// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2022-2023 Cyphernet Association, Switzerland
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Edwards25519 curve keys and EdDSA algorithm implementation for Ed25519 scheme.


/// Cryptographic signature.
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[wrapper(Deref)]
pub struct Signature(::ed25519::Signature);

impl From<::ed25519::Signature> for Signature {
    fn from(other: ::ed25519::Signature) -> Self { Self(other) }
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self { Self(::ed25519::Signature::new(bytes)) }
}

impl TryFrom<&[u8]> for Signature {
    type Error = ::ed25519::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ::ed25519::Signature::from_slice(bytes).map(Self)
    }
}

pub trait Sign: EcSk {
    type Sig: Sized;

    fn sign(&self, msg: impl AsRef<[u8]>) -> Self::Sig;
}

impl Sign for PrivateKey {
    type Sig = Signature;

    fn sign(&self, msg: impl AsRef<[u8]>) -> Signature { self.0.sign(msg, None).into() }

    /*
    fn verify(self, pk: &PublicKey, msg: impl AsRef<[u8]>) -> bool {
        pk.0.verify(msg, &self.0).is_ok()
    }
     */
}

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


// ============================================================================
// Display and from string

#[cfg(feature = "multibase")]
mod human_readable {
    pub use super::*;

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
        InvalidKey(ed25519_compact::Error),
    }

    impl PublicKey {
        /// Multicodec key type for Ed25519 keys.
        pub const MULTICODEC_TYPE: [u8; 2] = [0xED, 0x1];

        /// Encode public key in human-readable format.
        ///
        /// We use the format specified by the DID `key` method, which is described as:
        ///
        /// `did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))`
        pub fn to_human_readable(&self) -> String {
            let mut buf = [0; 2 + ::ed25519::PublicKey::BYTES];
            buf[..2].copy_from_slice(&Self::MULTICODEC_TYPE);
            buf[2..].copy_from_slice(self.0.deref());

            multibase::encode(multibase::Base::Base58Btc, buf)
        }
    }

    impl Display for PublicKey {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { f.write_str(&self.to_human()) }
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
        fn from(other: PublicKey) -> Self { other.to_human() }
    }

    impl TryFrom<String> for PublicKey {
        type Error = PublicKeyError;

        fn try_from(value: String) -> Result<Self, Self::Error> { Self::from_str(&value) }
    }
}

#[cfg(feature = "pem")]
mod pem_der {
    use super::*;

    impl PublicKey {
        pub fn from_pem(pem: &str) -> Result<Self, ::ed25519::Error> {
            ::ed25519::PublicKey::from_pem(pem).map(Self)
        }

        pub fn from_der(der: &[u8]) -> Result<Self, ::ed25519::Error> {
            ::ed25519::PublicKey::from_der(der).map(Self::from)
        }

        pub fn to_pem(&self) -> String { self.0.to_pem() }
    }

    impl PrivateKey {
        pub fn from_pem(pem: &str) -> Result<Self, ::ed25519::Error> {
            ::ed25519::SecretKey::from_pem(pem).map(Self::from)
        }

        pub fn from_der(der: &[u8]) -> Result<Self, ::ed25519::Error> {
            ::ed25519::SecretKey::from_der(der).map(Self::from)
        }

        pub fn to_pem(&self) -> String { self.0.to_pem() }
    }
}
