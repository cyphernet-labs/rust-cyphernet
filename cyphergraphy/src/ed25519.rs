// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2022-2023 Cyphernet Initiative, Switzerland
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

use std::cmp::Ordering;
use std::ops::Deref;

use crate::display::{Encoding, MultiDisplay};
use crate::{EcPk, EcPkInvalid, EcSig, EcSigInvalid, EcSign, EcSk, EcSkInvalid, EcVerifyError};

// ============================================================================
// ed25519_compact keys

impl MultiDisplay<Encoding> for ed25519_compact::PublicKey {
    type Display = String;
    fn display_fmt(&self, f: &Encoding) -> Self::Display { f.encode(self.as_slice()) }
}

impl EcPk for ed25519_compact::PublicKey {
    const COMPRESSED_LEN: usize = 32;
    const CURVE_NAME: &'static str = "Curve25519";
    type Compressed = [u8; 32];

    fn base_point() -> Self {
        ed25519_compact::PublicKey::from_slice(
            &[
                0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                0x66, 0x66, 0x66, 0x66,
            ][..],
        )
        .expect("hardcoded basepoint value")
    }

    fn to_pk_compressed(&self) -> Self::Compressed { *self.deref() }

    fn from_pk_compressed(pk: Self::Compressed) -> Result<Self, EcPkInvalid> {
        Ok(ed25519_compact::PublicKey::new(pk))
    }

    fn from_pk_compressed_slice(slice: &[u8]) -> Result<Self, EcPkInvalid> {
        if slice.len() != Self::COMPRESSED_LEN {
            return Err(EcPkInvalid {});
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(slice);
        Self::from_pk_compressed(buf)
    }
}

impl EcSk for ed25519_compact::SecretKey {
    type Pk = ed25519_compact::PublicKey;

    fn generate_keypair() -> (Self, Self::Pk)
    where Self: Sized {
        let pair = ed25519_compact::KeyPair::generate();
        (pair.sk, pair.pk)
    }

    fn to_pk(&self) -> Result<Self::Pk, EcSkInvalid> { Ok(self.public_key()) }
}

// ============================================================================
// Key newtypes

#[derive(Wrapper, Copy, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(into = "String", try_from = "String")
)]
pub struct PublicKey(#[from] ed25519_compact::PublicKey);

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.as_ref().partial_cmp(other.0.as_ref())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering { self.0.as_ref().cmp(other.0.as_ref()) }
}

impl EcPk for PublicKey {
    const COMPRESSED_LEN: usize = 32;
    const CURVE_NAME: &'static str = "Edward25519";
    type Compressed = [u8; 32];

    fn base_point() -> Self { Self(ed25519_compact::PublicKey::base_point()) }

    fn to_pk_compressed(&self) -> Self::Compressed { self.0.to_pk_compressed() }

    fn from_pk_compressed(pk: Self::Compressed) -> Result<Self, EcPkInvalid> {
        ed25519_compact::PublicKey::from_pk_compressed(pk).map(Self)
    }

    fn from_pk_compressed_slice(slice: &[u8]) -> Result<Self, EcPkInvalid> {
        ed25519_compact::PublicKey::from_pk_compressed_slice(slice).map(Self)
    }
}

impl MultiDisplay<Encoding> for PublicKey {
    type Display = String;
    fn display_fmt(&self, f: &Encoding) -> Self::Display { self.0.display_fmt(f) }
}

#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
pub struct PrivateKey(#[from] ed25519_compact::SecretKey);

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for PrivateKey {
    fn cmp(&self, other: &Self) -> Ordering { self.0.cmp(&other.0) }
}

impl EcSk for PrivateKey {
    type Pk = PublicKey;

    fn generate_keypair() -> (Self, Self::Pk)
    where Self: Sized {
        let (sk, pk) = ed25519_compact::SecretKey::generate_keypair();
        (sk.into(), pk.into())
    }

    fn to_pk(&self) -> Result<PublicKey, EcSkInvalid> { self.0.to_pk().map(PublicKey::from) }
}

// ============================================================================
// EdDSA

impl EcSign for ed25519_compact::SecretKey {
    type Sig = ed25519_compact::Signature;

    fn sign(&self, msg: impl AsRef<[u8]>) -> ed25519_compact::Signature {
        self.sign(msg, None).into()
    }
}

impl MultiDisplay<Encoding> for ed25519_compact::Signature {
    type Display = String;
    fn display_fmt(&self, f: &Encoding) -> Self::Display { f.encode(self.as_slice()) }
}

impl EcSig for ed25519_compact::Signature {
    const COMPRESSED_LEN: usize = 64;

    type Pk = ed25519_compact::PublicKey;
    type Compressed = [u8; 64];

    fn to_sig_compressed(&self) -> Self::Compressed { *self.deref() }

    fn from_sig_compressed(sig: Self::Compressed) -> Result<Self, EcSigInvalid> {
        Ok(Self::from_slice(&sig).expect("fixed length"))
    }

    fn from_sig_compressed_slice(slice: &[u8]) -> Result<Self, EcSigInvalid> {
        Self::from_slice(slice).map_err(|_| EcSigInvalid {})
    }

    fn verify(&self, pk: &Self::Pk, msg: impl AsRef<[u8]>) -> Result<(), EcVerifyError> {
        pk.verify(msg, self).map_err(EcVerifyError::from)
    }
}

/// Cryptographic signature.
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[wrapper(Deref)]
pub struct Signature(ed25519_compact::Signature);

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl From<ed25519_compact::Signature> for Signature {
    fn from(other: ed25519_compact::Signature) -> Self { Self(other) }
}

impl MultiDisplay<Encoding> for Signature {
    type Display = String;
    fn display_fmt(&self, f: &Encoding) -> Self::Display { self.0.display_fmt(f) }
}

impl EcSig for Signature {
    const COMPRESSED_LEN: usize = 64;
    type Pk = PublicKey;
    type Compressed = [u8; 64];

    fn to_sig_compressed(&self) -> Self::Compressed { self.0.to_sig_compressed() }

    fn from_sig_compressed(sig: Self::Compressed) -> Result<Self, EcSigInvalid> {
        ed25519_compact::Signature::from_sig_compressed(sig).map(Self)
    }

    fn from_sig_compressed_slice(slice: &[u8]) -> Result<Self, EcSigInvalid> {
        ed25519_compact::Signature::from_sig_compressed_slice(slice).map(Self)
    }

    fn verify(&self, pk: &Self::Pk, msg: impl AsRef<[u8]>) -> Result<(), EcVerifyError> {
        self.0.verify(pk, msg)
    }
}

impl EcSign for PrivateKey {
    type Sig = Signature;

    fn sign(&self, msg: impl AsRef<[u8]>) -> Signature { Signature(self.0.sign(msg, None)) }
}

// ============================================================================
// Display and from string

#[cfg(feature = "multibase")]
mod human_readable {
    use std::fmt::{self, Display, Formatter};
    use std::str::FromStr;

    use super::*;
    use crate::EcSerError;

    impl PublicKey {
        /// Multicodec key type for Ed25519 keys.
        pub const MULTICODEC_TYPE: [u8; 2] = [0xED, 0x1];

        /// Encode public key in human-readable format.
        ///
        /// We use the format specified by the DID `key` method, which is described as:
        ///
        /// `did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))`
        pub fn to_human_readable(&self) -> String {
            let mut buf = [0; 2 + ed25519_compact::PublicKey::BYTES];
            buf[..2].copy_from_slice(&Self::MULTICODEC_TYPE);
            buf[2..].copy_from_slice(self.0.deref());

            multibase::encode(multibase::Base::Base58Btc, buf)
        }
    }

    impl Display for PublicKey {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str(&self.to_human_readable())
        }
    }

    impl FromStr for PublicKey {
        type Err = EcSerError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let (_, bytes) = multibase::decode(s)?;

            if let Some(bytes) = bytes.strip_prefix(&Self::MULTICODEC_TYPE) {
                let key = ed25519_compact::PublicKey::from_slice(bytes)?;

                Ok(Self(key))
            } else {
                Err(EcSerError::DataEncoding(s!("unrecognized multicode type")))
            }
        }
    }

    impl From<PublicKey> for String {
        fn from(other: PublicKey) -> Self { other.to_human_readable() }
    }

    impl TryFrom<String> for PublicKey {
        type Error = EcSerError;

        fn try_from(value: String) -> Result<Self, Self::Error> { Self::from_str(&value) }
    }

    impl Display for Signature {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let base = multibase::Base::Base58Btc;
            write!(f, "{}", multibase::encode(base, self.0))
        }
    }

    impl FromStr for Signature {
        type Err = EcSerError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let (_, bytes) = multibase::decode(s)?;
            let sig = ed25519_compact::Signature::from_slice(bytes.as_slice())?;

            Ok(Self(sig))
        }
    }
}

#[cfg(feature = "pem")]
mod pem_der {
    use super::*;

    impl PublicKey {
        pub fn from_pem(pem: &str) -> Result<Self, ed25519_compact::Error> {
            ed25519_compact::PublicKey::from_pem(pem).map(Self)
        }

        pub fn from_der(der: &[u8]) -> Result<Self, ed25519_compact::Error> {
            ed25519_compact::PublicKey::from_der(der).map(Self::from)
        }

        pub fn to_pem(&self) -> String { self.0.to_pem() }
    }

    impl PrivateKey {
        pub fn from_pem(pem: &str) -> Result<Self, ed25519_compact::Error> {
            ed25519_compact::SecretKey::from_pem(pem).map(Self::from)
        }

        pub fn from_der(der: &[u8]) -> Result<Self, ed25519_compact::Error> {
            ed25519_compact::SecretKey::from_der(der).map(Self::from)
        }

        pub fn to_pem(&self) -> String { self.0.to_pem() }
    }
}
