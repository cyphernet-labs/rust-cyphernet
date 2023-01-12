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

//! Curve25519 keys and ECDH algorithm implementation for X25519 scheme.

use std::cmp::Ordering;
use std::ops::Deref;
use ed25519_compact::Error;

use super::*;

// ============================================================================
// ed25519_compact keys

impl EcPk for ed25519_compact::x25519::PublicKey {
    const COMPRESSED_LEN: usize = 32;
    const CURVE_NAME: &'static str = "Curve25519";
    type Compressed = [u8; 32];

    fn base_point() -> Self { ed25519_compact::x25519::PublicKey::base_point() }

    fn to_pk_compressed(&self) -> Self::Compressed {
        *self.deref()
    }

    fn from_pk_compressed(pk: Self::Compressed) -> Result<Self, EcPkInvalid> {
        Ok(ed25519_compact::x25519::PublicKey::new(pk))
    }
}

impl EcSk for ed25519_compact::x25519::SecretKey {
    type Pk = ed25519_compact::x25519::PublicKey;

    fn to_pk(&self) -> Result<Self::Pk, EcSkInvalid> { self.recover_public_key().map_err(EcSkInvalid::from) }
}

// ============================================================================
// Key newtypes

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref)]
pub struct SharedSecret([u8; 32]);

#[derive(Wrapper, Copy, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
// TODO: Do serde
/* #[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(into = "String", try_from = "String")
)] */
pub struct PublicKey(#[from] ed25519_compact::x25519::PublicKey);

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
    const CURVE_NAME: &'static str = "Curve25519";
    type Compressed = [u8; 32];

    fn base_point() -> Self {
        Self(ed25519_compact::x25519::PublicKey::base_point())
    }

    fn to_pk_compressed(&self) -> Self::Compressed {
        self.0.to_pk_compressed()
    }

    fn from_pk_compressed(pk: Self::Compressed) -> Result<Self, EcPkInvalid> {
        ed25519_compact::x25519::PublicKey::from_pk_compressed(pk).map(Self)
    }
}

#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
pub struct PrivateKey(#[from] ed25519_compact::x25519::SecretKey);

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for PrivateKey {
    fn cmp(&self, other: &Self) -> Ordering { self.0.cmp(&other.0) }
}

impl EcSk for PrivateKey {
    type Pk = PublicKey;

    fn to_pk(&self) -> Result<PublicKey, EcSkInvalid> { self.0.to_pk().map(PublicKey::from) }
}

impl From<ed25519_compact::Error> for EcPkInvalid {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidPublicKey => EcPkInvalid {},

            Error::WeakPublicKey |
            Error::InvalidSecretKey |
            Error::SignatureMismatch |
            Error::InvalidSignature |
            Error::InvalidSeed |
            Error::InvalidBlind |
            Error::InvalidNoise |
            Error::ParseError |
            Error::NonCanonical => {
                unreachable!("ECDH in ed25519-compact crate should not generate this errors")
            }
        }
    }
}

impl From<ed25519_compact::Error> for EcSkInvalid {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidSecretKey => EcSkInvalid {},

            Error::WeakPublicKey |
            Error::InvalidPublicKey |
            Error::SignatureMismatch |
            Error::InvalidSignature |
            Error::InvalidSeed |
            Error::InvalidBlind |
            Error::InvalidNoise |
            Error::ParseError |
            Error::NonCanonical => {
                unreachable!("ECDH in ed25519-compact crate should not generate this errors")
            }
        }
    }
}

impl From<ed25519_compact::Error> for EcdhError {
    fn from(err: Error) -> Self {
        match err {
            Error::WeakPublicKey => EcdhError::WeakPk,
            Error::InvalidPublicKey => EcdhError::InvalidPk(EcPkInvalid {}),
            Error::InvalidSecretKey => EcdhError::InvalidSk(EcSkInvalid {}),

            Error::SignatureMismatch |
            Error::InvalidSignature |
            Error::InvalidSeed |
            Error::InvalidBlind |
            Error::InvalidNoise |
            Error::ParseError |
            Error::NonCanonical => {
                unreachable!("ECDH in ed25519-compact crate should not generate this errors")
            }
        }
    }
}

// ============================================================================
// ECDH

impl Ecdh for ed25519_compact::x25519::SecretKey {
    type SharedSecret = [u8; 32];

    fn ecdh(&self, pk: &Self::Pk) -> Result<Self::SharedSecret, EcdhError> {
        Ok(*pk.dh(self)?)
    }
}

impl Ecdh for PrivateKey {
    type SharedSecret = SharedSecret;

    fn ecdh(&self, pk: &PublicKey) -> Result<SharedSecret, EcdhError> {
        self.0.ecdh(&pk.0).map(SharedSecret::from)
    }
}
