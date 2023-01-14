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

use crate::*;

// ============================================================================
// ed25519_compact keys

impl MultiDisplay for ed25519_compact::x25519::PublicKey {
    type Format = Encoding;
    type Display = String;
    fn display_fmt(&self, f: &Self::Format) -> String { f.encode(self.as_slice()) }
}

impl EcPk for ed25519_compact::x25519::PublicKey {
    const COMPRESSED_LEN: usize = 32;
    const CURVE_NAME: &'static str = "Curve25519";
    type Compressed = [u8; 32];

    fn base_point() -> Self { ed25519_compact::x25519::PublicKey::base_point() }

    fn to_pk_compressed(&self) -> Self::Compressed { *self.deref() }

    fn from_pk_compressed(pk: Self::Compressed) -> Result<Self, EcPkInvalid> {
        Ok(ed25519_compact::x25519::PublicKey::new(pk))
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

impl EcSk for ed25519_compact::x25519::SecretKey {
    type Pk = ed25519_compact::x25519::PublicKey;

    fn generate_keypair() -> (Self, Self::Pk)
    where Self: Sized {
        let pair = ed25519_compact::x25519::KeyPair::generate();
        (pair.sk, pair.pk)
    }

    fn to_pk(&self) -> Result<Self::Pk, EcSkInvalid> {
        self.recover_public_key().map_err(EcSkInvalid::from)
    }
}

// ============================================================================
// Key newtypes

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref)]
pub struct SharedSecret([u8; 32]);

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl SharedSecret {
    pub fn empty() -> Self { SharedSecret([0u8; 32]) }

    pub fn is_empty(self) -> bool { self == Self::empty() }
}

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

    fn base_point() -> Self { Self(ed25519_compact::x25519::PublicKey::base_point()) }

    fn to_pk_compressed(&self) -> Self::Compressed { self.0.to_pk_compressed() }

    fn from_pk_compressed(pk: Self::Compressed) -> Result<Self, EcPkInvalid> {
        ed25519_compact::x25519::PublicKey::from_pk_compressed(pk).map(Self)
    }

    fn from_pk_compressed_slice(slice: &[u8]) -> Result<Self, EcPkInvalid> {
        ed25519_compact::x25519::PublicKey::from_pk_compressed_slice(slice).map(Self)
    }
}

impl MultiDisplay for PublicKey {
    type Format = Encoding;
    type Display = String;

    fn display_fmt(&self, f: &Self::Format) -> Self::Display { self.0.display_fmt(f) }
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

    fn generate_keypair() -> (Self, Self::Pk)
    where Self: Sized {
        let (sk, pk) = ed25519_compact::x25519::SecretKey::generate_keypair();
        (sk.into(), pk.into())
    }

    fn to_pk(&self) -> Result<PublicKey, EcSkInvalid> { self.0.to_pk().map(PublicKey::from) }
}

// ============================================================================
// ECDH

impl Ecdh for ed25519_compact::x25519::SecretKey {
    type SharedSecret = [u8; 32];

    fn ecdh(&self, pk: &Self::Pk) -> Result<Self::SharedSecret, EcdhError> { Ok(*pk.dh(self)?) }
}

impl Ecdh for PrivateKey {
    type SharedSecret = SharedSecret;

    fn ecdh(&self, pk: &PublicKey) -> Result<SharedSecret, EcdhError> {
        self.0.ecdh(&pk.0).map(SharedSecret::from)
    }
}
