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

use amplify::IoError;

#[cfg(feature = "ed25519")]
pub mod x25519;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display("invalid secret key")]
#[non_exhaustive]
pub struct EcSkInvalid {}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display("invalid public key")]
#[non_exhaustive]
pub struct EcPkInvalid {}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
#[non_exhaustive]
pub enum EcdhError {
    /// public key provided for the ECDH is weak key
    WeakPk,

    #[display(inner)]
    #[from]
    InvalidPk(EcPkInvalid),

    #[display(inner)]
    #[from]
    InvalidSk(EcSkInvalid)
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum EcSerError {
    #[display(inner)]
    #[from]
    Io(IoError),

    /// public key has invalid length {0}
    InvalidKeyLength(usize),

    #[display(inner)]
    #[from]
    InvalidKey(EcPkInvalid)
}

/// Elliptic-curve based public key type which can be used in ECDH or signature schemes.
///
/// # Safety
///
/// The type provides no guarantees on the key validity upon deserialization.
pub trait EcPk: Clone + Eq {
    const COMPRESSED_LEN: usize;
    const CURVE_NAME: &'static str;

    // TODO: When generic_const_exprs arrive switch to Self::COMPRESSED_LEN arrays
    type Compressed: Copy + Sized + Send;

    fn base_point() -> Self;

    fn to_pk_compressed(&self) -> Self::Compressed;
    fn from_pk_compressed(pk: Self::Compressed) -> Result<Self, EcPkInvalid>;
}

/// Elliptic-curve based private key type.
///
/// # Safety
///
/// The type provides no guarantees on the key validity upon deserialization.
pub trait EcSk: Eq {
    type Pk: EcPk;
    fn to_pk(&self) -> Result<Self::Pk, EcSkInvalid>;
}

/// Elliptic-curve based public key type which can be used for ECDH.
///
/// # Safety
///
/// The type provides no guarantees on the key validity upon deserialization.
pub trait Ecdh: EcSk {
    type SharedSecret: Copy + Sized + Send;

    fn ecdh(&self, pk: &Self::Pk) -> Result<Self::SharedSecret, EcdhError>;
}

pub trait Digest {
    const OUTPUT_LEN: usize;

    type Output: Copy + Sized + Send;

    fn digest(&mut self);
    fn finalize(self) -> Self::Output;
}

pub trait KeyedDigest: Digest {
    type Key;
    fn with_key(key: Self::Key) -> Self;
}

/*
pub trait EcSig {
    type Sk: EcSk<Pk = Self::Pk>;
    type Pk: EcPk;

    fn sign(self, sk: &Self::Sk, msg: impl AsRef<[u8]>) -> Self;
    fn verify(self, pk: &Self::Pk, msg: impl AsRef<[u8]>) -> bool;
}

pub trait EcHmSig: EcSig + Add + AddAssign + Sized {}
*/
