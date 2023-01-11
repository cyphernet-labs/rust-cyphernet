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

#[cfg(feature = "ed25519")]
pub mod ed25519;

pub trait EcPk: Clone + Eq {
    fn generator() -> Self;
}

pub trait EcSk: Eq {
    type Pk: EcPk;
    fn to_pk(&self) -> Self::Pk;
}

pub trait Ecdh: EcSk {
    type Secret: Sized;
    type Err;

    fn ecdh(&self, pk: &Self::Pk) -> Result<Self::Secret, Self::Err>;
}

pub trait Digest {
    const OUTPUT_LEN: usize;
    type Key;
    type Midstate: Copy + Sized + Send;
    type Output: Copy + Sized + Send;

    fn with_key(key: Self::Key) -> Self;
    fn from_midstate(midstate: Self::Midstate) -> Self;
    fn to_midstate(&self) -> Self::Midstate;
    fn input(&mut self);
    fn output(&self) -> Self::Output;
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
