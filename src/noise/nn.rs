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

use std::marker::PhantomData;

use crate::crypto::{Digest, Ecdh};
use crate::noise::framing::IncompleteHandshake;
use crate::noise::{
    HandshakeError, NoiseDecryptor, NoiseEncryptor, NoiseProtocol, NoiseState, StaticKeyPat,
};

#[allow(non_camel_case_types)]
pub struct Noise_NN<E: Ecdh, D: Digest> {
    states: NoiseNnState,
    _phantom: PhantomData<(E, D)>,
}

pub enum NoiseNnState {}

impl<E: Ecdh, D: Digest> NoiseState for Noise_NN<E, D> {
    type Act = ();

    fn advance_handshake(&mut self, input: &[u8]) -> Result<Option<Self::Act>, HandshakeError> {
        todo!()
    }

    fn next_handshake_len(&self) -> usize { todo!() }

    fn is_handshake_complete(&self) -> bool { todo!() }

    fn with_split(encryptor: NoiseEncryptor, decryptor: NoiseDecryptor) -> Self { todo!() }

    fn try_as_split(&self) -> Result<(&NoiseEncryptor, &NoiseDecryptor), IncompleteHandshake> {
        todo!()
    }

    fn try_as_split_mut(
        &mut self,
    ) -> Result<(&mut NoiseEncryptor, &mut NoiseDecryptor), IncompleteHandshake> {
        todo!()
    }

    fn try_into_split(
        self,
    ) -> Result<(NoiseEncryptor, NoiseDecryptor), (Self, IncompleteHandshake)> {
        todo!()
    }
}

impl<E: Ecdh, D: Digest> NoiseProtocol for Noise_NN<E, D> {
    type Ecdh = E;
    type Digest = D;
    const INITIATOR: StaticKeyPat = StaticKeyPat::No;
    const RESPONDER: StaticKeyPat = StaticKeyPat::No;
}
