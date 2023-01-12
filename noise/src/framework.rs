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

use cypher::EcPk;

use crate::error::{HandshakeError, IncompleteHandshake};
use crate::SymmetricKey;

pub enum StaticKeyPat {
    No,
    Xmits,
    Known,
}

pub trait NoiseState: Sized {
    type Act: AsRef<[u8]>;
    type Pubkey: EcPk + Copy;

    fn advance_handshake(&mut self, input: &[u8]) -> Result<Option<Self::Act>, HandshakeError>;
    fn next_handshake_len(&self) -> usize;
    fn is_handshake_complete(&self) -> bool;

    fn with_split(
        encryptor: NoiseEncryptor<Self::Pubkey>,
        decryptor: NoiseDecryptor<Self::Pubkey>,
    ) -> Self;
    fn as_split(
        &self,
    ) -> Result<(&NoiseEncryptor<Self::Pubkey>, &NoiseDecryptor<Self::Pubkey>), IncompleteHandshake>;
    fn as_split_mut(
        &mut self,
    ) -> Result<
        (&mut NoiseEncryptor<Self::Pubkey>, &mut NoiseDecryptor<Self::Pubkey>),
        IncompleteHandshake,
    >;
    fn into_split(
        self,
    ) -> Result<
        (NoiseEncryptor<Self::Pubkey>, NoiseDecryptor<Self::Pubkey>),
        (Self, IncompleteHandshake),
    >;

    fn expect_remote_pubkey(&self) -> Self::Pubkey { self.as_split().unwrap().1.remote_pubkey }
    fn expect_encryptor(&mut self) -> &mut NoiseEncryptor<Self::Pubkey> {
        self.as_split_mut().unwrap().0
    }
    fn expect_decryptor(&mut self) -> &mut NoiseDecryptor<Self::Pubkey> {
        self.as_split_mut().unwrap().1
    }
}

pub trait NoiseProtocol: NoiseState {
    type Ecdh: cypher::Ecdh;
    type Digest: cypher::Digest;

    const INITIATOR: StaticKeyPat;
    const RESPONDER: StaticKeyPat;
}

#[derive(Clone, Debug)]
pub struct NoiseEncryptor<Pk: EcPk> {
    pub(crate) sending_key: SymmetricKey,
    pub(crate) sending_chaining_key: SymmetricKey,
    pub(crate) sending_nonce: u32,
    pub(crate) remote_pubkey: Pk,
}

#[derive(Clone, Debug)]
pub struct NoiseDecryptor<Pk: EcPk> {
    pub(crate) receiving_key: SymmetricKey,
    pub(crate) receiving_chaining_key: SymmetricKey,
    pub(crate) receiving_nonce: u32,

    pub(crate) pending_message_length: Option<usize>,
    pub(crate) read_buffer: Option<Vec<u8>>,
    pub(crate) poisoned: bool, /* signal an error has occurred so None is returned on
                                * iteration after failure */
    pub(crate) remote_pubkey: Pk,
}
