// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2022-2023 Cyphernet DAO, Switzerland
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

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use]
extern crate amplify;

use std::fmt::Debug;

use cypher::{Cert, EcPk, EcSig, EcSign};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error<Id: EcPk> {
    /// authorization message has invalid length {0}
    InvalidLen(usize),

    /// the provided identity certificate doesn't contain a valid signature
    InvalidCert,

    /// the provided credentials has invalid nonce signature
    SigMismatch,

    /// remote id {0:?} is not authorized
    Unauthorized(Id),

    /// authentication is complete and cant advance anymore
    Completed,
}

#[derive(Debug)]
pub enum EidolonState<S: EcSig> {
    Uninit(Cert<S>, Vec<S::Pk>, bool),
    Initiator(Cert<S>, Vec<S::Pk>, Vec<u8>),
    ResponderAwaits(Cert<S>, Vec<S::Pk>, Vec<u8>),
    CredentialsSent(Vec<S::Pk>, Vec<u8>),
    Complete(Cert<S>),
}

impl<S: EcSig> EidolonState<S> {
    const MESSAGE_LEN: usize = S::Pk::COMPRESSED_LEN + S::COMPRESSED_LEN * 2;

    pub fn initiator(creds: Cert<S>, allowed_ids: Vec<S::Pk>) -> Self {
        Self::Uninit(creds, allowed_ids, true)
    }

    pub fn responder(creds: Cert<S>, allowed_ids: Vec<S::Pk>) -> Self {
        Self::Uninit(creds, allowed_ids, false)
    }

    pub fn init(&mut self, nonce: impl AsRef<[u8]>) {
        let nonce = nonce.as_ref().to_vec();
        *self = match self {
            Self::Uninit(cert, allowed_ids, true) => {
                Self::Initiator(cert.clone(), allowed_ids.clone(), nonce)
            }
            Self::Uninit(cert, allowed_ids, false) => {
                Self::ResponderAwaits(cert.clone(), allowed_ids.clone(), nonce)
            }
            _ => panic!("repeated call to init method"),
        };
    }

    pub fn is_init(&self) -> bool { !matches!(self, Self::Uninit(..)) }

    pub fn advance<P: EcSign>(
        &mut self,
        input: &[u8],
        signer: &P,
    ) -> Result<Vec<u8>, Error<S::Pk>> {
        match self {
            EidolonState::Uninit(_, _, _) => panic!("advancing uninitialized state machine"),
            EidolonState::Initiator(creds, allowed_ids, nonce) => {
                debug_assert!(input.is_empty());
                let data = Self::serialize_creds(creds, nonce, signer);
                *self = EidolonState::CredentialsSent(allowed_ids.clone(), nonce.clone());
                Ok(data)
            }
            EidolonState::ResponderAwaits(creds, allowed_ids, nonce) => {
                let cert = Self::verify_input(input, nonce, allowed_ids)?;
                let data = Self::serialize_creds(creds, nonce, signer);
                *self = EidolonState::Complete(cert);
                Ok(data)
            }
            EidolonState::CredentialsSent(allowed_ids, nonce) => {
                let cert = Self::verify_input(input, nonce, allowed_ids)?;
                *self = EidolonState::Complete(cert);
                Ok(vec![])
            }
            EidolonState::Complete(_) => Err(Error::Completed),
        }
    }

    pub fn is_complete(&self) -> bool { matches!(self, Self::Complete(_)) }

    pub fn remote_cert(&self) -> Option<&Cert<S>> {
        if let Self::Complete(cert) = self {
            Some(cert)
        } else {
            None
        }
    }

    pub fn next_read_len(&self) -> usize {
        match self {
            EidolonState::Uninit(_, _, _) => 0,
            EidolonState::Initiator(_, _, _) => 0,
            EidolonState::ResponderAwaits(_, _, _) | EidolonState::CredentialsSent(_, _) => {
                S::Pk::COMPRESSED_LEN + 2 * S::COMPRESSED_LEN
            }
            EidolonState::Complete(_) => 0,
        }
    }

    fn verify_input(
        input: &[u8],
        nonce: &[u8],
        allowed_ids: &[S::Pk],
    ) -> Result<Cert<S>, Error<S::Pk>> {
        if input.len() != Self::MESSAGE_LEN {
            return Err(Error::InvalidLen(input.len()));
        }
        let pk = &input[..S::Pk::COMPRESSED_LEN];
        let next = &input[S::Pk::COMPRESSED_LEN..];
        let sig = &next[..S::COMPRESSED_LEN];
        let sig_nonce = &next[S::COMPRESSED_LEN..];

        let pk = S::Pk::from_pk_compressed_slice(pk).expect("fixed length");
        let sig = S::from_sig_compressed_slice(sig).expect("fixed length");
        let sig_nonce = S::from_sig_compressed_slice(sig_nonce).expect("fixed length");

        sig.verify(&pk, pk.to_pk_compressed()).map_err(|_| Error::InvalidCert)?;
        sig_nonce.verify(&pk, nonce).map_err(|_| Error::SigMismatch)?;

        if !allowed_ids.is_empty() {
            for id in allowed_ids {
                if id == &pk {
                    return Ok(Cert { pk, sig });
                }
            }
        } else {
            return Ok(Cert { pk, sig });
        }

        Err(Error::Unauthorized(pk))
    }

    fn serialize_creds<P: EcSign>(creds: &Cert<S>, nonce: &[u8], signer: &P) -> Vec<u8> {
        let sig = signer.sign(nonce);
        let mut data = Vec::with_capacity(S::Pk::COMPRESSED_LEN + S::COMPRESSED_LEN * 2);
        data.extend_from_slice(creds.pk.to_pk_compressed().as_ref());
        data.extend_from_slice(creds.sig.to_sig_compressed().as_ref());
        data.extend_from_slice(sig.to_sig_compressed().as_ref());
        data
    }
}
