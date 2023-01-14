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

#[macro_use]
extern crate amplify;

use cypher::{Cert, EcPk, EcSig, EcSign};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// authorization message has invalid length {0}
    InvalidLen(usize),

    /// the provided identity certificate doesn't contain a valid signature
    InvalidCert,

    /// the provided credentials has invalid nonce signature
    SigMismatch,

    /// authentication is complete and cant advance anymore
    Completed,
}

#[derive(Debug)]
pub enum EidolonState<S: EcSig> {
    Uninit(Cert<S>, bool),
    Initiator(Cert<S>, Vec<u8>),
    ResponderAwaits(Cert<S>, Vec<u8>),
    CredentialsSent,
    Complete(Cert<S>),
}

impl<S: EcSig> EidolonState<S> {
    const MESSAGE_LEN: usize = S::Pk::COMPRESSED_LEN + S::COMPRESSED_LEN * 2;

    pub fn initiator(creds: Cert<S>) -> Self { Self::Uninit(creds, true) }

    pub fn responder(creds: Cert<S>) -> Self { Self::Uninit(creds, false) }

    pub fn init(&mut self, nonce: impl AsRef<[u8]>) {
        let nonce = nonce.as_ref().to_vec();
        *self = match self {
            Self::Uninit(cert, true) => Self::Initiator(cert.clone(), nonce),
            Self::Uninit(cert, false) => Self::ResponderAwaits(cert.clone(), nonce),
            _ => panic!("repeated call to init method"),
        };
    }

    pub fn is_init(&self) -> bool { !matches!(self, Self::Uninit(..)) }

    pub fn advance<P: EcSign>(&mut self, input: &[u8], signer: &P) -> Result<Vec<u8>, Error> {
        match self {
            EidolonState::Uninit(_, _) => panic!("advancing uninitialized state machine"),
            EidolonState::Initiator(creds, nonce) => {
                debug_assert!(input.is_empty());
                let data = Self::serialize_creds(creds, nonce, signer);
                *self = EidolonState::CredentialsSent;
                Ok(data)
            }
            EidolonState::ResponderAwaits(creds, nonce) => {
                let cert = Self::verify_input(input)?;
                let data = Self::serialize_creds(creds, nonce, signer);
                *self = EidolonState::Complete(cert);
                Ok(data)
            }
            EidolonState::CredentialsSent => {
                let cert = Self::verify_input(input)?;
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

    fn verify_input(input: &[u8]) -> Result<Cert<S>, Error> {
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
        sig_nonce.verify(&pk, pk.to_pk_compressed()).map_err(|_| Error::SigMismatch)?;

        Ok(Cert { pk, sig })
    }

    fn serialize_creds<P: EcSign>(creds: &Cert<S>, nonce: &[u8], signer: &P) -> Vec<u8> {
        let sig = signer.sign(&nonce);
        let mut data = Vec::with_capacity(S::Pk::COMPRESSED_LEN + S::COMPRESSED_LEN * 2);
        data.extend_from_slice(creds.pk.to_pk_compressed().as_ref());
        data.extend_from_slice(creds.sig.to_sig_compressed().as_ref());
        data.extend_from_slice(sig.to_sig_compressed().as_ref());
        data
    }
}
