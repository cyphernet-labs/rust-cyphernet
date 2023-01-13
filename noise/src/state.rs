// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2023 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2023 Cyphernet Initiative, Switzerland
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

use std::collections::VecDeque;

use cypher::x25519::SharedSecret;
use cypher::{Digest, EcPk, Ecdh};

use crate::cipher::{decrypt, encrypt, rekey};
use crate::error::{EncryptionError, NoiseError};
use crate::hkdf::{hkdf_2, hkdf_3};
use crate::patterns::{HandshakePattern, Keyset, MessagePattern};
use crate::{ChainingKey, HandshakeHash, NoiseNonce};

trait WithTruncated {
    fn with_truncated(temp_key: impl AsRef<[u8]>) -> Self;
}

impl WithTruncated for SharedSecret {
    fn with_truncated(temp_key: impl AsRef<[u8]>) -> Self {
        let mut key = [0u8; 32];
        match temp_key.as_ref().len() {
            32 => {
                key.copy_from_slice(temp_key.as_ref());
            }
            64 => {
                key.copy_from_slice(&temp_key.as_ref()[..32]);
            }
            x => {
                panic!(
                    "Noise protocol requires HASH function with output length either 32 or 64 \
                     bytes (a function outputting {x} bytes were given)"
                )
            }
        }
        SharedSecret::from(key)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CipherState {
    k: SharedSecret,
    n: NoiseNonce,
}

impl CipherState {
    pub fn new() -> Self {
        CipherState {
            k: SharedSecret::empty(),
            n: 0,
        }
    }

    pub fn initialize_key(&mut self, key: SharedSecret) {
        self.k = key;
        self.n = 0;
    }

    pub fn has_key(&mut self) -> bool { !self.k.is_empty() }

    pub fn nonce(&self) -> NoiseNonce { self.n }

    pub fn set_nonce(&mut self, nonce: NoiseNonce) { self.n = nonce; }

    pub fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        if self.k.is_empty() {
            Ok(plaintext.to_vec())
        } else {
            // If k is non-empty returns ENCRYPT(k, n++, ad, plaintext).
            let ciphertext = encrypt(self.k, self.n, ad, plaintext);
            self.n += 1;
            ciphertext
        }
    }
    pub fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        if self.k.is_empty() {
            Ok(ciphertext.to_vec())
        } else {
            // If k is non-empty returns DECRYPT(k, n++, ad, ciphertext).
            // If an authentication failure occurs in DECRYPT() then n is not incremented and an
            // error is signaled to the caller.
            let plaintext = decrypt(self.k, self.n, ad, ciphertext)?;
            self.n += 1;
            Ok(plaintext)
        }
    }

    fn rekey(&mut self) { self.k = rekey(self.k); }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SymmetricState<D: Digest> {
    cipher: CipherState,
    ck: ChainingKey<D>,
    h: HandshakeHash<D>,
    was_split: bool,
}

impl<D: Digest> SymmetricState<D> {
    pub fn with<const HASHLEN: usize>(protocol_name: String) -> Self {
        debug_assert_eq!(HASHLEN, D::OUTPUT_LEN);
        let len = protocol_name.len();
        let h = if len <= HASHLEN {
            let mut h = [0u8; HASHLEN];
            h[..len].copy_from_slice(protocol_name.as_bytes());
            D::Output::try_from(&h).unwrap_or_else(|_| unreachable!())
        } else {
            D::digest(protocol_name.as_bytes())
        };
        let cipher = CipherState::new();
        Self {
            cipher,
            h,
            ck: h,
            was_split: false,
        }
    }

    pub fn mix_key(&mut self, input_key_material: impl AsRef<[u8]>) {
        let (ck, temp_key) = hkdf_2::<D>(self.ck, input_key_material);
        self.ck = ck;
        self.cipher.initialize_key(SharedSecret::with_truncated(temp_key));
    }

    pub fn mix_hash(&mut self, data: impl AsRef<[u8]>) {
        self.h = D::digest_concat([self.h.as_ref(), data.as_ref()]);
    }

    pub fn mix_key_and_hash(&mut self, input_key_material: impl AsRef<[u8]>) {
        // Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
        let (ck, temp_h, temp_k) = hkdf_3::<D>(self.ck, input_key_material);
        self.ck = ck;

        // Calls MixHash(temp_h).
        self.mix_hash(temp_h);

        // If HASHLEN is 64, then truncates temp_k to 32 bytes.
        // Calls InitializeKey(temp_k).
        self.cipher.initialize_key(SharedSecret::with_truncated(temp_k));
    }

    pub fn get_handshake_hash(&self) -> HandshakeHash<D> {
        if !self.was_split {
            panic!(
                "SymmetricState::get_handshake_hash must be called only after \
                 SymmetricState::split"
            )
        }
        self.h
    }

    pub fn encrypt_and_hash(
        &mut self,
        plaintext: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        // ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns
        // ciphertext. Note that if k is empty, the EncryptWithAd() call will set ciphertext equal
        // to plaintext.
        let ciphertext = self.cipher.encrypt_with_ad(self.h.as_ref(), plaintext.as_ref())?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    pub fn decrypt_and_hash(
        &mut self,
        ciphertext: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        // plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns
        // plaintext. Note that if k is empty, the DecryptWithAd() call will set plaintext equal to
        // ciphertext.
        let plaintext = self.cipher.decrypt_with_ad(self.h.as_ref(), ciphertext.as_ref())?;
        self.mix_hash(&ciphertext);
        Ok(plaintext)
    }

    pub fn split(&self) -> (CipherState, CipherState) {
        // Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
        let (temp_k1, temp_k2) = hkdf_2::<D>(self.ck, &[]);

        // If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
        let k1 = SharedSecret::with_truncated(temp_k1);
        let k2 = SharedSecret::with_truncated(temp_k2);

        // Creates two new CipherState objects c1 and c2.
        let mut c1 = CipherState::new();
        let mut c2 = CipherState::new();

        // Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
        c1.initialize_key(k1);
        c2.initialize_key(k2);

        // Returns the pair (c1, c2).
        (c1, c2)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HandshakeState<E: Ecdh, D: Digest> {
    state: SymmetricState<D>,
    is_initiator: bool,
    keyset: Keyset<E>,
    handshake_pattern: HandshakePattern,
    message_patterns: VecDeque<&'static [MessagePattern]>,
}

impl<E: Ecdh, D: Digest> HandshakeState<E, D> {
    /// Initialize(handshake_pattern, initiator, prologue, s, e, rs, re): Takes a valid
    /// handshake_pattern (see Section 7) and an initiator boolean specifying this party's role
    /// as either initiator or responder.
    ///
    /// Takes a prologue byte sequence which may be zero-length, or which may contain context
    /// information that both parties want to confirm is identical (see Section 6).
    ///
    /// Takes a set of DH key pairs (s, e) and public keys (rs, re) for initializing local
    /// variables, any of which may be empty. Public keys are only passed in if the
    /// handshake_pattern uses pre-messages (see Section 7). The ephemeral values (e, re) are
    /// typically left empty, since they are created and exchanged during the handshake; but
    /// there are exceptions (see Section 10).
    ///
    /// Performs the following steps:
    ///
    /// Derives a protocol_name byte sequence by combining the names for the handshake pattern
    /// and crypto functions, as specified in Section 8.
    ///
    /// Calls InitializeSymmetric(protocol_name).
    ///
    /// Calls MixHash(prologue).
    ///
    /// Sets the initiator, s, e, rs, and re variables to the corresponding arguments.
    ///
    /// Calls MixHash() once for each public key listed in the pre-messages from
    /// handshake_pattern, with the specified public key as input (see Section 7 for an
    /// explanation of pre-messages). If both initiator and responder have pre-messages, the
    /// initiator's public keys are hashed first. If multiple public keys are listed in either
    /// party's pre-message, the public keys are hashed in the order that they are listed.
    ///
    /// Sets message_patterns to the message patterns from handshake_pattern.
    pub fn initialize<const HASHLEN: usize>(
        handshake_pattern: HandshakePattern,
        is_initiator: bool,
        prologue: &[u8],
        keyset: Keyset<E>,
    ) -> Self {
        debug_assert_eq!(HASHLEN, D::OUTPUT_LEN);
        let mut name_components = vec![s!("Noise")];
        let curve_name = match E::Pk::CURVE_NAME {
            "Edward25519" => "25519",
            "Secp356k1" => "secp256k1",
            unsupported => {
                unimplemented!("curve {unsupported} is not supported by the Noise library")
            }
        };
        name_components.push(handshake_pattern.to_string());
        name_components.push(curve_name.to_owned());
        name_components.push("ChaChaPoly".to_owned());
        name_components.push(D::DIGEST_NAME.to_owned());
        let protocol_name = name_components.join("_");

        let mut state = SymmetricState::<D>::with::<HASHLEN>(protocol_name);
        state.mix_hash(prologue);

        for pre_msg in handshake_pattern.pre_messages() {
            if let Some(key) = keyset.pre_message_key(*pre_msg, is_initiator) {
                state.mix_hash(key.to_pk_compressed().as_ref())
            }
        }

        let message_patterns = VecDeque::from_iter(
            handshake_pattern.message_patterns(is_initiator).into_iter().copied(),
        );

        Self {
            handshake_pattern,
            message_patterns,
            is_initiator,
            keyset,
            state,
        }
    }

    /// Takes a payload byte sequence which may be zero-length
    ///
    /// # Errors
    ///
    /// If any EncryptAndHash() call returns an error
    fn write_message(&mut self, payload: &[u8]) -> Result<HandshakeAct, EncryptionError> {
        match self.message_patterns.pop_front() {
            Some(seq) => {
                let mut message_buffer = Vec::<u8>::new();
                // 1. Fetches and deletes the next message pattern from message_patterns, then
                // sequentially processes each token from the message pattern:
                //   - For "e": Sets e (which must be empty) to GENERATE_KEYPAIR(). Appends
                //     e.public_key to the buffer. Calls MixHash(e.public_key).
                //   - For "s": Appends EncryptAndHash(s.public_key) to the buffer.
                //   - For "ee": Calls MixKey(DH(e, re)).
                //   - For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if
                //     responder.
                //   - For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if
                //     responder.
                //   - For "ss": Calls MixKey(DH(s, rs)).

                for pat in seq {
                    match pat {
                        MessagePattern::E => {
                            let (e, pubkey) = E::generate_keypair();
                            message_buffer.extend(pubkey.to_pk_compressed().as_ref());

                            let re = self.keyset.expect_re();
                            self.state.mix_key(e.ecdh(&re)?);
                            self.keyset.e = e;
                        }
                        MessagePattern::S => message_buffer
                            .extend(self.keyset.expect_s().to_pk()?.to_pk_compressed().as_ref()),
                        MessagePattern::EE => {
                            self.state.mix_key(self.keyset.e.ecdh(&self.keyset.expect_re())?)
                        }
                        MessagePattern::ES if self.is_initiator => {
                            self.state.mix_key(self.keyset.e.ecdh(&self.keyset.expect_rs())?)
                        }
                        MessagePattern::ES => self
                            .state
                            .mix_key(self.keyset.expect_s().ecdh(&self.keyset.expect_re())?),
                        MessagePattern::SE if self.is_initiator => self
                            .state
                            .mix_key(self.keyset.expect_s().ecdh(&self.keyset.expect_re())?),
                        MessagePattern::SE => {
                            self.state.mix_key(self.keyset.e.ecdh(&self.keyset.expect_rs())?)
                        }
                        MessagePattern::SS => self
                            .state
                            .mix_key(self.keyset.expect_s().ecdh(&self.keyset.expect_rs())?),
                    };
                }

                // 2. Appends EncryptAndHash(payload) to the buffer.
                message_buffer.extend(self.state.encrypt_and_hash(payload)?);

                Ok(HandshakeAct::Buffer(message_buffer))
            }
            None => {
                // 3. If there are no more message patterns returns two new CipherState objects by
                // calling Split().
                let (c1, c2) = self.state.split();
                Ok(HandshakeAct::Split(c1, c2))
            }
        }
    }

    /// Takes a byte sequence containing a Noise handshake message, and a payload_buffer to write
    /// the message's plaintext payload into.
    ///
    /// # Errors
    ///
    /// If any DecryptAndHash() call returns an error
    fn read_message(&mut self, message: &[u8]) -> Result<HandshakeAct, EncryptionError> {
        match self.message_patterns.pop_front() {
            Some(seq) => {
                let mut payload_buffer = Vec::new();
                let mut pos = 0usize;

                // Performs the following steps:
                //
                // 1. Fetches and deletes the next message pattern from message_patterns, then
                // sequentially processes each token from the message pattern:
                //   - For "e": Sets re (which must be empty) to the next DHLEN bytes from the
                //     message. Calls MixHash(re.public_key).
                //   - For "s": Sets temp to the next DHLEN + 16 bytes of the message if HasKey() ==
                //     True, or to the next DHLEN bytes otherwise. Sets rs (which must be empty) to
                //     DecryptAndHash(temp).
                //   - For "ee": Calls MixKey(DH(e, re)).
                //   - For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if
                //     responder.
                //   - For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if
                //     responder.
                //   - For "ss": Calls MixKey(DH(s, rs)).
                for pat in seq {
                    match pat {
                        MessagePattern::E => {
                            debug_assert!(self.keyset.re.is_none());

                            let next_pos = pos + E::Pk::COMPRESSED_LEN;
                            let re =
                                E::Pk::from_pk_compressed_slice(&payload_buffer[pos..next_pos])?;
                            pos = next_pos;

                            self.state.mix_hash(&re.to_pk_compressed());
                            self.keyset.re = Some(re);
                        }
                        MessagePattern::S => {
                            debug_assert!(self.keyset.rs.is_none());
                            let next_pos = match self.state.cipher.has_key() {
                                true => 32 + 16,
                                false => 32,
                            };
                            let temp =
                                self.state.decrypt_and_hash(&payload_buffer[pos..next_pos])?;
                            self.keyset.rs = Some(E::Pk::from_pk_compressed_slice(&temp)?);
                            pos = next_pos;
                        }
                        MessagePattern::EE => {
                            self.state.mix_key(self.keyset.e.ecdh(&self.keyset.expect_re())?);
                        }
                        MessagePattern::ES if self.is_initiator => {
                            self.state.mix_key(self.keyset.e.ecdh(&self.keyset.expect_rs())?);
                        }
                        MessagePattern::ES => {
                            self.state
                                .mix_key(self.keyset.expect_s().ecdh(&self.keyset.expect_re())?);
                        }
                        MessagePattern::SE if self.is_initiator => {
                            self.state
                                .mix_key(self.keyset.expect_s().ecdh(&self.keyset.expect_re())?);
                        }
                        MessagePattern::SE => {
                            self.state.mix_key(self.keyset.e.ecdh(&self.keyset.expect_rs())?);
                        }
                        MessagePattern::SS => {
                            self.state
                                .mix_key(self.keyset.expect_s().ecdh(&self.keyset.expect_rs())?);
                        }
                    }
                }

                // 2. Calls DecryptAndHash() on the remaining bytes of the message and stores the
                // output into payload_buffer.
                let output = self.state.decrypt_and_hash(&message[pos..])?;
                payload_buffer.extend(output);

                Ok(HandshakeAct::Buffer(payload_buffer))
            }
            None => {
                // 3. If there are no more message patterns returns two new CipherState objects by
                // calling Split().
                let (c1, c2) = self.state.split();
                Ok(HandshakeAct::Split(c1, c2))
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum HandshakeAct {
    Buffer(Vec<u8>),
    Split(CipherState, CipherState),
}

#[derive(Clone, Eq, PartialEq)]
pub enum NoiseState<E: Ecdh, D: Digest> {
    Handshake(HandshakeState<E, D>),
    Active {
        sending_cipher: CipherState,
        receiving_cipher: CipherState,
        handshake_hash: HandshakeHash<D>,
        remote_static_pubkey: Option<E::Pk>,
    },
}

impl<E: Ecdh, D: Digest> NoiseState<E, D> {
    /// Takes incoming data from the remote peer, advances internal state machine
    /// and returns a data to be sent to the remote peer for the next handshake
    /// act. If the handshake is over, returns an empty vector. On subsequent
    /// calls return [`NoiseError::HandshakeComplete`] error.
    pub fn advance(&mut self, input: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let (output, payload) = self.advance_with_payload(input, &[])?;
        if !payload.is_empty() {
            Err(NoiseError::PayloadNotEmpty)
        } else {
            Ok(output)
        }
    }

    pub fn advance_with_payload(
        &mut self,
        input: &[u8],
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), NoiseError> {
        match self {
            NoiseState::Handshake(handshake) => {
                let act = handshake.read_message(input)?;
                let read_payload = match act {
                    HandshakeAct::Buffer(payload) => payload,
                    HandshakeAct::Split(sending_cipher, receiving_cipher) => {
                        *self = NoiseState::Active {
                            sending_cipher,
                            receiving_cipher,
                            handshake_hash: handshake.state.get_handshake_hash(),
                            remote_static_pubkey: handshake.keyset.rs.clone(),
                        };
                        return Ok((vec![], vec![]));
                    }
                };
                let act = handshake.write_message(payload)?;
                match act {
                    HandshakeAct::Buffer(buffer) => Ok((buffer, read_payload)),
                    HandshakeAct::Split(sending_cipher, receiving_cipher) => {
                        *self = NoiseState::Active {
                            sending_cipher,
                            receiving_cipher,
                            handshake_hash: handshake.state.get_handshake_hash(),
                            remote_static_pubkey: handshake.keyset.rs.clone(),
                        };
                        Ok((vec![], vec![]))
                    }
                }
            }
            NoiseState::Active { .. } => Err(NoiseError::HandshakeComplete),
        }
    }
}
