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

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use cypher::x25519::SharedSecret;

use crate::error::EncryptionError;
use crate::NoiseNonce;

fn _nonce(nonce: NoiseNonce) -> Nonce {
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce[4..].copy_from_slice(&nonce.to_le_bytes());
    *Nonce::from_slice(&chacha_nonce[..])
}

fn _cypher(key: &[u8]) -> ChaCha20Poly1305 {
    let key = Key::from_slice(key);
    ChaCha20Poly1305::new(key)
}

/// Encrypt a plaintext with associated data using the key and nonce.
///
/// # Returns
///
/// Returns the encrypted msg, which is also copied to ciphertext array, if
/// provided.
///
/// # Panics
///
/// Function panics if `plaintext` and `cyphertext` have different length.
pub(crate) fn encrypt(
    key: SharedSecret,
    nonce: NoiseNonce,
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };
    _cypher(key.as_ref()).encrypt(&_nonce(nonce), payload).map_err(EncryptionError::from)
}

/// Decrypts the ciphertext with key, nonce and associated data.
///
/// # Returns
///
/// Returns the decrypted msg, which is also copied to plaintext array, if
/// provided.
///
/// # Panics
///
/// Function panics if `plaintext` and `cyphertext` have different length.
pub(crate) fn decrypt(
    key: SharedSecret,
    nonce: NoiseNonce,
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };
    _cypher(key.as_ref()).decrypt(&_nonce(nonce), payload).map_err(EncryptionError::from)
}

pub(crate) fn rekey(k: SharedSecret) -> SharedSecret {
    // Returns a new 32-byte cipher key as a pseudorandom function of k. If this function is not
    // specifically defined for some set of cipher functions, then it defaults to returning the
    // first 32 bytes from ENCRYPT(k, maxnonce, zerolen, zeros), where maxnonce equals 264-1,
    // zerolen is a zero-length byte sequence, and zeros is a sequence of 32 bytes filled with
    // zeros.

    let key = encrypt(k, u64::MAX, &[], &[0u8; 32]).expect("error re-keying");
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&key);
    SharedSecret::from(buf)
}
