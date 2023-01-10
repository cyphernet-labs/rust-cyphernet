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

use hmac::{Hmac, Mac};
use sha2::Sha256;

// Allows 1 or more inputs and "concatenates" them together using the input()
// function of HmacEngine::<Sha256>
fn hmac_sha256(
    key: impl AsRef<[u8]>,
    inputs: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> [u8; 32] {
    let mut engine =
        Hmac::<Sha256>::new_from_slice(key.as_ref()).expect("HMAC must take key of any size");
    for input in inputs {
        engine.update(input.as_ref());
    }
    *engine.finalize().into_bytes().as_ref()
}

/// Implements HKDF defined in [RFC 5869](https://tools.ietf.org/html/rfc5869pub).
/// Returns the first 64 octets as two 32 byte arrays.
pub(crate) fn derive(salt: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    // 2.1.  Notation
    //
    // HMAC-Hash denotes the HMAC function [HMAC] instantiated with hash
    // function 'Hash'.  HMAC always has two arguments: the first is a key
    // and the second an input (or message).  (Note that in the extract
    // step, 'IKM' is used as the HMAC input, not as the HMAC key.)
    //
    // When the message is composed of several elements we use concatenation
    // (denoted |) in the second argument; for example, HMAC(K, elem1 |
    // elem2 | elem3).

    // 2.2. Step 1: Extract
    // HKDF-Extract(salt, IKM) -> PRK
    // PRK = HMAC-Hash(salt, IKM)
    let prk = hmac_sha256(salt, [ikm]);

    // 2.3.  Step 2: Expand
    // HKDF-Expand(PRK, info, L) -> OKM
    // N = ceil(L/HashLen)
    // T = T(1) | T(2) | T(3) | ... | T(N)
    // OKM = first L octets of T
    //
    // where:
    // T(0) = empty string (zero length)
    // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    let t1 = hmac_sha256(prk, [&[1]]);
    // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    let t2 = hmac_sha256(prk, [&t1[..], &[2][..]]);

    (t1, t2)
}

// Appendix A.  Test Vectors
#[cfg(test)]
mod test {
    use amplify::hex::FromHex;

    use super::derive;

    // Test with SHA-256 and zero-length salt/info
    // Our implementation uses a zero-length info field and returns the first 64
    // octets. As a result, this test will be a prefix match on the vector
    // provided by the RFC which is 42 bytes.
    #[test]
    fn rfc_5869_test_vector_3() {
        let ikm = Vec::<u8>::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let (t1, t2) = derive(&[], &ikm);

        let mut calculated_okm = t1.to_vec();
        calculated_okm.extend_from_slice(&t2);
        calculated_okm.truncate(42);
        assert_eq!(calculated_okm, Vec::<u8>::from_hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8").unwrap());
    }
}
