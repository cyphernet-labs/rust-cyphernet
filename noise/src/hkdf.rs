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

use cypher::Digest;

use crate::ChainingKey;

// Allows 1 or more inputs and "concatenates" them together using the input()
// function of HmacEngine::<Sha256>
fn hmac_hash<D: Digest>(
    key: impl AsRef<[u8]>,
    inputs: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> D::Output {
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    let mut iengine = D::new();
    let mut oengine = D::new();

    let key = key.as_ref();
    if key.len() > D::BLOCK_LEN {
        let hash = D::digest(key);
        for (b_i, b_h) in ipad.iter_mut().zip(&hash.as_ref()[..]) {
            *b_i ^= *b_h;
        }
        for (b_o, b_h) in opad.iter_mut().zip(&hash.as_ref()[..]) {
            *b_o ^= *b_h;
        }
    } else {
        for (b_i, b_h) in ipad.iter_mut().zip(key) {
            *b_i ^= *b_h;
        }
        for (b_o, b_h) in opad.iter_mut().zip(key) {
            *b_o ^= *b_h;
        }
    };

    iengine.input(&ipad[..D::BLOCK_LEN]);
    oengine.input(&opad[..D::BLOCK_LEN]);

    for buf in inputs {
        iengine.input(buf);
    }

    let ihash = iengine.finalize();
    oengine.input(&ihash.as_ref()[..]);
    let ohash = oengine.finalize();
    ohash
}

fn _hkdf<D: Digest>(
    chaining_key: ChainingKey<D>,
    input_material: impl AsRef<[u8]>,
) -> (D::Output, D::Output, D::Output) {
    // Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
    let temp_key = hmac_hash::<D>(chaining_key, [input_material]);

    // Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
    let output1 = hmac_hash::<D>(temp_key.as_ref(), [&[1]]);

    // Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
    let output2 = hmac_hash::<D>(temp_key.as_ref(), [&output1.as_ref()[..], &[2][..]]);

    (temp_key, output1, output2)
}

/// Implements HKDF defined in [RFC 5869](https://tools.ietf.org/html/rfc5869pub).
/// Returns the first 64 octets as two 32 byte arrays.
pub(crate) fn hkdf_2<D: Digest>(
    chaining_key: ChainingKey<D>,
    input_material: impl AsRef<[u8]>,
) -> (D::Output, D::Output) {
    let (_, output1, output2) = _hkdf::<D>(chaining_key, input_material);
    (output1, output2)
}

pub(crate) fn hkdf_3<D: Digest>(
    chaining_key: ChainingKey<D>,
    input_material: impl AsRef<[u8]>,
) -> (D::Output, D::Output, D::Output) {
    let (temp_key, output1, output2) = _hkdf::<D>(chaining_key, input_material);
    // Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
    let output3 = hmac_hash::<D>(temp_key, [&output2.as_ref()[..], &[3][..]]);

    (output1, output3, output2)
}

// Appendix A.  Test Vectors
#[cfg(test)]
mod test {
    use amplify::hex::FromHex;
    use cypher::Sha256;

    use super::hkdf_2;

    // Test with SHA-256 and zero-length salt/info
    // Our implementation uses a zero-length info field and returns the first 64
    // octets. As a result, this test will be a prefix match on the vector
    // provided by the RFC which is 42 bytes.
    #[test]
    fn rfc_5869_test_vector_3() {
        let ikm = Vec::<u8>::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let (t1, t2) = hkdf_2::<Sha256>([0u8; 32], &ikm);

        let mut calculated_okm = t1.to_vec();
        calculated_okm.extend_from_slice(&t2);
        calculated_okm.truncate(42);
        assert_eq!(calculated_okm, Vec::<u8>::from_hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8").unwrap());
    }
}
