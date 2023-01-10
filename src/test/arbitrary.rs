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

use ::ed25519::{KeyPair, Seed};
use quickcheck::Arbitrary;

use crate::crypto::ed25519::PublicKey;

#[derive(Clone, Debug)]
pub struct ByteArray<const N: usize>([u8; N]);

impl<const N: usize> ByteArray<N> {
    pub fn into_inner(self) -> [u8; N] { self.0 }
}

impl<const N: usize> Arbitrary for ByteArray<N> {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut bytes: [u8; N] = [0; N];
        for byte in &mut bytes {
            *byte = u8::arbitrary(g);
        }
        Self(bytes)
    }
}

impl Arbitrary for PublicKey {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let bytes: ByteArray<32> = Arbitrary::arbitrary(g);
        let seed = Seed::new(bytes.into_inner());
        let keypair = KeyPair::from_seed(seed);

        PublicKey::from(keypair.pk)
    }
}
