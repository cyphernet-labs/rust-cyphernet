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

pub trait Digest: Sized {
    const DIGEST_NAME: &'static str;
    const OUTPUT_LEN: usize;
    const BLOCK_LEN: usize;

    type Output: Copy + Eq + Sized + Send + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    fn new() -> Self;
    fn with_output_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != Self::OUTPUT_LEN {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&slice);
        todo!()
    }

    fn digest(data: impl AsRef<[u8]>) -> Self::Output { Self::digest_concat([data]) }
    fn digest_concat(data: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Self::Output {
        let mut engine = Self::new();
        for item in data {
            engine.input(item);
        }
        engine.finalize()
    }
    fn input(&mut self, data: impl AsRef<[u8]>);
    fn finalize(self) -> Self::Output;
}

pub trait Digest32: Digest<Output = [u8; 32]> {}
pub trait Digest64: Digest<Output = [u8; 64]> {}

pub trait KeyedDigest: Digest {
    type Key;
    fn with_key(key: Self::Key) -> Self;
}

pub trait HmacDigest<D: Digest>: Digest {
    fn with_key(key: impl AsRef<[u8]>) -> Self;
}

#[cfg(feature = "sha2")]
mod sha2 {
    use ::sha2::digest::{FixedOutput, Update};

    use super::*;

    impl Digest for Sha256 {
        const DIGEST_NAME: &'static str = "SHA256";
        const OUTPUT_LEN: usize = 32;
        const BLOCK_LEN: usize = 64;
        type Output = [u8; 32];

        fn new() -> Self { Sha256::default() }

        fn input(&mut self, data: impl AsRef<[u8]>) { self.update(data.as_ref()); }

        fn finalize(self) -> Self::Output {
            let mut buf = [0u8; 32];
            let out = &*self.finalize_fixed();
            buf.copy_from_slice(out);
            buf
        }
    }
}
#[cfg(feature = "sha2")]
pub use ::sha2::Sha256;

pub struct Hmac<D: Digest> {
    iengine: D,
    oengine: D,
}

impl<D: Digest> Hmac<D> {
    pub fn keyed(key: impl AsRef<[u8]>) -> Self {
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

        Self { iengine, oengine }
    }
}

impl<D: Digest> Digest for Hmac<D> {
    const DIGEST_NAME: &'static str = "HMAC";
    const OUTPUT_LEN: usize = D::OUTPUT_LEN;
    const BLOCK_LEN: usize = D::BLOCK_LEN;
    type Output = D::Output;

    fn new() -> Self { Self::keyed(&[]) }

    fn input(&mut self, data: impl AsRef<[u8]>) { self.iengine.input(data); }

    fn finalize(mut self) -> Self::Output {
        let ihash = self.iengine.finalize();
        self.oengine.input(&ihash.as_ref()[..]);
        self.oengine.finalize()
    }
}

impl<D: Digest> HmacDigest<D> for Hmac<D> {
    fn with_key(key: impl AsRef<[u8]>) -> Self { Self::keyed(key) }
}
