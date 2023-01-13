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

use ::hmac::digest::block_buffer::Eager;
use ::hmac::digest::consts::U256;
use ::hmac::digest::core_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore,
};
use ::hmac::digest::typenum::{IsLess, Le, NonZero};
use ::hmac::digest::{FixedOutput, HashMarker};
use ::hmac::Mac;

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

#[cfg(feature = "hmac")]
mod hmac {
    use super::*;

    impl<D: Digest> Digest for Hmac<D>
    where
        D: CoreProxy,
        D::Core: HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        const DIGEST_NAME: &'static str = "HMAC";
        const OUTPUT_LEN: usize = D::OUTPUT_LEN;
        const BLOCK_LEN: usize = D::BLOCK_LEN;
        type Output = D::Output;

        fn new() -> Self { todo!() }

        fn input(&mut self, data: impl AsRef<[u8]>) { self.update(data.as_ref()); }

        fn finalize(self) -> Self::Output {
            let out = &*self.finalize_fixed();
            out.try_into().unwrap_or_else(|_| {
                panic!("HMAC output size mismatches size of digest function output");
            })
        }
    }

    impl<D: Digest> HmacDigest<D> for Hmac<D>
    where
        D: CoreProxy,
        D::Core: HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        fn with_key(key: impl AsRef<[u8]>) -> Self {
            Hmac::new_from_slice(key.as_ref()).expect("HMAC takes key of any size")
        }
    }
}
#[cfg(feature = "hmac")]
pub use ::hmac::Hmac;
