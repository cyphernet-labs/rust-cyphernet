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

// TODO: Move to amplify crate

use std::fmt::Display;

use amplify::hex::ToHex;
use bech32::ToBase32;

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum Encoding {
    Base16,

    #[cfg(feature = "multibase")]
    Base32,

    #[cfg(feature = "bech32")]
    Bech32(String, bech32::Variant),

    #[cfg(feature = "multibase")]
    Base58,

    #[cfg(feature = "multibase")]
    Base64,

    #[cfg(feature = "multibase")]
    Multibase(multibase::Base),
}

impl Encoding {
    pub fn encode(&self, data: &[u8]) -> String {
        #[cfg(feature = "multibase")]
        use multibase::{encode, Base};

        match self {
            Encoding::Base16 => data.to_hex(),

            #[cfg(feature = "multibase")]
            Encoding::Base32 => {
                let mut s: String = encode(Base::Base32Lower, data);
                s.remove(0);
                s
            }

            #[cfg(feature = "bech32")]
            Encoding::Bech32(hrp, variant) => {
                let b32 = data.to_base32();
                bech32::encode(hrp, b32, *variant).expect("invalid HRP")
            }

            #[cfg(feature = "multibase")]
            Encoding::Base58 => {
                let mut s: String = encode(Base::Base58Btc, data);
                s.remove(0);
                s
            }

            #[cfg(feature = "multibase")]
            Encoding::Base64 => {
                let mut s: String = encode(Base::Base64, data);
                s.remove(0);
                s
            }

            #[cfg(feature = "multibase")]
            Encoding::Multibase(base) => encode(*base, data),
        }
    }
}

pub trait MultiDisplay<F> {
    type Display: Display;

    fn display(&self) -> Self::Display
    where F: Default {
        self.display_fmt(&default!())
    }
    fn display_fmt(&self, f: &F) -> Self::Display;
}
