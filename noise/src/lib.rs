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

#[macro_use]
extern crate amplify;

pub mod error;
mod patterns;
mod cipher;
mod hkdf;
mod state;

pub use state::{CipherState, HandshakeState};

pub type SymmetricKey = [u8; 32];
pub type ChainingKey<D: cypher::Digest> = D::Output;
pub type HandshakeHash<D: cypher::Digest> = D::Output;
pub type NoiseNonce = u64;
