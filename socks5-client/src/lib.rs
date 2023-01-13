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

//! Pure rust SOCKS5 protocol implementation for a client with zero dependencies.
//!
//! The library is a part of [rust cyphernet suite](https://github.com/Cyphernet-WG/rust-cyphernet)
//! and used by it for generic implementation of noise protocol framework abstracted
//! from the underlying curve.

#[macro_use]
extern crate amplify;

mod encoding;
mod error;

use std::net::{SocketAddr, ToSocketAddrs};
use std::{io, option};

use cypheraddr::NetAddr;
pub use error::ServerError;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Socks5 {
    proxy: SocketAddr,
}

impl Socks5 {
    pub fn new(proxy_addr: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self {
            proxy: proxy_addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::ErrorKind::InvalidInput)?,
        })
    }
}

impl ToSocketAddrs for Socks5 {
    type Iter = option::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> { Ok(Some(self.proxy).into_iter()) }
}
