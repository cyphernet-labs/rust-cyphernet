// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2022-2023 Cyphernet DAO, Switzerland
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

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! Pure rust SOCKS5 protocol implementation for a client with zero dependencies.
//!
//! The library is a part of [rust cyphernet suite](https://github.com/Cyphernet-DAO/rust-cyphernet)
//! and used by it for generic implementation of noise protocol framework abstracted
//! from the underlying curve.

#[macro_use]
extern crate amplify;

mod encoding;
mod error;

use std::io;

use cypheraddr::{Host, HostName, NetAddr};
pub use error::ServerError;

use crate::encoding::{Encoding, EncodingError, DOMAIN, IPV4, IPV6};

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from]
    Server(ServerError),
    #[from]
    Encoding(EncodingError),

    /// invalid server reply
    InvalidReply,

    /// not supported SOCKS protocol version {0}
    VersionNotSupported(u8),

    /// server requires authentication with an unsupported method
    AuthRequired,

    /// SOCKS5 connection is established, the handshake is complete
    Completed,

    /// connection is closed due to a failure
    Closed,
}

#[derive(Debug)]
pub enum Socks5 {
    Initial(NetAddr<HostName>, bool),
    Connected(NetAddr<HostName>),
    Awaiting,
    Reading(u8, u8),
    Active(NetAddr<HostName>),
    Rejected(ServerError),
    Failed(Error),
}

impl Socks5 {
    pub fn with(addr: impl Into<NetAddr<HostName>>, force_proxy: bool) -> Self {
        Self::Initial(addr.into(), force_proxy)
    }

    pub fn advance(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Socks5::Initial(addr, false) if !addr.requires_proxy() => {
                *self = Socks5::Active(addr.clone());
                Ok(vec![])
            }
            Socks5::Initial(addr, _) => {
                debug_assert!(input.is_empty());
                let out = vec![0x05, 0x01, 0x00];
                *self = Socks5::Connected(addr.clone());
                Ok(out)
            }
            Socks5::Connected(addr) => {
                debug_assert_eq!(input.len(), 2);
                if input[0] != 0x05 {
                    *self = Socks5::Failed(Error::VersionNotSupported(input[0]));
                    return Err(Error::VersionNotSupported(input[0]));
                }
                if input[1] != 0x00 {
                    *self = Socks5::Failed(Error::AuthRequired);
                    return Err(Error::AuthRequired);
                }

                let mut out = vec![0x05, 0x01, 0x00];
                addr.encode(&mut out)?;
                *self = Socks5::Awaiting;
                Ok(out)
            }
            Socks5::Awaiting => {
                debug_assert_eq!(input.len(), 5);
                if input[0] != 0x05 {
                    *self = Socks5::Failed(Error::VersionNotSupported(input[0]));
                    return Err(Error::VersionNotSupported(input[0]));
                }
                if input[1] != 0x00 {
                    let err = ServerError::from(input[1]);
                    *self = Socks5::Rejected(err);
                    return Err(Error::Closed);
                }
                *self = Socks5::Reading(input[3], input[4]);
                Ok(vec![])
            }
            Socks5::Reading(code1, code2) => {
                let mut vec = Vec::with_capacity(input.len() + 2);
                vec.extend_from_slice(&[*code1, *code2]);
                vec.extend_from_slice(input);
                let mut cursor = io::Cursor::new(vec);
                let addr = NetAddr::<HostName>::decode(&mut cursor)?;
                *self = Socks5::Active(addr);
                Ok(vec![])
            }
            Socks5::Active(_) => Err(Error::Completed),
            Socks5::Rejected(_) | Socks5::Failed(_) => Err(Error::Closed),
        }
    }

    pub fn next_read_len(&self) -> usize {
        match self {
            Socks5::Initial(_, _) => 0,
            Socks5::Connected(_) => 2,
            Socks5::Awaiting => 5,
            Socks5::Reading(ty, _) if *ty == IPV4 => 5,
            Socks5::Reading(ty, _) if *ty == IPV6 => 17,
            Socks5::Reading(ty, len) if *ty == DOMAIN => *len as usize + 1,
            Socks5::Reading(_, _) => 1,
            Socks5::Active(_) | Socks5::Rejected(_) | Socks5::Failed(_) => 0,
        }
    }
}
