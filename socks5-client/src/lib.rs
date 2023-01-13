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

use std::io;

use cypheraddr::{HostName, NetAddr};
pub use error::ServerError;

use crate::encoding::{Encoding, EncodingError};

pub type Reply = Result<NetAddr<HostName>, ServerError>;

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
    Initial(NetAddr<HostName>),
    Connected(NetAddr<HostName>),
    Connecting,
    Active(NetAddr<HostName>),
    Rejected(ServerError),
    Failed(Error),
}

impl Socks5 {
    pub fn with(addr: impl Into<NetAddr<HostName>>) -> Self { Self::Initial(addr.into()) }

    pub fn advance(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Socks5::Initial(addr) => {
                debug_assert!(input.is_empty());
                let out = vec![0x05, 0x01, 0x00];
                *self = Socks5::Connected(addr.clone());
                Ok(out)
            }
            Socks5::Connected(addr) => {
                if input.len() != 2 {
                    *self = Socks5::Failed(Error::InvalidReply);
                    return Err(Error::InvalidReply);
                }
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
                *self = Socks5::Connecting;
                Ok(out)
            }
            Socks5::Connecting => {
                let mut cursor = io::Cursor::new(input);
                match Reply::decode(&mut cursor)? {
                    Ok(addr) => {
                        *self = Socks5::Active(addr);
                        Ok(vec![])
                    }
                    Err(code) => {
                        *self = Socks5::Rejected(code);
                        Err(Error::Closed)
                    }
                }
            }
            Socks5::Active(_) => Err(Error::Completed),
            _ => Err(Error::Closed),
        }
    }
}
