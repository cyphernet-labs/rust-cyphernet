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

use std::borrow::Borrow;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::net::{self, ToSocketAddrs};
use std::str::FromStr;

use cypher::EcPk;

use crate::{Addr, AddrParseError, Host, NetAddr, PartialAddr, ToSocketAddr};

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum PeerAddrParseError<Id: Debug>
where
    Id: FromStr,
    <Id as FromStr>::Err: std::error::Error,
{
    #[from]
    #[from(net::AddrParseError)]
    #[display(inner)]
    Addr(AddrParseError),

    /// invalid peer key. Details: {0}
    Key(<Id as FromStr>::Err),

    /// invalid peer address format. Peer address must contain peer key and peer
    /// network address, separated by '@'
    InvalidFormat,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct PeerAddr<Id: EcPk, A: Addr> {
    pub id: Id,
    pub addr: A,
}

impl<Id: EcPk, A: Addr> PeerAddr<Id, A> {
    pub fn new(id: Id, addr: A) -> Self { Self { id, addr } }
}

impl<Id: EcPk, A: Addr> Borrow<Id> for PeerAddr<Id, A> {
    fn borrow(&self) -> &Id { &self.id }
}

impl<Id: EcPk, A: Addr> Host for PeerAddr<Id, A> {
    fn requires_proxy(&self) -> bool { self.addr.requires_proxy() }
}

impl<Id: EcPk, A: Addr> Addr for PeerAddr<Id, A> {
    fn port(&self) -> u16 { self.addr.port() }
}

impl<Id: EcPk, A: Addr + ToSocketAddr> ToSocketAddr for PeerAddr<Id, A> {
    fn to_socket_addr(&self) -> net::SocketAddr { self.addr.to_socket_addr() }
}

impl<Id: EcPk, A: Addr> Display for PeerAddr<Id, A>
where
    Id: Display,
    A: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "{}@{}", self.id, self.addr) }
}

impl<Id: EcPk, A: Addr> FromStr for PeerAddr<Id, A>
where
    Id: FromStr + Debug,
    <Id as FromStr>::Err: std::error::Error,
    A: FromStr,
    <A as FromStr>::Err: Into<PeerAddrParseError<Id>>,
{
    type Err = PeerAddrParseError<Id>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((pk, addr)) = s.split_once('@') {
            Ok(PeerAddr {
                id: Id::from_str(pk).map_err(PeerAddrParseError::Key)?,
                addr: A::from_str(addr).map_err(<A as FromStr>::Err::into)?,
            })
        } else {
            Err(PeerAddrParseError::InvalidFormat)
        }
    }
}

impl<Id: EcPk, H: Host, const DEFAULT_PORT: u16> From<PeerAddr<Id, PartialAddr<H, DEFAULT_PORT>>>
    for PeerAddr<Id, NetAddr<H>>
{
    fn from(peer: PeerAddr<Id, PartialAddr<H, DEFAULT_PORT>>) -> Self {
        PeerAddr {
            addr: peer.addr.into(),
            id: peer.id,
        }
    }
}

impl<Id: EcPk, A: Addr, To: Host> From<PeerAddr<Id, A>> for NetAddr<To>
where NetAddr<To>: From<A>
{
    fn from(peer: PeerAddr<Id, A>) -> Self { peer.addr.into() }
}

impl<Id: EcPk, A: Addr + Into<net::SocketAddr>> From<PeerAddr<Id, A>> for net::SocketAddr {
    fn from(peer: PeerAddr<Id, A>) -> Self { peer.addr.into() }
}

impl<Id: EcPk, A: Addr> PeerAddr<Id, A> {
    pub fn with(id: impl Into<Id>, addr: impl Into<A>) -> Self {
        PeerAddr {
            id: id.into(),
            addr: addr.into(),
        }
    }
}

impl<Id: EcPk, A> ToSocketAddrs for PeerAddr<Id, A>
where A: Addr + ToSocketAddrs
{
    type Iter = A::Iter;

    fn to_socket_addrs(&self) -> io::Result<A::Iter> { self.addr.to_socket_addrs() }
}
