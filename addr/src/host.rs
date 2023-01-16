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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::{AddrParseError, Host, Localhost};

/// An Internet host name which can be resolved by standard OS means (and thus
/// accepted by `std::net` methods via use of [`std::net::ToSocketAddrs`] trait,
/// when combined with a port address).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[display(inner)]
#[cfg(feature = "dns")]
pub enum InetHost {
    /// IP name, including both IPv4 and IPv6 variants.
    #[from]
    #[from(Ipv4Addr)]
    #[from(Ipv6Addr)]
    Ip(IpAddr),

    /// DNS-based name.
    Dns(String),
}

#[cfg(feature = "dns")]
impl Host for InetHost {
    fn requires_proxy(&self) -> bool { false }
}

#[cfg(feature = "dns")]
impl Localhost for InetHost {
    fn localhost() -> Self { Self::Ip(Localhost::localhost()) }
}

#[cfg(feature = "dns")]
impl FromStr for InetHost {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match IpAddr::from_str(s) {
            Ok(addr) => Ok(Self::Ip(addr)),
            // TODO: Check charset and format of a DNS name
            Err(_) => Ok(Self::Dns(s.to_owned())),
        }
    }
}

/// A host name covers multiple types which are not necessarily resolved by an
/// OS and may require additional name resolvers (like via SOCKS5 etc). The type
/// doesn't provide an information about the resolver; for that use
/// [`super::ProxiedHost`].
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[display(inner)]
#[non_exhaustive]
pub enum HostName {
    #[from]
    #[from(Ipv4Addr)]
    #[from(Ipv6Addr)]
    Ip(IpAddr),

    #[cfg(feature = "dns")]
    Dns(String),

    #[cfg(feature = "tor")]
    #[from]
    Tor(super::tor::OnionAddrV3),

    #[cfg(feature = "i2p")]
    #[from]
    I2p(super::i2p::I2pAddr),

    #[cfg(feature = "nym")]
    #[from]
    Nym(super::nym::NymAddr),
}

impl Host for HostName {
    fn requires_proxy(&self) -> bool {
        match self {
            HostName::Ip(_) => false,
            #[cfg(feature = "dns")]
            HostName::Dns(_) => false,
            #[allow(unreachable_patterns)]
            _ => true,
        }
    }
}

impl Localhost for HostName {
    fn localhost() -> Self { Self::Ip(Localhost::localhost()) }
}

#[cfg(feature = "dns")]
impl From<InetHost> for HostName {
    fn from(host: InetHost) -> Self {
        match host {
            InetHost::Ip(ip) => HostName::Ip(ip),
            InetHost::Dns(dns) => HostName::Dns(dns),
        }
    }
}

impl FromStr for HostName {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = IpAddr::from_str(s) {
            return Ok(Self::Ip(addr));
        }
        #[cfg(feature = "tor")]
        if s.ends_with(".onion") {
            return super::tor::OnionAddrV3::from_str(s)
                .map(Self::Tor)
                .map_err(AddrParseError::from);
        }
        // TODO: Support Num and I2P
        #[cfg(feature = "dns")]
        {
            Ok(Self::Dns(s.to_owned()))
        }
        #[cfg(not(feature = "dns"))]
        {
            Err(AddrParseError::UnknownAddressFormat)
        }
    }
}
