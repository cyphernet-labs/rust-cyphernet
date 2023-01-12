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

use std::net::{IpAddr, ToSocketAddrs};

#[cfg(feature = "dns")]
use crate::InetHost;
use crate::{Addr, Host, HostName, NetAddr};

/// A hack to apply feature gates to the generic defaults
#[cfg(feature = "dns")]
type DefaultAddr = NetAddr<InetHost>;
#[cfg(not(feature = "dns"))]
type DefaultAddr = NetAddr<IpAddr>;

/// An host which should be accessed via a proxy - or accessed directly.
#[derive(Clone, PartialEq, Eq, Hash, Debug, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum ProxiedHost<P: ToSocketAddrs + Addr = DefaultAddr> {
    #[cfg(feature = "dns")]
    #[from]
    #[from(IpAddr)]
    #[from(std::net::Ipv4Addr)]
    #[from(std::net::Ipv6Addr)]
    Native(InetHost),

    #[cfg(not(feature = "dns"))]
    #[from(IpAddr)]
    #[from(std::net::Ipv4Addr)]
    #[from(std::net::Ipv6Addr)]
    Native(IpAddr),

    Ip(IpAddr, P),

    #[cfg(feature = "dns")]
    Dns(String, P),

    #[cfg(feature = "tor")]
    Tor(super::tor::OnionAddrV3, P),

    #[cfg(feature = "i2p")]
    I2p(super::i2p::I2pAddr, P),

    #[cfg(feature = "nym")]
    Nym(super::nym::NymAddr, P),
}

impl<P: ToSocketAddrs + Addr> Host for ProxiedHost<P> {}

impl<P: ToSocketAddrs + Addr> ProxiedHost<P> {
    pub fn with_proxy(host: HostName, proxy: P) -> Self {
        match host {
            HostName::Ip(ip) => ProxiedHost::Ip(ip, proxy),
            #[cfg(feature = "dns")]
            HostName::Dns(dns) => ProxiedHost::Dns(dns, proxy),
            #[cfg(feature = "tor")]
            HostName::Tor(tor) => ProxiedHost::Tor(tor, proxy),
            #[cfg(feature = "i2p")]
            HostName::I2p(i2p) => ProxiedHost::I2p(i2p, proxy),
            #[cfg(feature = "nym")]
            HostName::Nym(nym) => ProxiedHost::Nym(nym, proxy),
        }
    }

    pub fn proxy(&self) -> Option<&P> {
        match self {
            ProxiedHost::Native(_) => None,
            ProxiedHost::Ip(_, proxy) => Some(proxy),
            #[cfg(feature = "dns")]
            ProxiedHost::Dns(_, proxy) => Some(proxy),
            #[cfg(feature = "tor")]
            ProxiedHost::Tor(_, proxy) => Some(proxy),
            #[cfg(feature = "i2p")]
            ProxiedHost::I2p(_, proxy) => Some(proxy),
            #[cfg(feature = "nym")]
            ProxiedHost::Nym(_, proxy) => Some(proxy),
        }
    }
}

/// An address which must be accessed through proxy. Usually this is SOCLS5
/// proxy, but at the type level there is no information about the specific
/// proxy type which should be used (however they may contained within the
/// generic type parameter `A`).
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProxiedAddr<A: Addr = NetAddr<HostName>> {
    #[cfg(feature = "dns")]
    pub proxy_addr: NetAddr<InetHost>,
    #[cfg(not(feature = "dns"))]
    pub proxy_addr: std::net::SocketAddr,
    pub remote_addr: A,
}

impl<A: Addr> Host for ProxiedAddr<A> {}

impl<A: Addr> Addr for ProxiedAddr<A> {
    fn port(&self) -> u16 { self.remote_addr.port() }
}
