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

use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::str::FromStr;
use std::{fmt, io, vec};

use crate::addr::{Addr, AddrParseError, Host, InetHost, Localhost, ToSocketAddr};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetAddr<H: Host> {
    pub host: H,
    pub port: u16,
}

impl<H: Localhost> NetAddr<H> {
    pub fn localhost(port: u16) -> Self {
        Self {
            host: H::localhost(),
            port,
        }
    }
}

impl<H: Host> Host for NetAddr<H> {}

impl<H: Host> Addr for NetAddr<H> {
    fn port(&self) -> u16 { self.port }
}

impl<H: Host> Display for NetAddr<H>
where H: Display
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.host, f)?;
        write!(f, ":{}", self.port)
    }
}

impl<H: Host> FromStr for NetAddr<H>
where
    H: FromStr,
    AddrParseError: From<H::Err>,
{
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.rsplit_once(':') {
            None => Err(AddrParseError::PortAbsent),
            Some((host, port)) => Ok(NetAddr {
                host: H::from_str(host)?,
                port: u16::from_str(port).map_err(|_| AddrParseError::InvalidPort)?,
            }),
        }
    }
}

impl<H: Host> From<SocketAddr> for NetAddr<H>
where H: From<IpAddr>
{
    fn from(socket_addr: SocketAddr) -> Self {
        NetAddr {
            host: H::from(socket_addr.ip()),
            port: socket_addr.port(),
        }
    }
}

impl<H: Host> From<SocketAddrV4> for NetAddr<H>
where H: From<Ipv4Addr>
{
    fn from(socket_addr: SocketAddrV4) -> Self {
        NetAddr {
            host: H::from(*socket_addr.ip()),
            port: socket_addr.port(),
        }
    }
}

impl<H: Host> From<SocketAddrV6> for NetAddr<H>
where H: From<Ipv6Addr>
{
    fn from(socket_addr: SocketAddrV6) -> Self {
        NetAddr {
            host: H::from(*socket_addr.ip()),
            port: socket_addr.port(),
        }
    }
}

impl ToSocketAddr for NetAddr<IpAddr> {
    fn to_socket_addr(&self) -> SocketAddr { SocketAddr::new(self.host, self.port) }
}

impl ToSocketAddr for NetAddr<Ipv4Addr> {
    fn to_socket_addr(&self) -> SocketAddr { SocketAddr::new(self.host.into(), self.port) }
}

impl ToSocketAddr for NetAddr<Ipv6Addr> {
    fn to_socket_addr(&self) -> SocketAddr { SocketAddr::new(self.host.into(), self.port) }
}

impl ToSocketAddrs for NetAddr<IpAddr> {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        Ok(SocketAddr::new(self.host, self.port).to_socket_addrs()?.collect::<Vec<_>>().into_iter())
    }
}

#[cfg(feature = "dns")]
impl ToSocketAddrs for NetAddr<InetHost> {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        match &self.host {
            InetHost::Dns(dns) => (dns.as_str(), self.port).to_socket_addrs(),
            InetHost::Ip(ip) => Ok(SocketAddr::new(*ip, self.port)
                .to_socket_addrs()?
                .collect::<Vec<_>>()
                .into_iter()),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PartialAddr<H: Host, const DEFAULT_PORT: u16> {
    pub host: H,
    pub port: Option<u16>,
}

impl<H: Localhost, const DEFAULT_PORT: u16> PartialAddr<H, DEFAULT_PORT> {
    pub fn localhost(port: Option<u16>) -> Self {
        Self {
            host: H::localhost(),
            port,
        }
    }
}

impl<H: Host, const DEFAULT_PORT: u16> Host for PartialAddr<H, DEFAULT_PORT> {}

impl<H: Host, const DEFAULT_PORT: u16> Localhost for PartialAddr<H, DEFAULT_PORT>
where H: Localhost
{
    fn localhost() -> Self {
        PartialAddr {
            host: H::localhost(),
            port: None,
        }
    }
}

impl<H: Host, const DEFAULT_PORT: u16> Addr for PartialAddr<H, DEFAULT_PORT> {
    fn port(&self) -> u16 { self.port.unwrap_or(DEFAULT_PORT) }
}

impl<H: Host, const DEFAULT_PORT: u16> From<PartialAddr<H, DEFAULT_PORT>> for NetAddr<H> {
    fn from(addr: PartialAddr<H, DEFAULT_PORT>) -> Self {
        NetAddr {
            port: addr.port(),
            host: addr.host,
        }
    }
}

impl<H: Host, const DEFAULT_PORT: u16> Display for PartialAddr<H, DEFAULT_PORT>
where H: Display
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.host, f)?;
        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }
        Ok(())
    }
}

impl<H: Host, const DEFAULT_PORT: u16> FromStr for PartialAddr<H, DEFAULT_PORT>
where
    H: FromStr,
    AddrParseError: From<H::Err>,
{
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((host, port)) = s.rsplit_once(':') {
            Ok(PartialAddr {
                host: H::from_str(host)?,
                port: Some(u16::from_str(port).map_err(|_| AddrParseError::InvalidPort)?),
            })
        } else {
            Ok(PartialAddr {
                host: H::from_str(s)?,
                port: None,
            })
        }
    }
}
