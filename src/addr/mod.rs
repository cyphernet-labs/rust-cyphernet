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

//! Cyphernet node address types

mod host;
#[cfg(feature = "i2p")]
pub mod i2p;
mod net;
#[cfg(feature = "nym")]
pub mod nym;
mod p2p;
mod proxied;
#[cfg(feature = "tor")]
pub mod tor;

pub use host::HostName;
#[cfg(feature = "dns")]
pub use host::InetHost;
pub use net::{NetAddr, PartialAddr};
pub use p2p::{PeerAddr, PeerAddrParseError};
pub use proxied::{ProxiedAddr, ProxiedHost};

/// Marker trait for all types of host names
pub trait Host {}

impl Host for std::net::IpAddr {}

impl Host for std::net::Ipv4Addr {}

impl Host for std::net::Ipv6Addr {}

impl Host for std::net::SocketAddr {}

impl Host for std::net::SocketAddrV4 {}

impl Host for std::net::SocketAddrV6 {}

pub trait Localhost: Host {
    fn localhost() -> Self;
}

impl Localhost for std::net::IpAddr {
    fn localhost() -> Self { std::net::Ipv4Addr::LOCALHOST.into() }
}

impl Localhost for std::net::Ipv4Addr {
    fn localhost() -> Self { std::net::Ipv4Addr::LOCALHOST }
}

impl Localhost for std::net::Ipv6Addr {
    fn localhost() -> Self { std::net::Ipv6Addr::LOCALHOST }
}

pub trait Addr: Host {
    fn port(&self) -> u16;
}

impl Addr for std::net::SocketAddr {
    fn port(&self) -> u16 {
        match self {
            std::net::SocketAddr::V4(v4) => v4.port(),
            std::net::SocketAddr::V6(v6) => v6.port(),
        }
    }
}

impl Addr for std::net::SocketAddrV4 {
    fn port(&self) -> u16 { std::net::SocketAddrV4::port(self) }
}

impl Addr for std::net::SocketAddrV6 {
    fn port(&self) -> u16 { std::net::SocketAddrV6::port(self) }
}

/*
pub trait PortOr {
    fn port_or(&self, default: u16) -> u16;
}

impl PortOr for std::net::IpAddr {
    fn port_or(&self, default: u16) -> u16 {
        match self {
            std::net::SocketAddr::V4(v4) => v4.port(),
            std::net::SocketAddr::V6(v6) => v6.port(),
        }
    }
}

impl PortOr for std::net::Ipv4Addr {
    fn port_or(&self, default: u16) -> u16 {
        std::net::SocketAddrV4::port(self)
    }
}

impl PortOr for std::net::Ipv6Addr {
    fn port_or(&self, default: u16) -> u16 {
        std::net::SocketAddrV6::port(self)
    }
}
 */

/// Trait for the types which are able to return socket address to connect to.
/// NBL In case of a proxied addresses this should be an address of the proxy,
/// not the destination host.
///
/// The trait is required since the socket address has to be constructed from a
/// type reference without cloning.
pub trait ToSocketAddr {
    fn to_socket_addr(&self) -> std::net::SocketAddr;
}

impl ToSocketAddr for std::net::SocketAddr {
    fn to_socket_addr(&self) -> std::net::SocketAddr { *self }
}

impl ToSocketAddr for std::net::SocketAddrV4 {
    fn to_socket_addr(&self) -> std::net::SocketAddr { std::net::SocketAddr::V4(*self) }
}

impl ToSocketAddr for std::net::SocketAddrV6 {
    fn to_socket_addr(&self) -> std::net::SocketAddr { std::net::SocketAddr::V6(*self) }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AddrParseError {
    #[from]
    #[cfg(feature = "tor")]
    #[display(inner)]
    /// invalid Tor ONION address
    Tor(tor::OnionAddrError),

    #[from]
    #[display(inner)]
    /// invalid IP or socket address
    InvalidSocketAddr(std::net::AddrParseError),

    /// unexpected or absent URL scheme. The address should start with '{0}'
    InvalidUrlScheme(&'static str),

    /// invalid port number
    InvalidPort,

    /// absent port information
    PortAbsent,

    /// unknown network address format
    UnknownAddressFormat,
}
