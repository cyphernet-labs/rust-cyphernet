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

//! Rust library providing a set of address data types with minimal dependencies
//! which allow simple use of.
//! - Tor, Nym, I2P and other mix networks and SOCKS proxies;
//! - P2P addresses with node public keys.
//!
//! The crate may be used in a way that prevents using DNS names (outside mixnet
//! scope).
//!
//! The library is a part of [rust cyphernet suite](https://github.com/Cyphernet-DAO/rust-cyphernet).
//! Cyphernet is a set of libraries for privacy-preserving networking & internet
//! applications.
//!
//! Network addresses provided by the library include the following types:
//! * [`InetHost`] - IP addr or DNS name
//! * [`HostName`] - IP, DNS, Tor, I2P, Nym host name (no port or proxy information)
//! * [`NetAddr`] - any type of host name + port information
//! * [`PartialAddr`] - any type of host name + optional port, which defaults to generic const if
//!   not provided
//! * [`PeerAddr`] - any of the above addresses + node public key for authentication
//! * [`ProxiedHost`] - host name + proxy (there are IP/DNS w/o proxy and with proxy)
//! * [`ProxiedAddr`] - any of the above addresses + proxy (thus IP/DNS is always proxied)
//!
//! The library tries to minimize number of dependencies. Most of its
//! functionality is available via non-default features, like:
//! - `mixnets`: supports for mixnet network addresses, including `tor`, `nym`, `i2p` (may require
//!   additional crypto libraries for parsing public keys)
//! - `serde`: encoding for addresses types
//! - `dns`: enable use of DNS names alongside IP addresses and mixnet names.

#[macro_use]
extern crate amplify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod host;
#[cfg(feature = "i2p")]
pub mod i2p;
mod net;
#[cfg(feature = "nym")]
pub mod nym;
#[cfg(any(feature = "p2p-ed25519", feature = "p2p-secp256k1"))]
mod p2p;
mod proxied;
#[cfg(feature = "tor")]
pub mod tor;

pub use host::HostName;
#[cfg(feature = "dns")]
pub use host::InetHost;
pub use net::{NetAddr, PartialAddr};
#[cfg(any(feature = "p2p-ed25519", feature = "p2p-secp256k1"))]
pub use p2p::{PeerAddr, PeerAddrParseError};
pub use proxied::{ProxiedAddr, ProxiedHost};

/// Marker trait for all types of host names.
pub trait Host {
    fn requires_proxy(&self) -> bool;
}

impl Host for std::net::IpAddr {
    fn requires_proxy(&self) -> bool { false }
}

impl Host for std::net::Ipv4Addr {
    fn requires_proxy(&self) -> bool { false }
}

impl Host for std::net::Ipv6Addr {
    fn requires_proxy(&self) -> bool { false }
}

impl Host for std::net::SocketAddr {
    fn requires_proxy(&self) -> bool { false }
}

impl Host for std::net::SocketAddrV4 {
    fn requires_proxy(&self) -> bool { false }
}

impl Host for std::net::SocketAddrV6 {
    fn requires_proxy(&self) -> bool { false }
}

/// Trait for address types which can represent a localhost address.
pub trait Localhost: Host {
    /// Returns a localhost address expressed by the means of this specofic
    /// address type.
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

/// Marker trait for all network addresses which can be connected to.
pub trait Addr: Host {
    /// Port number for the service.
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

/// Error parsing network address.
#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AddrParseError {
    #[from]
    #[cfg(feature = "tor")]
    #[display(inner)]
    /// invalid Tor ONION address
    Tor(tor::OnionAddrParseError),

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
