//! Cyphernet node address types

#[cfg(feature = "i2p")]
pub mod i2p;
mod net;
mod node;
#[cfg(feature = "nym")]
pub mod nym;
mod proxied;
mod socket;
mod universal;

pub use net::{HostAddr, NetAddr};
pub use node::{PeerAddr, PeerAddrParseError};
pub use proxied::ProxiedAddr;
pub use socket::SocketAddr;
pub use universal::{ProxyError, UniversalAddr};

pub trait Addr {
    fn port(&self) -> u16;
}

pub trait ToSocketAddr {
    fn to_socket_addr(&self) -> std::net::SocketAddr;
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
    fn port(&self) -> u16 {
        std::net::SocketAddrV4::port(self)
    }
}

impl Addr for std::net::SocketAddrV6 {
    fn port(&self) -> u16 {
        std::net::SocketAddrV6::port(self)
    }
}

impl ToSocketAddr for std::net::SocketAddr {
    fn to_socket_addr(&self) -> std::net::SocketAddr {
        *self
    }
}

impl ToSocketAddr for std::net::SocketAddrV4 {
    fn to_socket_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::V4(*self)
    }
}

impl ToSocketAddr for std::net::SocketAddrV6 {
    fn to_socket_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::V6(*self)
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AddrParseError {
    #[from]
    #[cfg(feature = "tor")]
    #[display(inner)]
    /// invalid Tor ONION address
    Tor(torut::onion::OnionAddressParseError),

    #[from]
    #[display(inner)]
    /// invalid IP or socket address
    InvalidSocketAddr(std::net::AddrParseError),

    /// unexpected or absent URL scheme. The address should start with '{0}'
    InvalidUrlScheme(&'static str),

    /// invalid port number
    InvalidPort,

    /// unknown network address format
    UnknownAddressFormat,
}
