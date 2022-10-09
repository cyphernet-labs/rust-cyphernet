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

pub use net::HostAddr;
pub use node::{LocalNode, NodeId, PeerAddr};
pub use proxied::ProxiedAddr;
pub use socket::SocketAddr;
pub use universal::UniversalAddr;

pub trait Addr: std::fmt::Display + std::str::FromStr {
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
    fn port(&self) -> u16 {
        std::net::SocketAddrV4::port(self)
    }
}

impl Addr for std::net::SocketAddrV6 {
    fn port(&self) -> u16 {
        std::net::SocketAddrV6::port(self)
    }
}
