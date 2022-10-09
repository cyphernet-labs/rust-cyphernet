use std::fmt::Display;
use std::net::SocketAddr;

use super::{HostAddr, ProxiedAddr};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[display(inner)]
pub enum UniversalAddr<A: Display = HostAddr> {
    #[from]
    Proxied(ProxiedAddr<A>),

    #[from]
    Direct(SocketAddr),
}

impl From<&UniversalAddr> for SocketAddr {
    fn from(addr: &UniversalAddr) -> Self {
        match addr {
            UniversalAddr::Proxied(proxied) => proxied.into(),
            UniversalAddr::Direct(socket_addr) => *socket_addr,
        }
    }
}

impl From<UniversalAddr> for SocketAddr {
    fn from(addr: UniversalAddr) -> Self {
        match addr {
            UniversalAddr::Proxied(proxied) => proxied.into(),
            UniversalAddr::Direct(socket_addr) => socket_addr,
        }
    }
}
