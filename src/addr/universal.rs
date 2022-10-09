use std::net::SocketAddr;
use std::str::FromStr;

use crate::addr::Addr;

use super::ProxiedAddr;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[display(inner)]
pub enum UniversalAddr<A: Addr = SocketAddr> {
    #[from]
    Proxied(ProxiedAddr<A>),

    #[from]
    Direct(A),
}

impl<A: Addr> UniversalAddr<A> {
    pub fn replace_proxy(self, proxy_addr: SocketAddr) -> Self {
        match self {
            UniversalAddr::Proxied(mut addr) => {
                addr.proxy_addr = proxy_addr;
                UniversalAddr::Proxied(addr)
            }
            UniversalAddr::Direct(remote_addr) => UniversalAddr::Proxied(ProxiedAddr {
                proxy_addr,
                remote_addr,
            }),
        }
    }

    pub fn as_remote_addr(&self) -> &A {
        match self {
            UniversalAddr::Proxied(proxied) => &proxied.remote_addr,
            UniversalAddr::Direct(socket_addr) => socket_addr,
        }
    }

    pub fn into_remote_addr(self) -> A {
        match self {
            UniversalAddr::Proxied(proxied) => proxied.remote_addr,
            UniversalAddr::Direct(socket_addr) => socket_addr,
        }
    }
}

impl<A: Addr> Addr for UniversalAddr<A> {
    fn port(&self) -> u16 {
        match self {
            UniversalAddr::Proxied(addr) => addr.port(),
            UniversalAddr::Direct(socket) => socket.port(),
        }
    }
}

impl<A: Addr + Into<SocketAddr> + Copy> From<&UniversalAddr<A>> for SocketAddr {
    fn from(addr: &UniversalAddr<A>) -> Self {
        match addr {
            UniversalAddr::Proxied(proxied) => proxied.into(),
            UniversalAddr::Direct(socket_addr) => <A as Into<SocketAddr>>::into(*socket_addr),
        }
    }
}

impl<A: Addr + Into<SocketAddr>> From<UniversalAddr<A>> for SocketAddr {
    fn from(addr: UniversalAddr<A>) -> Self {
        match addr {
            UniversalAddr::Proxied(proxied) => proxied.into(),
            UniversalAddr::Direct(socket_addr) => socket_addr.into(),
        }
    }
}

impl<A: Addr> FromStr for UniversalAddr<A> {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}
