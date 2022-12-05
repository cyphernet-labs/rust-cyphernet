use std::fmt::{self, Display, Formatter};
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::{io, net, option};

use super::{PeerAddr, SocketAddr};

use super::{Addr, AddrParseError, ProxiedAddr};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum UniversalAddr<A: Addr = net::SocketAddr> {
    #[from]
    Proxied(ProxiedAddr<A>),

    #[from]
    Direct(A),
}

#[derive(Copy, Clone, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ProxyError {
    /// proxy information is already present in the address
    ProxyPresent,
}

impl<A: Addr> UniversalAddr<A> {
    pub fn has_proxy(&self) -> bool {
        matches!(self, UniversalAddr::Proxied(_))
    }

    pub fn replace_proxy(self, proxy_addr: net::SocketAddr) -> Self {
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

    pub fn try_proxy(self, proxy_addr: net::SocketAddr) -> Result<Self, ProxyError> {
        match self {
            UniversalAddr::Proxied(_) => Err(ProxyError::ProxyPresent),
            UniversalAddr::Direct(remote_addr) => Ok(UniversalAddr::Proxied(ProxiedAddr {
                proxy_addr,
                remote_addr,
            })),
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

    fn to_socket_addr(&self) -> net::SocketAddr {
        match self {
            UniversalAddr::Proxied(proxied) => proxied.to_socket_addr(),
            UniversalAddr::Direct(addr) => addr.to_socket_addr(),
        }
    }
}

impl<A> UniversalAddr<A>
where
    A: Addr + Copy + Into<net::SocketAddr>,
{
    pub fn to_socket_addr(&self) -> net::SocketAddr {
        match self {
            UniversalAddr::Proxied(proxied) => proxied.to_socket_addr(),
            UniversalAddr::Direct(socket_addr) => (*socket_addr).into(),
        }
    }
}

impl<A> ToSocketAddrs for UniversalAddr<A>
where
    A: Addr + Copy + Into<net::SocketAddr>,
{
    type Iter = option::IntoIter<net::SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<option::IntoIter<net::SocketAddr>> {
        Ok(Some(self.to_socket_addr()).into_iter())
    }
}

impl<const DEFAULT_PORT: u16> From<UniversalAddr<SocketAddr<DEFAULT_PORT>>>
    for UniversalAddr<net::SocketAddr>
{
    fn from(ua: UniversalAddr<SocketAddr<DEFAULT_PORT>>) -> Self {
        match ua {
            UniversalAddr::Proxied(addr) => UniversalAddr::Proxied(addr.into()),
            UniversalAddr::Direct(addr) => UniversalAddr::Direct(addr.into()),
        }
    }
}

impl<Id, const DEFAULT_PORT: u16> From<UniversalAddr<PeerAddr<Id, SocketAddr<DEFAULT_PORT>>>>
    for UniversalAddr<PeerAddr<Id, net::SocketAddr>>
where
    Id: FromStr,
    <Id as FromStr>::Err: std::error::Error,
{
    fn from(ua: UniversalAddr<PeerAddr<Id, SocketAddr<DEFAULT_PORT>>>) -> Self {
        match ua {
            UniversalAddr::Proxied(addr) => UniversalAddr::Proxied(addr.into()),
            UniversalAddr::Direct(addr) => UniversalAddr::Direct(addr.into()),
        }
    }
}

impl<A: Addr + Display> Display for UniversalAddr<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            UniversalAddr::Proxied(addr) => Display::fmt(addr, f),
            UniversalAddr::Direct(addr) => Display::fmt(addr, f),
        }
    }
}

impl<A: Addr + FromStr> FromStr for UniversalAddr<A> {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        A::from_str(s)
            .map(UniversalAddr::from)
            .map_err(|_| AddrParseError::UnknownAddressFormat)
            .or_else(|_| ProxiedAddr::from_str(s).map(UniversalAddr::from))
    }
}
