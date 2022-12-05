use std::fmt::{self, Display, Formatter};
use std::net::{self, ToSocketAddrs};
use std::str::FromStr;
use std::{io, option};

use super::{PeerAddr, SocketAddr};

use super::{Addr, AddrParseError};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProxiedAddr<A: Addr = net::SocketAddr> {
    pub proxy_addr: net::SocketAddr,
    pub remote_addr: A,
}

impl<A: Addr> Addr for ProxiedAddr<A> {
    fn port(&self) -> u16 {
        self.remote_addr.port()
    }

    fn to_socket_addr(&self) -> net::SocketAddr {
        self.proxy_addr
    }
}

impl<A> ToSocketAddrs for ProxiedAddr<A>
where
    A: Addr,
{
    type Iter = option::IntoIter<net::SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<option::IntoIter<net::SocketAddr>> {
        Ok(Some(self.to_socket_addr()).into_iter())
    }
}

impl<const DEFAULT_PORT: u16> From<ProxiedAddr<SocketAddr<DEFAULT_PORT>>>
    for ProxiedAddr<net::SocketAddr>
{
    fn from(addr: ProxiedAddr<SocketAddr<DEFAULT_PORT>>) -> Self {
        ProxiedAddr {
            proxy_addr: addr.proxy_addr,
            remote_addr: addr.remote_addr.into(),
        }
    }
}

impl<Id, const DEFAULT_PORT: u16> From<ProxiedAddr<PeerAddr<Id, SocketAddr<DEFAULT_PORT>>>>
    for ProxiedAddr<PeerAddr<Id, net::SocketAddr>>
{
    fn from(addr: ProxiedAddr<PeerAddr<Id, SocketAddr<DEFAULT_PORT>>>) -> Self {
        ProxiedAddr {
            proxy_addr: addr.proxy_addr,
            remote_addr: addr.remote_addr.into(),
        }
    }
}

impl<A: Addr + Display> Display for ProxiedAddr<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "socks5h://{}/{}", self.proxy_addr, self.remote_addr)
    }
}

impl<A: Addr + FromStr> FromStr for ProxiedAddr<A> {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("socks5h://") {
            return Err(AddrParseError::InvalidUrlScheme("socks5h://"));
        }
        if let Some((proxy, remote)) = s[10..].split_once('/') {
            Ok(ProxiedAddr {
                proxy_addr: net::SocketAddr::from_str(proxy)?,
                remote_addr: A::from_str(remote)
                    .map_err(|_| AddrParseError::UnknownAddressFormat)?,
            })
        } else {
            return Err(AddrParseError::UnknownAddressFormat);
        }
    }
}
