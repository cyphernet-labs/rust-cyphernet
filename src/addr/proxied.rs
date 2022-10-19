use std::net;
use std::str::FromStr;

use super::{PeerAddr, SocketAddr};
use crate::crypto::Ec;

use super::{Addr, AddrParseError};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("socks5h://{proxy_addr}/{remote_addr}")]
pub struct ProxiedAddr<A: Addr = net::SocketAddr> {
    pub proxy_addr: net::SocketAddr,
    pub remote_addr: A,
}

impl<A: Addr> Addr for ProxiedAddr<A> {
    fn port(&self) -> u16 {
        self.remote_addr.port()
    }
}

impl<A: Addr> From<&ProxiedAddr<A>> for net::SocketAddr {
    fn from(addr: &ProxiedAddr<A>) -> Self {
        addr.proxy_addr
    }
}

impl<A: Addr> From<ProxiedAddr<A>> for net::SocketAddr {
    fn from(addr: ProxiedAddr<A>) -> Self {
        addr.proxy_addr
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

impl<E: Ec + ?Sized, const DEFAULT_PORT: u16>
    From<ProxiedAddr<PeerAddr<E, SocketAddr<DEFAULT_PORT>>>>
    for ProxiedAddr<PeerAddr<E, net::SocketAddr>>
where
    <E as Ec>::PubKey: FromStr,
    <<E as Ec>::PubKey as FromStr>::Err: std::error::Error,
{
    fn from(addr: ProxiedAddr<PeerAddr<E, SocketAddr<DEFAULT_PORT>>>) -> Self {
        ProxiedAddr {
            proxy_addr: addr.proxy_addr,
            remote_addr: addr.remote_addr.into(),
        }
    }
}

impl<A: Addr> FromStr for ProxiedAddr<A> {
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
