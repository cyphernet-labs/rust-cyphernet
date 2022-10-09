use std::net::SocketAddr;
use std::str::FromStr;

use super::{Addr, AddrParseError};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("socks5h://{proxy_addr}/{remote_addr}")]
pub struct ProxiedAddr<A: Addr = SocketAddr> {
    pub proxy_addr: SocketAddr,
    pub remote_addr: A,
}

impl<A: Addr> Addr for ProxiedAddr<A> {
    fn port(&self) -> u16 {
        self.remote_addr.port()
    }
}

impl<A: Addr> From<&ProxiedAddr<A>> for SocketAddr {
    fn from(addr: &ProxiedAddr<A>) -> Self {
        addr.proxy_addr
    }
}

impl<A: Addr> From<ProxiedAddr<A>> for SocketAddr {
    fn from(addr: ProxiedAddr<A>) -> Self {
        addr.proxy_addr
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
                proxy_addr: SocketAddr::from_str(proxy)?,
                remote_addr: A::from_str(remote)
                    .map_err(|_| AddrParseError::UnknownAddressFormat)?,
            })
        } else {
            return Err(AddrParseError::UnknownAddressFormat);
        }
    }
}
