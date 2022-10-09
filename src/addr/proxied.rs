use std::fmt::Display;
use std::net::SocketAddr;

use super::HostAddr;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("socks5h://{proxy_addr}/{remote_addr}")]
pub struct ProxiedAddr<A: Display = HostAddr> {
    pub proxy_addr: SocketAddr,
    pub remote_addr: A,
}

impl From<&ProxiedAddr> for SocketAddr {
    fn from(addr: &ProxiedAddr) -> Self {
        addr.proxy_addr
    }
}

impl From<ProxiedAddr> for SocketAddr {
    fn from(addr: ProxiedAddr) -> Self {
        addr.proxy_addr
    }
}
