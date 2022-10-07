
use std::net::SocketAddr;

pub struct ProxiedAddr<A: ToString = String> {
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
