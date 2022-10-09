use std::net::SocketAddr;
use std::str::FromStr;

use super::Addr;

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
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}
