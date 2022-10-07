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

pub enum UniversalAddr<A: ToString = String> {
    Proxied(ProxiedAddr<A>),
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

impl From<SocketAddr> for UniversalAddr {
    fn from(socket_addr: SocketAddr) -> Self {
        UniversalAddr::Direct(socket_addr)
    }
}
