use crate::addr::{Addr, Host, ToSocketAddr};
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::{fmt, io, vec};

use super::AddrParseError;

/// A host name which can be consumed by `std::net` methods via use of
/// [`ToSocketAddrs`] trait (when combined with port address).
#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[display(inner)]
pub enum HostName {
    /// IP name, including both IPv4 and IPv6 variants
    #[from]
    #[from(Ipv4Addr)]
    #[from(Ipv6Addr)]
    Ip(IpAddr),

    /// DNS-based name
    Dns(String),
}

impl Host for HostName {}

impl FromStr for HostName {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match IpAddr::from_str(s) {
            Ok(addr) => Ok(Self::Ip(addr)),
            // TODO: Check charset and format of a DNS name
            Err(_) => Ok(Self::Dns(s.to_owned())),
        }
    }
}

/*
pub trait ToHostNames {
    type Iter<'a>: Iterator<Item = &'a HostName>;
    fn to_host_names(&self) -> Self::Iter;
}

impl ToHostNames for HostName {
    type Iter<'a> = option::IntoIter<&'a HostName>;

    fn to_host_names(&self) -> Self::Iter {
        Some(self).into_iter()
    }
}
 */

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[display(inner)]
#[non_exhaustive]
pub enum MixName {
    #[from]
    Ip(IpAddr),

    #[cfg(feature = "dns")]
    Dns(String),

    #[cfg(feature = "tor")]
    #[from]
    Tor(super::tor::OnionAddrV3),

    #[cfg(feature = "i2p")]
    #[from]
    I2p(super::i2p::I2pAddr),

    #[cfg(feature = "nym")]
    #[from]
    Nym(super::nym::NymAddr),
}

impl Host for MixName {}

impl FromStr for MixName {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = IpAddr::from_str(s) {
            return Ok(Self::Ip(addr));
        }
        #[cfg(feature = "tor")]
        if s.ends_with(".onion") {
            return super::tor::OnionAddrV3::from_str(s)
                .map(Self::Tor)
                .map_err(AddrParseError::from);
        }
        // TODO: Support Num and I2P
        #[cfg(feature = "dns")]
        {
            Ok(Self::Dns(s.to_owned()))
        }
        #[cfg(not(feature = "dns"))]
        {
            Err(AddrParseError::UnknownAddressFormat)
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum HostProxied<P: ToSocketAddrs + Addr = NetAddr<HostName>> {
    #[from]
    Ip(IpAddr),

    #[cfg(feature = "dns")]
    Dns(String),

    #[cfg(feature = "tor")]
    Tor(super::tor::OnionAddrV3, P),

    #[cfg(feature = "i2p")]
    I2p(super::i2p::I2pAddr, P),

    #[cfg(feature = "nym")]
    Nym(super::nym::NymAddr, P),
}

impl<P: ToSocketAddrs + Addr> Host for HostProxied<P> {}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetAddr<H: Host> {
    pub host: H,
    pub port: u16,
}

impl<H: Host> Host for NetAddr<H> {}

impl<H: Host> Addr for NetAddr<H> {
    fn port(&self) -> u16 {
        self.port
    }
}

impl<H: Host> fmt::Display for NetAddr<H>
where
    H: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.host, f)?;
        write!(f, ":{}", self.port)
    }
}

impl<H: Host> FromStr for NetAddr<H>
where
    H: FromStr,
    AddrParseError: From<H::Err>,
{
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.rsplit_once(':') {
            None => Err(AddrParseError::PortAbsent),
            Some((host, port)) => Ok(NetAddr {
                host: H::from_str(host)?,
                port: u16::from_str(port).map_err(|_| AddrParseError::InvalidPort)?,
            }),
        }
    }
}

impl ToSocketAddr for NetAddr<IpAddr> {
    fn to_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}

impl ToSocketAddr for NetAddr<Ipv4Addr> {
    fn to_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host.into(), self.port)
    }
}

impl ToSocketAddr for NetAddr<Ipv6Addr> {
    fn to_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host.into(), self.port)
    }
}

impl ToSocketAddrs for NetAddr<HostName> {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        match &self.host {
            HostName::Dns(dns) => (dns.as_str(), self.port).to_socket_addrs(),
            HostName::Ip(ip) => Ok(SocketAddr::new(*ip, self.port)
                .to_socket_addrs()?
                .collect::<Vec<_>>()
                .into_iter()),
        }
    }
}

pub type MixAddr = NetAddr<HostProxied>;

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PartialAddr<H: Host, const DEFAULT_PORT: u16> {
    pub host: H,
    pub port: Option<u16>,
}

impl<H: Host, const DEFAULT_PORT: u16> Host for PartialAddr<H, DEFAULT_PORT> {}

impl<H: Host, const DEFAULT_PORT: u16> Addr for PartialAddr<H, DEFAULT_PORT> {
    fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }
}

impl<H: Host, const DEFAULT_PORT: u16> Display for PartialAddr<H, DEFAULT_PORT>
where
    H: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.host, f)?;
        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }
        Ok(())
    }
}

impl<H: Host, const DEFAULT_PORT: u16> FromStr for PartialAddr<H, DEFAULT_PORT>
where
    H: FromStr,
    AddrParseError: From<H::Err>,
{
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((host, port)) = s.rsplit_once(':') {
            Ok(PartialAddr {
                host: H::from_str(host)?,
                port: Some(u16::from_str(port).map_err(|_| AddrParseError::InvalidPort)?),
            })
        } else {
            Ok(PartialAddr {
                host: H::from_str(s)?,
                port: None,
            })
        }
    }
}
