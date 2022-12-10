use crate::addr::ToSocketAddr;
use core::fmt;
use std::net;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use super::{Addr, AddrParseError};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SocketAddr<const DEFAULT_PORT: u16> {
    pub ip: IpAddr,
    pub port: Option<u16>,
}

impl<const DEFAULT_PORT: u16> SocketAddr<DEFAULT_PORT> {
    pub fn localhost() -> Self {
        Self {
            ip: Ipv4Addr::LOCALHOST.into(),
            port: None,
        }
    }

    pub fn unspecified() -> Self {
        Self {
            ip: Ipv4Addr::UNSPECIFIED.into(),
            port: None,
        }
    }
}

impl<const DEFAULT_PORT: u16> Addr for SocketAddr<DEFAULT_PORT> {
    fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }
}

impl<const DEFAULT_PORT: u16> ToSocketAddr for SocketAddr<DEFAULT_PORT> {
    fn to_socket_addr(&self) -> net::SocketAddr {
        net::SocketAddr::new(self.ip, self.port())
    }
}

impl<const DEFAULT_PORT: u16> From<SocketAddr<DEFAULT_PORT>> for net::SocketAddr {
    fn from(addr: SocketAddr<DEFAULT_PORT>) -> Self {
        addr.to_socket_addr()
    }
}

impl<const DEFAULT_PORT: u16> fmt::Display for SocketAddr<DEFAULT_PORT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.ip, f)?;
        if let Some(port) = self.port {
            write!(f, "{}", port)?;
        }
        Ok(())
    }
}

impl<const DEFAULT_PORT: u16> FromStr for SocketAddr<DEFAULT_PORT> {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((host, port)) = s.rsplit_once(':') {
            Ok(SocketAddr {
                ip: IpAddr::from_str(host)?,
                port: Some(u16::from_str(port).map_err(|_| AddrParseError::InvalidPort)?),
            })
        } else {
            Ok(SocketAddr {
                ip: IpAddr::from_str(s)?,
                port: None,
            })
        }
    }
}
