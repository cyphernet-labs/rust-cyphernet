use core::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use super::{Addr, AddrParseError};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SocketAddr<const DEFAULT_PORT: u16> {
    pub ip: IpAddr,
    pub port: Option<u16>,
}

impl<const DEFAULT_PORT: u16> Addr for SocketAddr<DEFAULT_PORT> {
    fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }
}

impl<const DEFAULT_PORT: u16> From<SocketAddr<DEFAULT_PORT>> for std::net::SocketAddr {
    fn from(addr: SocketAddr<DEFAULT_PORT>) -> Self {
        std::net::SocketAddr::new(addr.ip, addr.port())
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
