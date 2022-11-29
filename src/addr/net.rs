use std::net::IpAddr;
use std::str::FromStr;
use std::{fmt, net};

use super::{Addr, AddrParseError};

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[display(inner)]
#[non_exhaustive]
pub enum HostAddr {
    #[from]
    Ip(IpAddr),

    #[cfg(feature = "tor")]
    #[from]
    Tor(torut::onion::OnionAddressV3),

    #[cfg(feature = "i2p")]
    #[from]
    I2p(super::i2p::I2pAddr),

    #[cfg(feature = "nym")]
    #[from]
    Nym(super::nym::NymAddr),

    #[cfg(feature = "dns")]
    Dns(String),
}

impl FromStr for HostAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = IpAddr::from_str(s) {
            return Ok(HostAddr::Ip(addr));
        }
        #[cfg(feature = "tor")]
        if s.ends_with(".onion") {
            return torut::onion::OnionAddressV3::from_str(s)
                .map(HostAddr::Tor)
                .map_err(AddrParseError::from);
        }
        // TODO: Support Num and I2P
        #[cfg(feature = "dns")]
        {
            Ok(HostAddr::Dns(s.to_owned()))
        }
        #[cfg(not(feature = "dns"))]
        {
            Err(AddrParseError::UnknownAddressFormat)
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetAddr<const DEFAULT_PORT: u16> {
    pub host: HostAddr,
    pub port: Option<u16>,
}

impl<const DEFAULT_PORT: u16> Addr for NetAddr<DEFAULT_PORT> {
    fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }
}

impl<const DEFAULT_PORT: u16> fmt::Display for NetAddr<DEFAULT_PORT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.host, f)?;
        if let Some(port) = self.port {
            write!(f, "{}", port)?;
        }
        Ok(())
    }
}

impl<const DEFAULT_PORT: u16> FromStr for NetAddr<DEFAULT_PORT> {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((host, port)) = s.rsplit_once(':') {
            Ok(NetAddr {
                host: HostAddr::from_str(host)?,
                port: Some(u16::from_str(port).map_err(|_| AddrParseError::InvalidPort)?),
            })
        } else {
            Ok(NetAddr {
                host: HostAddr::from_str(s)?,
                port: None,
            })
        }
    }
}
