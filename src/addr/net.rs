use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display(inner)]
#[non_exhaustive]
pub enum HostAddr {
    #[from]
    Socket(IpAddr),

    #[cfg(feature = "tor")]
    #[from]
    Tor(torut::onion::OnionAddressV3),

    #[cfg(feature = "i2p")]
    #[from]
    I2P(super::i2p::I2pAddr),

    #[cfg(feature = "nym")]
    #[from]
    Nym(super::nym::NymAddr),

    #[cfg(feature = "dns")]
    Dns(String),
}

impl FromStr for HostAddr {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct NetAddr<const DEFAULT_PORT: u16> {
    pub host: HostAddr,
    pub port: Option<u16>,
}

impl<const DEFAULT_PORT: u16> NetAddr<DEFAULT_PORT> {
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }
}

impl<const DEFAULT_PORT: u16> FromStr for NetAddr<DEFAULT_PORT> {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}
