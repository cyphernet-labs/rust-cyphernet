use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display(inner)]
#[non_exhaustive]
pub enum NetAddr {
    #[from]
    Socket(SocketAddr),

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

impl FromStr for NetAddr {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}
