use std::borrow::Borrow;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::net::{self, ToSocketAddrs};
use std::str::FromStr;

use super::{Addr, AddrParseError, UniversalAddr};
use crate::addr::{SocketAddr, ToSocketAddr};
use crate::crypto::EcPk;

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum PeerAddrParseError<Id: Debug>
where
    Id: FromStr,
    <Id as FromStr>::Err: std::error::Error,
{
    #[from]
    #[from(net::AddrParseError)]
    #[display(inner)]
    Addr(AddrParseError),

    /// invalid peer key. Details: {0}
    Key(<Id as FromStr>::Err),

    /// invalid peer address format. Peer address must contain peer key and peer
    /// network address, separated by '@'
    InvalidFormat,
}

#[derive(Getters, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[getter(as_copy)]
pub struct PeerAddr<Id: EcPk, A: Addr = UniversalAddr> {
    id: Id,
    addr: A,
}

impl<Id: EcPk, A: Addr> PeerAddr<Id, A> {
    pub fn new(id: Id, addr: A) -> Self {
        Self { id, addr }
    }
}

impl<Id: EcPk, A: Addr> Borrow<Id> for PeerAddr<Id, A> {
    fn borrow(&self) -> &Id {
        &self.id
    }
}

impl<Id: EcPk, A: Addr> Addr for PeerAddr<Id, A> {
    fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl<Id: EcPk, A: Addr + ToSocketAddr> ToSocketAddr for PeerAddr<Id, A> {
    fn to_socket_addr(&self) -> net::SocketAddr {
        self.addr.to_socket_addr()
    }
}

impl<Id: EcPk, A: Addr> Display for PeerAddr<Id, A>
where
    Id: Display,
    A: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.id, self.addr)
    }
}

impl<Id: EcPk, A: Addr> FromStr for PeerAddr<Id, A>
where
    Id: FromStr + Debug,
    <Id as FromStr>::Err: std::error::Error,
    A: FromStr,
    <A as FromStr>::Err: Into<PeerAddrParseError<Id>>,
{
    type Err = PeerAddrParseError<Id>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((pk, addr)) = s.split_once('@') {
            Ok(PeerAddr {
                id: Id::from_str(pk).map_err(PeerAddrParseError::Key)?,
                addr: A::from_str(addr).map_err(<A as FromStr>::Err::into)?,
            })
        } else {
            Err(PeerAddrParseError::InvalidFormat)
        }
    }
}

impl<Id: EcPk, const DEFAULT_PORT: u16> From<PeerAddr<Id, SocketAddr<DEFAULT_PORT>>>
    for PeerAddr<Id, net::SocketAddr>
{
    fn from(peer: PeerAddr<Id, SocketAddr<DEFAULT_PORT>>) -> Self {
        PeerAddr {
            addr: peer.addr.into(),
            id: peer.id,
        }
    }
}

impl<Id: EcPk, A: Addr + Into<net::SocketAddr>> From<PeerAddr<Id, A>> for net::SocketAddr {
    fn from(peer: PeerAddr<Id, A>) -> Self {
        peer.addr.into()
    }
}

impl<Id: EcPk, A: Addr> PeerAddr<Id, A> {
    pub fn with(id: impl Into<Id>, addr: impl Into<A>) -> Self {
        PeerAddr {
            id: id.into(),
            addr: addr.into(),
        }
    }
}

impl<Id: EcPk, A> ToSocketAddrs for PeerAddr<Id, A>
where
    A: Addr + ToSocketAddrs,
{
    type Iter = A::Iter;

    fn to_socket_addrs(&self) -> io::Result<A::Iter> {
        self.addr.to_socket_addrs()
    }
}
