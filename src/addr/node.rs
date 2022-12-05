use std::borrow::Borrow;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::net::{self, ToSocketAddrs};
use std::ops::Deref;
use std::str::FromStr;

use super::{Addr, AddrParseError, UniversalAddr};
use crate::addr::SocketAddr;
use crate::crypto::{Ec, EcPrivKey, EcPubKey};

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

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NodeId<E: Ec + ?Sized>(E::PubKey);

impl<E: Ec + ?Sized> Deref for NodeId<E> {
    type Target = E::PubKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<E: Ec + ?Sized> AsRef<E::PubKey> for NodeId<E> {
    fn as_ref(&self) -> &E::PubKey {
        &self.0
    }
}

impl<E: Ec + ?Sized> NodeId<E> {
    pub fn from_public_key(pk: E::PubKey) -> Self {
        Self(pk)
    }

    pub fn from_raw(raw: <E::PubKey as EcPubKey<E>>::Raw) -> Self {
        Self(E::PubKey::from_raw(raw))
    }

    pub fn into_raw(self) -> <E::PubKey as EcPubKey<E>>::Raw {
        self.0.into_raw()
    }
}

impl<E: Ec + ?Sized> Display for NodeId<E>
where
    E::PubKey: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<E: Ec + ?Sized> FromStr for NodeId<E>
where
    E::PubKey: FromStr,
{
    type Err = <E::PubKey as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        E::PubKey::from_str(s).map(Self)
    }
}

#[derive(Getters, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[getter(as_copy)]
pub struct PeerAddr<Id, A: Addr = UniversalAddr> {
    id: Id,
    addr: A,
}

impl<Id, A: Addr> PeerAddr<Id, A> {
    pub fn new(id: Id, addr: A) -> Self {
        Self { id, addr }
    }
}

impl<Id, A: Addr> Borrow<Id> for PeerAddr<Id, A> {
    fn borrow(&self) -> &Id {
        &self.id
    }
}

impl<E: Ec + ?Sized, A: Addr> AsRef<E::PubKey> for PeerAddr<NodeId<E>, A> {
    fn as_ref(&self) -> &E::PubKey {
        self.id.as_ref()
    }
}

impl<Id, A: Addr> Addr for PeerAddr<Id, A> {
    fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl<Id, A: Addr> Display for PeerAddr<Id, A>
where
    Id: Display,
    A: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.id, self.addr)
    }
}

impl<Id, A: Addr> FromStr for PeerAddr<Id, A>
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

impl<Id, const DEFAULT_PORT: u16> From<PeerAddr<Id, SocketAddr<DEFAULT_PORT>>>
    for PeerAddr<Id, net::SocketAddr>
{
    fn from(peer: PeerAddr<Id, SocketAddr<DEFAULT_PORT>>) -> Self {
        PeerAddr {
            addr: peer.addr.into(),
            id: peer.id,
        }
    }
}

impl<Id, A: Addr + Into<net::SocketAddr>> From<PeerAddr<Id, A>> for net::SocketAddr {
    fn from(peer: PeerAddr<Id, A>) -> Self {
        peer.addr.into()
    }
}

impl<Id, A: Addr> PeerAddr<Id, A> {
    pub fn with(id: impl Into<Id>, addr: impl Into<A>) -> Self {
        PeerAddr {
            id: id.into(),
            addr: addr.into(),
        }
    }
}

impl<E: Ec + ?Sized, A: Addr> PeerAddr<NodeId<E>, A> {
    pub fn to_pubkey(&self) -> E::PubKey {
        self.id.0
    }
}

impl<'a, Id, A> PeerAddr<Id, A>
where
    A: Addr + 'a,
    &'a A: Into<net::SocketAddr>,
{
    pub fn to_socket_addr(&'a self) -> net::SocketAddr {
        (&self.addr).into()
    }
}

impl<Id, A> ToSocketAddrs for PeerAddr<Id, A>
where
    A: Addr + ToSocketAddrs,
{
    type Iter = A::Iter;

    fn to_socket_addrs(&self) -> io::Result<A::Iter> {
        self.addr.to_socket_addrs()
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct LocalNode<E: Ec + ?Sized> {
    privkey: E::PrivKey,
    pubkey: E::PubKey,
}

impl<E: Ec + ?Sized> LocalNode<E> {
    pub fn from(sk: E::PrivKey) -> Self {
        let pk = sk.to_public_key();
        LocalNode {
            privkey: sk,
            pubkey: pk,
        }
    }

    pub fn id(&self) -> NodeId<E> {
        NodeId::from_public_key(self.pubkey)
    }

    pub fn private_key(&self) -> &E::PrivKey {
        &self.privkey
    }
}
