use std::fmt::Display;
use std::str::FromStr;

use super::UniversalAddr;
use crate::crypto::{Ec, EcPubKey};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
pub struct NodeId<E: Ec + ?Sized>(<E::PubKey as EcPubKey<E>>::Raw);

impl<E: Ec + ?Sized> NodeId<E> {
    pub fn from_raw(raw: <E::PubKey as EcPubKey<E>>::Raw) -> Self {
        Self(raw)
    }

    pub fn into_raw(self) -> <E::PubKey as EcPubKey<E>>::Raw {
        self.0
    }
}

impl<E: Ec + ?Sized> FromStr for NodeId<E>
where
    E::PubKey: FromStr,
{
    type Err = <E::PubKey as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        E::PubKey::from_str(s).map(E::PubKey::into_raw).map(Self)
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("{pubkey}@{addr}")]
pub struct PeerAddr<E: Ec + ?Sized, A: Display = UniversalAddr> {
    pubkey: NodeId<E>,
    addr: A,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct LocalNode<E: Ec + ?Sized> {
    privkey: E::PrivKey,
    pubkey: E::PubKey,
}
