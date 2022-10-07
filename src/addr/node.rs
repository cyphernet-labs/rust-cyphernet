use std::fmt::Display;

use super::UniversalAddr;
use crate::crypto::{Ec, EcPubKey};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
pub struct NodeId<E: Ec + ?Sized>(<E::PubKey as EcPubKey<E>>::Inner);

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
