pub mod ed25519;

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::{Add, AddAssign};

pub trait Ec: Copy + Clone + Eq + Ord + Hash + Debug {
    type PubKey: EcPubKey<Self>;
    type PrivKey: EcPrivKey<Self>;
    type EcdhSecret: Copy;
    type EcdhErr;
}

pub trait EcPubKey<C: Ec + ?Sized>: Copy + Eq + Ord + Hash + Debug + Display {
    type Raw: Copy;

    fn from_raw(raw: Self::Raw) -> Self;
    fn into_raw(self) -> Self::Raw;

    fn ecdh(self, sk: &C::PrivKey) -> Result<C::EcdhSecret, C::EcdhErr>;
}

pub trait EcPrivKey<C: Ec + ?Sized>: Eq + Ord + Hash + Debug {
    type Raw: Copy;

    fn from_raw(raw: Self::Raw) -> Self;
    fn into_raw(self) -> Self::Raw;
    fn to_raw(&self) -> Self::Raw;
    fn as_raw(&self) -> &Self::Raw;

    fn to_public_key(&self) -> C::PubKey;

    fn ecdh(&self, pk: C::PubKey) -> Result<C::EcdhSecret, C::EcdhErr>;
}

pub trait EcSig<C: Ec + ?Sized>: Copy + Eq + Hash + Debug + Display {
    type Raw: Copy;

    fn from_raw(raw: Self::Raw) -> Self;
    fn into_raw(self) -> Self::Raw;

    fn sign(self, sk: C::PrivKey, msg: impl AsRef<[u8]>) -> Self;
    fn verify(self, pk: C::PubKey, msg: impl AsRef<[u8]>) -> bool;
}

pub trait EcHomSig<C: Ec + ?Sized>: EcSig<C> + Add + AddAssign {}
