use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::{Add, AddAssign};

pub trait Ec {
    type PubKey: EcPubKey<Self>;
    type PrivKey: EcPrivKey<Self>;
    type EcdhSecret: Copy;
}

pub trait EcPubKey<C: Ec + ?Sized>: Copy + Eq + Ord + Hash + Debug + Display {
    type Raw: Copy + Eq + Ord + Hash + Debug + Display;

    fn from_raw(raw: Self::Raw) -> Self;
    fn into_raw(self) -> Self::Raw;

    fn ecdh(self, sk: C::PrivKey) -> C::EcdhSecret;
    fn verify<S: EcSig<C>>(self, sig: S, msg: impl AsRef<[u8]>) -> bool;
}

pub trait EcPrivKey<C: Ec + ?Sized>: Copy + Eq + Ord + Hash + Debug + Display {
    type Raw: Copy + Eq + Ord + Hash + Debug + Display;

    fn from_raw(raw: Self::Raw) -> Self;
    fn into_raw(self) -> Self::Raw;

    fn ecdh(self, pk: C::PubKey) -> C::EcdhSecret;
    fn sign<S: EcSig<C>>(self, msg: impl AsRef<[u8]>) -> S;
}

pub trait EcSig<C: Ec + ?Sized>: Copy + Eq + Hash + Debug + Display {
    type Raw: Copy + Eq + Hash + Debug + Display;

    fn verify(self, pk: C::PubKey, msg: impl AsRef<[u8]>) -> bool;
}

pub trait EcHomSig<C: Ec + ?Sized>: EcSig<C> + Add + AddAssign {}
