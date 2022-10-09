use ed25519::{PublicKey, SecretKey};

use super::*;

pub struct Curve25519;

impl Ec for Curve25519 {
    type PubKey = PublicKey;
    type PrivKey = SecretKey;
    type EcdhSecret = [u8; 32];
}

impl EcPubKey<Curve25519> for PublicKey {
    type Raw = [u8; 32];

    fn from_raw(raw: Self::Raw) -> Self {
        todo!()
    }

    fn into_raw(self) -> Self::Raw {
        todo!()
    }

    fn ecdh(self, sk: crate::crypto::PrivKey) -> crate::crypto::EcdhSecret {
        todo!()
    }

    fn verify<S: EcSig<Curve25519>>(self, sig: S, msg: impl AsRef<[u8]>) -> bool {
        todo!()
    }
}

impl EcPrivKey<Curve25519> for SecretKey {
    type Raw = [u8; 32];

    fn from_raw(raw: Self::Raw) -> Self {
        todo!()
    }

    fn into_raw(self) -> Self::Raw {
        todo!()
    }

    fn ecdh(self, pk: crate::crypto::PubKey) -> crate::crypto::EcdhSecret {
        todo!()
    }

    fn sign<S: EcSig<Curve25519>>(self, msg: impl AsRef<[u8]>) -> S {
        todo!()
    }
}
