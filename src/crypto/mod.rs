#[cfg(feature = "ed25519")]
pub mod ed25519;

pub trait EcPk {}

pub trait EcSk {
    type Pk: EcPk;
    fn to_pk(&self) -> Self::Pk;
}

pub trait Ecdh {
    type Pk: EcPk;
    type Secret: Sized;
    type Err;

    fn ecdh(&self, pk: &Self::Pk) -> Result<Self::Secret, Self::Err>;
}

/*
pub trait EcSig {
    type Sk: EcSk<Pk = Self::Pk>;
    type Pk: EcPk;

    fn sign(self, sk: &Self::Sk, msg: impl AsRef<[u8]>) -> Self;
    fn verify(self, pk: &Self::Pk, msg: impl AsRef<[u8]>) -> bool;
}

pub trait EcHmSig: EcSig + Add + AddAssign + Sized {}
*/
