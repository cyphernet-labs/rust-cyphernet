use ::ed25519::{KeyPair, Seed};
use quickcheck::Arbitrary;

use crate::crypto::ed25519::PublicKey;

#[derive(Clone, Debug)]
pub struct ByteArray<const N: usize>([u8; N]);

impl<const N: usize> ByteArray<N> {
    pub fn into_inner(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> Arbitrary for ByteArray<N> {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut bytes: [u8; N] = [0; N];
        for byte in &mut bytes {
            *byte = u8::arbitrary(g);
        }
        Self(bytes)
    }
}

impl Arbitrary for PublicKey {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let bytes: ByteArray<32> = Arbitrary::arbitrary(g);
        let seed = Seed::new(bytes.into_inner());
        let keypair = KeyPair::from_seed(seed);

        PublicKey::from(keypair.pk)
    }
}
