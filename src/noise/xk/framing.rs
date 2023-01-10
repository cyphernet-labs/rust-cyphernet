use ed25519::x25519::{KeyPair, PublicKey, SecretKey};

use super::NoiseXkState;
use crate::noise::framing::NoiseTranscoder;

impl NoiseTranscoder<NoiseXkState> {
    pub fn with_xk_initiator(local_key: SecretKey, remote_key: PublicKey) -> Self {
        let ephemeral_key = KeyPair::generate().sk;
        let state = NoiseXkState::new_initiator(local_key, remote_key, ephemeral_key);
        NoiseTranscoder { state }
    }

    pub fn with_xk_responder(local_key: SecretKey) -> Self {
        let ephemeral_key = KeyPair::generate().sk;
        let state = NoiseXkState::new_responder(local_key, ephemeral_key);
        NoiseTranscoder { state }
    }
}
