use ed25519::x25519::{KeyPair, PublicKey, SecretKey};

use super::NoiseXkState;
use crate::noise::framing::NoiseTranscoder;

impl NoiseTranscoder<NoiseXkState> {
    #[cfg(feature = "keygen")]
    pub fn with_xk_initiator(local_key: SecretKey, remote_key: PublicKey) -> Self {
        let ephemeral_key = KeyPair::generate().sk;
        let state = NoiseXkState::new_initiator(local_key, remote_key, ephemeral_key);
        NoiseTranscoder { state }

        /*
        let mut data = vec![];
        loop {
            let (act, h) = handshake.next(&data)?;
            handshake = h;
            if let Some(ref act) = act {
                connection.write_all(&*act)?;
                if let NoiseXkState::Complete(transcoder) = handshake {
                    break Ok(transcoder);
                }
                data = vec![0u8; handshake.data_len()];
                connection.read_exact(&mut data)?;
            }
        }
         */
    }

    #[cfg(feature = "keygen")]
    pub fn with_xk_responder(local_key: SecretKey) -> Self {
        let ephemeral_key = KeyPair::generate().sk;
        let state = NoiseXkState::new_responder(local_key, ephemeral_key);
        NoiseTranscoder { state }

        /*
        let mut data = vec![0u8; handshake.data_len()];
        connection.read_exact(&mut data)?;
        loop {
            let (act, h) = handshake.next(&data)?;
            handshake = h;
            if let NoiseXkState::Complete(transcoder) = handshake {
                break Ok(transcoder);
            }
            if let Some(act) = act {
                connection.write_all(&*act)?;
                data = vec![0u8; handshake.data_len()];
                connection.read_exact(&mut data)?;
            }
        }
         */
    }
}
