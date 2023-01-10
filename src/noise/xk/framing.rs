use std::io;

use ed25519::x25519::{KeyPair, PublicKey, SecretKey};

use super::HandshakeState;
use crate::noise::framing::{NoiseDecryptor, NoiseEncryptor, NoiseTranscoder};
use crate::noise::xk::handshake::HandshakeError;
use crate::noise::SymmetricKey;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from]
    Io(io::Error),

    #[from]
    Handshake(HandshakeError),
}

impl NoiseTranscoder {
    #[cfg(feature = "keygen")]
    pub fn new_initiator(
        local_key: SecretKey,
        remote_key: PublicKey,
        mut connection: impl io::Read + io::Write,
    ) -> Result<Self, Error> {
        let ephemeral_key = KeyPair::generate().sk;
        let mut handshake = HandshakeState::new_initiator(local_key, remote_key, ephemeral_key);

        let mut data = vec![];
        loop {
            let (act, h) = handshake.next(&data)?;
            handshake = h;
            if let Some(ref act) = act {
                connection.write_all(&*act)?;
                if let HandshakeState::Complete(transcoder) = handshake {
                    break Ok(transcoder);
                }
                data = vec![0u8; handshake.data_len()];
                connection.read_exact(&mut data)?;
            }
        }
    }

    #[cfg(feature = "keygen")]
    pub fn new_responder(
        local_key: SecretKey,
        mut connection: impl io::Read + io::Write,
    ) -> Result<Self, Error> {
        let ephemeral_key = KeyPair::generate().sk;
        let mut handshake = HandshakeState::new_responder(local_key, ephemeral_key);

        let mut data = vec![0u8; handshake.data_len()];
        connection.read_exact(&mut data)?;
        loop {
            let (act, h) = handshake.next(&data)?;
            handshake = h;
            if let HandshakeState::Complete(transcoder) = handshake {
                break Ok(transcoder);
            }
            if let Some(act) = act {
                connection.write_all(&*act)?;
                data = vec![0u8; handshake.data_len()];
                connection.read_exact(&mut data)?;
            }
        }
    }

    /// Instantiate a new Conduit with specified sending and receiving keys
    pub fn with(
        sending_key: SymmetricKey,
        receiving_key: SymmetricKey,
        chaining_key: SymmetricKey,
        remote_pubkey: PublicKey,
        read_buffer: Option<Vec<u8>>,
    ) -> Self {
        NoiseTranscoder {
            encryptor: NoiseEncryptor {
                sending_key,
                sending_chaining_key: chaining_key,
                sending_nonce: 0,
                remote_pubkey,
            },
            decryptor: NoiseDecryptor {
                receiving_key,
                receiving_chaining_key: chaining_key,
                receiving_nonce: 0,
                read_buffer,
                pending_message_length: None,
                poisoned: false,
                remote_pubkey,
            },
        }
    }
}
