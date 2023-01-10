use crate::noise::xk::NoiseXkState;
use ed25519::x25519::PublicKey;

use super::{chacha, hkdf::sha2_256 as hkdf, EncryptionError, SymmetricKey};

pub const KEY_ROTATION_PERIOD: u32 = 1000;

#[derive(Debug)]
pub struct NoiseEncryptor {
    pub(in crate::noise) sending_key: SymmetricKey,
    pub(in crate::noise) sending_chaining_key: SymmetricKey,
    pub(in crate::noise) sending_nonce: u32,
    pub(in crate::noise) remote_pubkey: PublicKey,
}

impl NoiseEncryptor {
    pub const TAGGED_MESSAGE_LENGTH_HEADER_SIZE: usize = Self::MESSAGE_LEN_SIZE + chacha::TAG_SIZE;
    const MESSAGE_LEN_SIZE: usize = 2;

    pub fn encrypt_buf(&mut self, buffer: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let length = buffer.len();
        let length_bytes = if length > u16::MAX as usize {
            return Err(EncryptionError::ExceedingMaxLength(length));
        } else {
            (length as u16).to_be_bytes()
        };

        let mut ciphertext =
            vec![0u8; Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE + length as usize + chacha::TAG_SIZE];

        chacha::encrypt(
            &self.sending_key,
            self.sending_nonce as u64,
            &[0; 0],
            &length_bytes,
            Some(&mut ciphertext[..Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE]),
        )?;
        self.increment_nonce();

        let _ = &chacha::encrypt(
            &self.sending_key,
            self.sending_nonce as u64,
            &[0; 0],
            buffer,
            Some(&mut ciphertext[Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE..]),
        )?;
        self.increment_nonce();

        Ok(ciphertext)
    }

    fn increment_nonce(&mut self) {
        increment_nonce(
            &mut self.sending_nonce,
            &mut self.sending_chaining_key,
            &mut self.sending_key,
        );
    }
}

#[derive(Debug)]
pub struct NoiseDecryptor {
    pub(in crate::noise) receiving_key: SymmetricKey,
    pub(in crate::noise) receiving_chaining_key: SymmetricKey,
    pub(in crate::noise) receiving_nonce: u32,

    pub(in crate::noise) pending_message_length: Option<usize>,
    pub(in crate::noise) read_buffer: Option<Vec<u8>>,
    pub(in crate::noise) poisoned: bool, /* signal an error has occurred so None is returned on
                                          * iteration after failure */
    pub(in crate::noise) remote_pubkey: PublicKey,
}

impl NoiseDecryptor {
    pub const TAGGED_MESSAGE_LENGTH_HEADER_SIZE: usize = Self::MESSAGE_LEN_SIZE + chacha::TAG_SIZE;
    const MESSAGE_LEN_SIZE: usize = 2;

    pub fn read_buf(&mut self, data: &[u8]) {
        let read_buffer = self.read_buffer.get_or_insert(Vec::new());
        read_buffer.extend_from_slice(data);
    }

    /// Decrypt a single message. If data containing more than one message has
    /// been received, only the first message will be returned, and the rest
    /// stored in the internal buffer. If a message pending in the buffer
    /// still hasn't been decrypted, that message will be returned in lieu
    /// of anything new, even if new data is provided.
    pub fn decrypt_single_message(
        &mut self,
        new_data: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, EncryptionError> {
        let mut read_buffer = if let Some(buffer) = self.read_buffer.take() {
            buffer
        } else {
            Vec::new()
        };

        if let Some(data) = new_data {
            read_buffer.extend_from_slice(data);
        }

        let (current_message, offset) = self.decrypt_buf(&read_buffer[..])?;
        read_buffer.drain(..offset); // drain the read buffer
        self.read_buffer = Some(read_buffer); // assign the new value to the built-in buffer
        Ok(current_message)
    }

    fn decrypt_buf(&mut self, buffer: &[u8]) -> Result<(Option<Vec<u8>>, usize), EncryptionError> {
        let message_length = if let Some(length) = self.pending_message_length {
            // we have already decrypted the header
            length
        } else {
            if buffer.len() < Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE {
                // A message must be at least 18 or 18 bytes (2 or 3 for
                // encrypted length, 16 for the tag)
                return Ok((None, 0));
            }

            let encrypted_length = &buffer[0..Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE];

            let mut decrypt = |length_bytes: &mut [u8]| -> Result<(), EncryptionError> {
                chacha::decrypt(
                    &self.receiving_key,
                    self.receiving_nonce as u64,
                    &[0; 0],
                    encrypted_length,
                    Some(length_bytes),
                )?;
                self.increment_nonce();
                Ok(())
            };

            // the message length
            let mut length_bytes = [0u8; 2];
            decrypt(&mut length_bytes)?;
            u16::from_be_bytes(length_bytes) as usize
        };

        let message_end_index =
            Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE + message_length + chacha::TAG_SIZE;

        if buffer.len() < message_end_index {
            self.pending_message_length = Some(message_length);
            return Ok((None, 0));
        }

        self.pending_message_length = None;

        let encrypted_message = &buffer[Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE..message_end_index];
        let mut message = vec![0u8; message_length];

        chacha::decrypt(
            &self.receiving_key,
            self.receiving_nonce as u64,
            &[0; 0],
            encrypted_message,
            Some(&mut message),
        )?;

        self.increment_nonce();

        Ok((Some(message), message_end_index))
    }

    fn increment_nonce(&mut self) {
        increment_nonce(
            &mut self.receiving_nonce,
            &mut self.receiving_chaining_key,
            &mut self.receiving_key,
        );
    }

    // Used in tests to determine whether or not excess bytes entered the
    // conduit without needing to bring up infrastructure to properly encode
    // it
    #[cfg(test)]
    pub fn read_buffer_length(&self) -> usize {
        match &self.read_buffer {
            &Some(ref vec) => vec.len(),
            &None => 0,
        }
    }

    #[inline]
    pub(crate) fn pending_message_len(&self) -> Option<usize> {
        self.pending_message_length
    }

    #[inline]
    pub(crate) fn read_buffer(&self) -> Option<&[u8]> {
        self.read_buffer
            .as_ref()
            .and_then(|buf| self.pending_message_length.map(|len| &buf[..len]))
    }
}

impl Iterator for NoiseDecryptor {
    type Item = Result<Option<Vec<u8>>, EncryptionError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned {
            return None;
        }

        match self.decrypt_single_message(None) {
            Ok(Some(result)) => Some(Ok(Some(result))),
            Ok(None) => None,
            Err(e) => {
                self.poisoned = true;
                Some(Err(e))
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("incomplete Noise handshake")]
pub struct IncompleteHandshake;
pub trait NoiseState {
    fn with_split(encryptor: NoiseEncryptor, decryptor: NoiseDecryptor) -> Self;
    fn try_as_split(&self) -> Result<(&NoiseEncryptor, &NoiseDecryptor), IncompleteHandshake>;
    fn try_as_split_mut(
        &mut self,
    ) -> Result<(&mut NoiseEncryptor, &mut NoiseDecryptor), IncompleteHandshake>;
    fn try_into_split(self) -> Result<(NoiseEncryptor, NoiseDecryptor), IncompleteHandshake>;
    fn expect_remote_pubkey(&self) -> PublicKey {
        self.try_as_split().unwrap().1.remote_pubkey
    }
    fn expect_encryptor(&mut self) -> &mut NoiseEncryptor {
        self.try_as_split_mut().unwrap().0
    }
    fn expect_decryptor(&mut self) -> &mut NoiseDecryptor {
        self.try_as_split_mut().unwrap().1
    }
}

/// Returned after a successful handshake to encrypt and decrypt communication
/// with peer nodes. It should not normally be manually instantiated.
/// Automatically handles key rotation.
/// For decryption, it is recommended to call `decrypt_message_stream` for
/// automatic buffering.
#[derive(Debug)]
pub struct NoiseTranscoder {
    pub state: NoiseXkState,
}

impl NoiseState for NoiseTranscoder {
    fn with_split(encryptor: NoiseEncryptor, decryptor: NoiseDecryptor) -> Self {
        NoiseTranscoder {
            state: NoiseXkState::with_split(encryptor, decryptor),
        }
    }

    fn try_as_split(&self) -> Result<(&NoiseEncryptor, &NoiseDecryptor), IncompleteHandshake> {
        self.state.try_as_split()
    }

    fn try_as_split_mut(
        &mut self,
    ) -> Result<(&mut NoiseEncryptor, &mut NoiseDecryptor), IncompleteHandshake> {
        self.state.try_as_split_mut()
    }

    fn try_into_split(self) -> Result<(NoiseEncryptor, NoiseDecryptor), IncompleteHandshake> {
        self.state.try_into_split()
    }
}

impl NoiseTranscoder {
    /// Encrypt data to be sent to peer
    pub fn encrypt_buf(&mut self, buffer: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.expect_encryptor().encrypt_buf(buffer)
    }

    pub fn read_buf(&mut self, data: &[u8]) {
        self.expect_decryptor().read_buf(data)
    }

    /// Decrypt a single message. If data containing more than one message has
    /// been received, only the first message will be returned, and the rest
    /// stored in the internal buffer. If a message pending in the buffer
    /// still hasn't been decrypted, that message will be returned in lieu
    /// of anything new, even if new data is provided.
    pub fn decrypt_single_message(
        &mut self,
        new_data: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, EncryptionError> {
        self.expect_decryptor().decrypt_single_message(new_data)
    }
}

fn increment_nonce(nonce: &mut u32, chaining_key: &mut SymmetricKey, key: &mut SymmetricKey) {
    *nonce += 1;
    if *nonce == KEY_ROTATION_PERIOD {
        rotate_key(chaining_key, key);
        *nonce = 0;
    }
}

fn rotate_key(chaining_key: &mut SymmetricKey, key: &mut SymmetricKey) {
    let (new_chaining_key, new_key) = hkdf::derive(chaining_key, key);
    chaining_key.copy_from_slice(&new_chaining_key);
    key.copy_from_slice(&new_key);
}
