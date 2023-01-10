mod chacha;
pub mod framing;
mod hkdf;
pub mod xk;

pub type SymmetricKey = [u8; 32];

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum EncryptionError {
    /// message length {0} exceeds maximum size allowed for the encryption
    /// protocol frame.
    ExceedingMaxLength(usize),

    /// ChaCha20Poly1305 AEAD encryptor error.
    #[from]
    ChaCha(chacha20poly1305::aead::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Display, Error, From)]
#[display(doc_comments)]
pub enum HandshakeError {
    /// unexpected version of noise protocol {version} in act {act} of handshake.
    UnexpectedVersion { version: u8, act: u8 },

    /// invalid remote ephemeral pubkey provided during noise handshake.
    InvalidEphemeralPubkey,

    /// the initiator has provided an invalid pubkey
    InvalidInitiatorPubkey,

    /// invalid length of handshake act {act}: expected {expected}, provided {found}
    InvalidActLen {
        act: u8,
        expected: usize,
        found: usize,
    },

    #[from]
    #[from(chacha20poly1305::aead::Error)]
    #[display(inner)]
    Encryption(EncryptionError),

    /// noise handshake is complete, nothing to process.
    Complete,
}

pub trait Handshake: AsRef<[u8]> {
    /// Returns the size of output data for the handshake act
    fn output_len(&self) -> usize {
        self.as_ref().len()
    }
}
