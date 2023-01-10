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
