// LNP/BP Noise_XK transport layer security protocol implementation. Part of
// Internet2 suite of libraries for decentralized, private & censorship-secure
// Internet.
//
// Written in 2022 by
//     Maxim Orlovsky
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

#[macro_use]
extern crate amplify;

mod ceremony;
mod chacha;
mod hkdf;
mod handshake;

pub type SymmetricKey = [u8; 32];

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
    From
)]
#[display(doc_comments)]
pub enum EncryptionError {
    /// message length {0} exceeds maximum size allowed for the encryption
    /// protocol frame.
    ExceedingMaxLength(usize),

    /// chacha20poly1305 AEAD encrypter error.
    #[from(chacha20poly1305::aead::Error)]
    ChaCha,

    /// message provided for a Noise protocol has incorrect length
    ExpectedMessageLenMismatch,
}
