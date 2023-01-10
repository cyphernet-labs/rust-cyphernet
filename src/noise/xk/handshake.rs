// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by Rajarshi Maitra
// Refactored in 2022 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use ed25519::x25519::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use super::ceremony::{
    Act, ActBuilder, ACT_ONE_LENGTH, ACT_THREE_LENGTH, ACT_TWO_LENGTH, EMPTY_ACT_ONE,
    EMPTY_ACT_THREE, EMPTY_ACT_TWO,
};
use crate::noise::framing::{IncompleteHandshake, NoiseDecryptor, NoiseEncryptor, NoiseState};
use crate::noise::xk::ceremony::PUBKEY_LEN;
use crate::noise::{chacha, hkdf::sha2_256 as hkdf, HandshakeError, SymmetricKey};

// Alias type to help differentiate between temporary key and chaining key when
// passing bytes around
type ChainingKey = [u8; 32];

// Generate a SHA-256 hash from one or more elements concatenated together
macro_rules! sha256 {
	( $( $x:expr ),+ ) => {{
        let mut sha = Sha256::new();
		$(
			sha.update($x);
		)+
		*(sha.finalize().as_ref() as &[u8; 32])
	}}
}

#[derive(Clone, Debug)]
pub enum NoiseXkState {
    InitiatorStarting(InitiatorStartingState),
    ResponderAwaitingActOne(ResponderAwaitingActOneState),
    InitiatorAwaitingActTwo(InitiatorAwaitingActTwoState),
    ResponderAwaitingActThree(ResponderAwaitingActThreeState),
    Complete {
        encryptor: NoiseEncryptor,
        decryptor: NoiseDecryptor,
    },
}

impl NoiseState for NoiseXkState {
    type Act = Act;

    fn with_split(encryptor: NoiseEncryptor, decryptor: NoiseDecryptor) -> Self {
        assert_eq!(
            encryptor.remote_pubkey, decryptor.remote_pubkey,
            "unrelated Noise encryptor and decryptor objects"
        );
        NoiseXkState::Complete {
            encryptor,
            decryptor,
        }
    }

    fn try_as_split(&self) -> Result<(&NoiseEncryptor, &NoiseDecryptor), IncompleteHandshake> {
        match self {
            NoiseXkState::InitiatorStarting(_)
            | NoiseXkState::ResponderAwaitingActOne(_)
            | NoiseXkState::InitiatorAwaitingActTwo(_)
            | NoiseXkState::ResponderAwaitingActThree(_) => Err(IncompleteHandshake),
            NoiseXkState::Complete {
                encryptor,
                decryptor,
            } => Ok((encryptor, decryptor)),
        }
    }
    fn try_as_split_mut(
        &mut self,
    ) -> Result<(&mut NoiseEncryptor, &mut NoiseDecryptor), IncompleteHandshake> {
        match self {
            NoiseXkState::InitiatorStarting(_)
            | NoiseXkState::ResponderAwaitingActOne(_)
            | NoiseXkState::InitiatorAwaitingActTwo(_)
            | NoiseXkState::ResponderAwaitingActThree(_) => Err(IncompleteHandshake),
            NoiseXkState::Complete {
                encryptor,
                decryptor,
            } => Ok((encryptor, decryptor)),
        }
    }

    fn try_into_split(
        self,
    ) -> Result<(NoiseEncryptor, NoiseDecryptor), (Self, IncompleteHandshake)> {
        match self {
            NoiseXkState::InitiatorStarting(_)
            | NoiseXkState::ResponderAwaitingActOne(_)
            | NoiseXkState::InitiatorAwaitingActTwo(_)
            | NoiseXkState::ResponderAwaitingActThree(_) => Err((self, IncompleteHandshake)),
            NoiseXkState::Complete {
                encryptor,
                decryptor,
            } => Ok((encryptor, decryptor)),
        }
    }

    fn advance_handshake(&mut self, input: &[u8]) -> Result<Option<Act>, HandshakeError> {
        // TODO: Find a way of doing this w/o clone
        let (act, clone) = match self.clone() {
            NoiseXkState::InitiatorStarting(state) => state.next(),
            NoiseXkState::ResponderAwaitingActOne(state) => state.next(input),
            NoiseXkState::InitiatorAwaitingActTwo(state) => state.next(input),
            NoiseXkState::ResponderAwaitingActThree(state) => state.next(input),
            NoiseXkState::Complete { .. } => Err(HandshakeError::Complete),
        }?;
        *self = clone;
        Ok(act)
    }

    fn next_handshake_len(&self) -> usize {
        match self {
            NoiseXkState::InitiatorStarting(_) => ACT_ONE_LENGTH,
            NoiseXkState::ResponderAwaitingActOne(_) => ACT_ONE_LENGTH,
            NoiseXkState::InitiatorAwaitingActTwo(_) => ACT_TWO_LENGTH,
            NoiseXkState::ResponderAwaitingActThree(_) => ACT_THREE_LENGTH,
            NoiseXkState::Complete { .. } => ACT_THREE_LENGTH,
        }
    }

    fn is_handshake_complete(&self) -> bool {
        matches!(self, NoiseXkState::Complete { .. })
    }
}

// Enum dispatch for state machine. Single public interface can statically
// dispatch to all states
impl NoiseXkState {
    pub fn new_initiator(
        initiator_static_private_key: SecretKey,
        responder_static_public_key: PublicKey,
        initiator_ephemeral_private_key: SecretKey,
    ) -> Self {
        NoiseXkState::InitiatorStarting(InitiatorStartingState::new(
            initiator_static_private_key,
            initiator_ephemeral_private_key,
            responder_static_public_key,
        ))
    }

    pub fn new_responder(
        responder_static_private_key: SecretKey,
        responder_ephemeral_private_key: SecretKey,
    ) -> Self {
        NoiseXkState::ResponderAwaitingActOne(ResponderAwaitingActOneState::new(
            responder_static_private_key,
            responder_ephemeral_private_key,
        ))
    }
}

// Handshake state of the Initiator prior to generating Act 1
#[derive(Clone, Debug)]
pub struct InitiatorStartingState {
    initiator_static_private_key: SecretKey,
    initiator_static_public_key: PublicKey,
    initiator_ephemeral_private_key: SecretKey,
    initiator_ephemeral_public_key: PublicKey,
    responder_static_public_key: PublicKey,
    chaining_key: [u8; 32],
    hash: [u8; 32],
}

// Handshake state of the Responder prior to receiving Act 1
#[derive(Clone, Debug)]
pub struct ResponderAwaitingActOneState {
    responder_static_private_key: SecretKey,
    responder_ephemeral_private_key: SecretKey,
    responder_ephemeral_public_key: PublicKey,
    chaining_key: [u8; 32],
    hash: [u8; 32],
    act_one_builder: ActBuilder,
}

// Handshake state of the Initiator prior to receiving Act 2
#[derive(Clone, Debug)]
pub struct InitiatorAwaitingActTwoState {
    initiator_static_private_key: SecretKey,
    initiator_static_public_key: PublicKey,
    initiator_ephemeral_private_key: SecretKey,
    responder_static_public_key: PublicKey,
    chaining_key: ChainingKey,
    hash: [u8; 32],
    act_two_builder: ActBuilder,
}

// Handshake state of the Responder prior to receiving Act 3
#[derive(Clone, Debug)]
pub struct ResponderAwaitingActThreeState {
    hash: [u8; 32],
    responder_ephemeral_private_key: SecretKey,
    chaining_key: ChainingKey,
    temporary_key: [u8; 32],
    act_three_builder: ActBuilder,
}

impl InitiatorStartingState {
    pub fn new(
        initiator_static_private_key: SecretKey,
        initiator_ephemeral_private_key: SecretKey,
        responder_static_public_key: PublicKey,
    ) -> Self {
        let initiator_static_public_key = initiator_static_private_key
            .recover_public_key()
            .expect("invalid initiator private key");
        let (hash, chaining_key) = initialize_handshake_state(&responder_static_public_key);
        let initiator_ephemeral_public_key = initiator_ephemeral_private_key
            .recover_public_key()
            .expect("invalid initiator public key");
        InitiatorStartingState {
            initiator_static_private_key,
            initiator_static_public_key,
            initiator_ephemeral_private_key,
            initiator_ephemeral_public_key,
            responder_static_public_key,
            chaining_key,
            hash,
        }
    }

    // Implementation to transition into Next state which is
    // `InitiatorAwaitingActTwo`. May transition to the same state in the
    // event there are not yet enough bytes or inconsistent bytes to move
    // forward with the handshake. https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-one (sender)
    //
    // PR Comment: This function took an empty byte to be compatible with
    // IHandshake trait in mother implementation which we are not using
    // anymore. So we can get rid of the the length check.
    pub fn next(self) -> Result<(Option<Act>, NoiseXkState), HandshakeError> {
        let initiator_static_private_key = self.initiator_static_private_key;
        let initiator_static_public_key = self.initiator_static_public_key;
        let initiator_ephemeral_private_key = self.initiator_ephemeral_private_key;
        let initiator_ephemeral_public_key = self.initiator_ephemeral_public_key;
        let responder_static_public_key = self.responder_static_public_key;
        let chaining_key = self.chaining_key;
        let hash = self.hash;

        // serialize act one
        let mut act_one = EMPTY_ACT_ONE;
        let (hash, chaining_key, _) = calculate_act_message(
            &initiator_ephemeral_private_key,
            initiator_ephemeral_public_key,
            responder_static_public_key,
            chaining_key,
            hash,
            &mut act_one,
        )?;

        Ok((
            Some(Act::One(act_one)),
            NoiseXkState::InitiatorAwaitingActTwo(InitiatorAwaitingActTwoState {
                initiator_static_private_key,
                initiator_static_public_key,
                initiator_ephemeral_private_key,
                responder_static_public_key,
                chaining_key,
                hash,
                act_two_builder: ActBuilder::new(Act::Two(EMPTY_ACT_TWO)),
            }),
        ))
    }
}

impl ResponderAwaitingActOneState {
    pub fn new(
        responder_static_private_key: SecretKey,
        responder_ephemeral_private_key: SecretKey,
    ) -> Self {
        let responder_static_public_key = responder_static_private_key
            .recover_public_key()
            .expect("invalid initiator public key");
        let (hash, chaining_key) = initialize_handshake_state(&responder_static_public_key);
        let responder_ephemeral_public_key = responder_ephemeral_private_key
            .recover_public_key()
            .expect("invalid initiator public key");

        ResponderAwaitingActOneState {
            responder_static_private_key,
            responder_ephemeral_private_key,
            responder_ephemeral_public_key,
            chaining_key,
            hash,
            act_one_builder: ActBuilder::new(Act::One(EMPTY_ACT_ONE)),
        }
    }

    pub fn next(self, input: &[u8]) -> Result<(Option<Act>, NoiseXkState), HandshakeError> {
        let mut act_one_builder = self.act_one_builder;
        let bytes_read = act_one_builder.fill(input);

        // Payload should exactly fill 50 bytes in this stage.
        // If a act3 response is received which is 66 bytes, or any other
        // garbage data that would indicate a bad peer connection.
        if bytes_read < input.len() {
            return Err(HandshakeError::InvalidActLen {
                act: 1,
                expected: input.len(),
                found: bytes_read,
            });
        }

        // In the event of a partial fill, stay in the same state and wait for
        // more data
        if !act_one_builder.is_finished() {
            assert_eq!(bytes_read, input.len());
            return Ok((
                None,
                NoiseXkState::ResponderAwaitingActOne(Self {
                    responder_static_private_key: self.responder_static_private_key,
                    responder_ephemeral_private_key: self.responder_ephemeral_private_key,
                    responder_ephemeral_public_key: self.responder_ephemeral_public_key,
                    chaining_key: self.chaining_key,
                    hash: self.hash,
                    act_one_builder,
                }),
            ));
        }

        let hash = self.hash;
        let responder_static_private_key = self.responder_static_private_key;
        let chaining_key = self.chaining_key;
        let responder_ephemeral_private_key = self.responder_ephemeral_private_key;
        let responder_ephemeral_public_key = self.responder_ephemeral_public_key;
        let act_one = Act::from(act_one_builder);

        let (initiator_ephemeral_public_key, hash, chaining_key, _) =
            process_act_message::<1>(&act_one, &responder_static_private_key, chaining_key, hash)?;

        let mut act_two = EMPTY_ACT_TWO;
        let (hash, chaining_key, temporary_key) = calculate_act_message(
            &responder_ephemeral_private_key,
            responder_ephemeral_public_key,
            initiator_ephemeral_public_key,
            chaining_key,
            hash,
            &mut act_two,
        )?;

        Ok((
            Some(Act::Two(act_two)),
            NoiseXkState::ResponderAwaitingActThree(ResponderAwaitingActThreeState {
                hash,
                responder_ephemeral_private_key,
                chaining_key,
                temporary_key,
                act_three_builder: ActBuilder::new(Act::Three(EMPTY_ACT_THREE)),
            }),
        ))
    }
}

impl InitiatorAwaitingActTwoState {
    pub fn next(self, input: &[u8]) -> Result<(Option<Act>, NoiseXkState), HandshakeError> {
        let mut act_two_builder = self.act_two_builder;
        let bytes_read = act_two_builder.fill(input);

        // Any payload that is not fully consumed by the builder indicates a bad
        // peer since responder data is required to generate
        // post-authentication messages (so it can't come before we transition)
        if bytes_read < input.len() {
            return Err(HandshakeError::InvalidActLen {
                act: 2,
                expected: input.len(),
                found: bytes_read,
            });
        }

        // In the event of a partial fill, stay in the same state and wait for
        // more data
        if !act_two_builder.is_finished() {
            assert_eq!(bytes_read, input.len());
            return Ok((
                None,
                NoiseXkState::InitiatorAwaitingActTwo(Self {
                    initiator_static_private_key: self.initiator_static_private_key,
                    initiator_static_public_key: self.initiator_static_public_key,
                    initiator_ephemeral_private_key: self.initiator_ephemeral_private_key,
                    responder_static_public_key: self.responder_static_public_key,
                    chaining_key: self.chaining_key,
                    hash: self.hash,
                    act_two_builder,
                }),
            ));
        }

        let initiator_static_private_key = self.initiator_static_private_key;
        let initiator_static_public_key = self.initiator_static_public_key;
        let initiator_ephemeral_private_key = &self.initiator_ephemeral_private_key;
        let responder_static_public_key = self.responder_static_public_key;
        let hash = self.hash;
        let chaining_key = self.chaining_key;
        let act_two = Act::from(act_two_builder);

        let (responder_ephemeral_public_key, hash, chaining_key, temporary_key) =
            process_act_message::<2>(
                &act_two,
                initiator_ephemeral_private_key,
                chaining_key,
                hash,
            )?;

        let mut act_three = EMPTY_ACT_THREE;

        // start serializing act three
        // 1. c = encryptWithAD(temp_k2, 1, h, s.pub.serializeCompressed())
        chacha::encrypt(
            &temporary_key,
            1,
            &hash,
            initiator_static_public_key.as_slice(),
            Some(&mut act_three[1..(17 + PUBKEY_LEN)]),
        )?;

        // 2. h = SHA-256(h || c)
        let hash = sha256!(hash, &act_three[1..(17 + PUBKEY_LEN)]);

        // 3. se = ECDH(s.priv, re)
        let ecdh = ecdh(
            &initiator_static_private_key,
            responder_ephemeral_public_key,
        );

        // 4. ck, temp_k3 = HKDF(ck, se)
        let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

        // 5. t = encryptWithAD(temp_k3, 0, h, zero)
        chacha::encrypt(
            &temporary_key,
            0,
            &hash,
            &[0; 0],
            Some(&mut act_three[(17 + PUBKEY_LEN)..]),
        )?;

        // 6. sk, rk = HKDF(ck, zero)
        let (sending_key, receiving_key) = hkdf::derive(&chaining_key, &[0; 0]);

        // 7. rn = 0, sn = 0
        // - done by Conduit
        let encryptor = NoiseEncryptor {
            sending_key,
            sending_chaining_key: chaining_key,
            sending_nonce: 0,
            remote_pubkey: responder_static_public_key,
        };
        let decryptor = NoiseDecryptor {
            receiving_key,
            receiving_chaining_key: chaining_key,
            receiving_nonce: 0,
            read_buffer: None,
            pending_message_length: None,
            poisoned: false,
            remote_pubkey: responder_static_public_key,
        };

        // 8. Send m = 0 || c || t
        act_three[0] = 0;
        Ok((
            Some(Act::Three(act_three)),
            NoiseXkState::Complete {
                encryptor,
                decryptor,
            },
        ))
    }
}

impl ResponderAwaitingActThreeState {
    fn next(self, input: &[u8]) -> Result<(Option<Act>, NoiseXkState), HandshakeError> {
        let mut act_three_builder = self.act_three_builder;
        let bytes_read = act_three_builder.fill(input);

        // In the event of a partial fill, stay in the same state and wait for
        // more data
        if !act_three_builder.is_finished() {
            assert_eq!(bytes_read, input.len());
            return Ok((
                None,
                NoiseXkState::ResponderAwaitingActThree(Self {
                    hash: self.hash,
                    responder_ephemeral_private_key: self.responder_ephemeral_private_key,
                    chaining_key: self.chaining_key,
                    temporary_key: self.temporary_key,
                    act_three_builder,
                }),
            ));
        }

        let hash = self.hash;
        let temporary_key = self.temporary_key;
        let responder_ephemeral_private_key = &self.responder_ephemeral_private_key;
        let chaining_key = self.chaining_key;

        // 1. Read exactly 66 bytes from the network buffer
        let act_three_bytes = Act::from(act_three_builder);
        assert_eq!(act_three_bytes.len(), ACT_THREE_LENGTH);

        // 2. Parse the read message (m) into v, c, and t
        let version = act_three_bytes[0];
        let tagged_encrypted_pubkey = &act_three_bytes[1..(17 + PUBKEY_LEN)];
        let chacha_tag = &act_three_bytes[(17 + PUBKEY_LEN)..];

        // 3. If v is an unrecognized handshake version, then the responder MUST
        // abort the connection attempt.
        if version != 0 {
            // this should not crash the process, hence no panic
            return Err(HandshakeError::UnexpectedVersion { version, act: 3 });
        }

        // 4. rs = decryptWithAD(temp_k2, 1, h, c)
        let mut remote_pubkey = [0; 32];
        chacha::decrypt(
            &temporary_key,
            1,
            &hash,
            tagged_encrypted_pubkey,
            Some(&mut remote_pubkey),
        )?;
        let initiator_pubkey = PublicKey::new(remote_pubkey);

        // 5. h = SHA-256(h || c)
        let hash = sha256!(hash, tagged_encrypted_pubkey);

        // 6. se = ECDH(e.priv, rs)
        let ecdh = ecdh(responder_ephemeral_private_key, initiator_pubkey);

        // 7. ck, temp_k3 = HKDF(ck, se)
        let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

        // 8. p = decryptWithAD(temp_k3, 0, h, t)
        chacha::decrypt(&temporary_key, 0, &hash, chacha_tag, Some(&mut [0; 0]))?;

        // 9. rk, sk = HKDF(ck, zero)
        let (receiving_key, sending_key) = hkdf::derive(&chaining_key, &[0; 0]);

        // 10. rn = 0, sn = 0
        // - done by Conduit
        let read_buffer = input[bytes_read..].to_vec();
        let encryptor = NoiseEncryptor {
            sending_key,
            sending_chaining_key: chaining_key,
            sending_nonce: 0,
            remote_pubkey: initiator_pubkey,
        };
        let decryptor = NoiseDecryptor {
            receiving_key,
            receiving_chaining_key: chaining_key,
            receiving_nonce: 0,
            read_buffer: Some(read_buffer),
            pending_message_length: None,
            poisoned: false,
            remote_pubkey: initiator_pubkey,
        };

        Ok((
            None,
            NoiseXkState::Complete {
                encryptor,
                decryptor,
            },
        ))
    }
}

// The handshake state always uses the responder's static public key. When
// running on the initiator, the initiator provides the remote's static public
// key and running on the responder they provide their own.
fn initialize_handshake_state(responder_static_public_key: &PublicKey) -> ([u8; 32], [u8; 32]) {
    let protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
    let prologue = b"lightning";

    // 1. h = SHA-256(protocolName)
    // 2. ck = h
    let chaining_key = sha256!(protocol_name);

    // 3. h = SHA-256(h || prologue)
    let hash = sha256!(chaining_key, prologue);

    // h = SHA-256(h || responderPublicKey)
    let hash = sha256!(hash, responder_static_public_key.as_slice());

    (hash, chaining_key)
}

// Due to the very high similarity of acts 1 and 2, this method is used to
// process both
fn calculate_act_message(
    local_private_ephemeral_key: &SecretKey,
    local_public_ephemeral_key: PublicKey,
    remote_public_key: PublicKey,
    chaining_key: ChainingKey,
    hash: [u8; 32],
    act_out: &mut [u8],
) -> Result<([u8; 32], SymmetricKey, SymmetricKey), HandshakeError> {
    // 1. e = generateKey() (passed in)
    // 2. h = SHA-256(h || e.pub.serializeCompressed())
    let serialized_local_public_key = local_public_ephemeral_key.as_slice();
    let hash = sha256!(hash, &serialized_local_public_key);

    // 3. ACT1: es = ECDH(e.priv, rs)
    // 3. ACT2: es = ECDH(e.priv, re)
    let ecdh = ecdh(local_private_ephemeral_key, remote_public_key);

    // 4. ACT1: ck, temp_k1 = HKDF(ck, es)
    // 4. ACT2: ck, temp_k2 = HKDF(ck, ee)
    let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

    // 5. ACT1: c = encryptWithAD(temp_k1, 0, h, zero)
    // 5. ACT2: c = encryptWithAD(temp_k2, 0, h, zero)
    chacha::encrypt(
        &temporary_key,
        0,
        &hash,
        &[0; 0],
        Some(&mut act_out[(PUBKEY_LEN + 1)..]),
    )?;

    // 6. h = SHA-256(h || c)
    let hash = sha256!(hash, &act_out[(PUBKEY_LEN + 1)..]);

    // Send m = 0 || e.pub.serializeCompressed() || c
    act_out[0] = 0;
    act_out[1..(PUBKEY_LEN + 1)].copy_from_slice(&serialized_local_public_key);

    Ok((hash, chaining_key, temporary_key))
}

// Due to the very high similarity of acts 1 and 2, this method is used to
// process both
fn process_act_message<const ACT: u8>(
    act_bytes: &[u8],
    local_private_key: &SecretKey,
    chaining_key: ChainingKey,
    hash: [u8; 32],
) -> Result<(PublicKey, [u8; 32], SymmetricKey, SymmetricKey), HandshakeError> {
    // 1. Read exactly 50 bytes from the network buffer
    // Partial act messages are handled by the callers. By the time it gets
    // here, it must be the correct size.
    assert_eq!(act_bytes.len(), ACT_ONE_LENGTH);
    assert_eq!(act_bytes.len(), ACT_TWO_LENGTH);

    // 2.Parse the read message (m) into v, re, and c
    let version = act_bytes[0];
    let ephemeral_public_key_bytes = &act_bytes[1..(PUBKEY_LEN + 1)];
    let chacha_tag = &act_bytes[(PUBKEY_LEN + 1)..];

    let ephemeral_public_key =
        if let Ok(public_key) = PublicKey::from_slice(ephemeral_public_key_bytes) {
            public_key
        } else {
            return Err(HandshakeError::InvalidEphemeralPubkey);
        };

    // 3. If v is an unrecognized handshake version, then the responder MUST
    // abort the connection attempt
    if version != 0 {
        // this should not crash the process, hence no panic
        return Err(HandshakeError::UnexpectedVersion { version, act: ACT });
    }

    // 4. h = SHA-256(h || re.serializeCompressed())
    let hash = sha256!(hash, ephemeral_public_key_bytes);

    // 5. Act1: es = ECDH(s.priv, re)
    // 5. Act2: ee = ECDH(e.priv, ee)
    let ecdh = ecdh(local_private_key, ephemeral_public_key);

    // 6. Act1: ck, temp_k1 = HKDF(ck, es)
    // 6. Act2: ck, temp_k2 = HKDF(ck, ee)
    let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

    // 7. Act1: p = decryptWithAD(temp_k1, 0, h, c)
    // 7. Act2: p = decryptWithAD(temp_k2, 0, h, c)
    chacha::decrypt(&temporary_key, 0, &hash, chacha_tag, Some(&mut [0; 0]))?;

    // 8. h = SHA-256(h || c)
    let hash = sha256!(hash, chacha_tag);

    Ok((ephemeral_public_key, hash, chaining_key, temporary_key))
}

// TODO: Replace with ECDH from crypto
fn ecdh(private_key: &SecretKey, public_key: PublicKey) -> SymmetricKey {
    let pk_object = public_key.dh(private_key).expect("invalid multiplication");

    sha256!(pk_object.as_slice())
}

#[cfg(test)]
// Reference RFC test vectors for hard-coded values
// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#appendix-a-transport-test-vectors
mod test {
    use crate::noise::EncryptionError;
    use amplify::hex::{FromHex, ToHex};

    use super::NoiseXkState::*;
    use super::*;

    struct TestCtx {
        initiator: NoiseXkState,
        initiator_public_key: PublicKey,
        responder: NoiseXkState,
        responder_static_public_key: PublicKey,
        valid_act1: Vec<u8>,
        valid_act2: Vec<u8>,
        valid_act3: Vec<u8>,
    }

    impl TestCtx {
        fn new() -> Self {
            let initiator_static_private_key = SecretKey::new([0x_11_u8; 32]);
            let initiator_public_key = initiator_static_private_key
                .recover_public_key()
                .expect("invalid initiator public key");
            let initiator_ephemeral_private_key = SecretKey::new([0x_12_u8; 32]);

            let responder_static_private_key = SecretKey::new([0x_21_u8; 32]);
            let responder_static_public_key = responder_static_private_key
                .recover_public_key()
                .expect("invalid initiator public key");
            let responder_ephemeral_private_key = SecretKey::new([0x_22_u8; 32]);

            let initiator = InitiatorStartingState::new(
                initiator_static_private_key,
                initiator_ephemeral_private_key,
                responder_static_public_key,
            );
            let responder = ResponderAwaitingActOneState::new(
                responder_static_private_key,
                responder_ephemeral_private_key,
            );

            TestCtx {
                initiator: InitiatorStarting(initiator),
                initiator_public_key,
                responder: ResponderAwaitingActOne(responder),
                responder_static_public_key,
                valid_act1: vec![
                    0, 5, 42, 80, 119, 58, 200, 217, 23, 115, 242, 220, 150, 98, 225, 47, 13, 239,
                    233, 21, 228, 21, 184, 161, 200, 226, 10, 90, 61, 106, 178, 184, 67, 90, 57, 8,
                    52, 233, 39, 72, 112, 151, 3, 47, 216, 171, 250, 121, 75,
                ],
                valid_act2: vec![
                    0, 15, 170, 104, 78, 210, 136, 103, 185, 127, 74, 106, 45, 238, 93, 248, 206,
                    151, 78, 118, 183, 1, 142, 63, 34, 161, 196, 207, 38, 120, 87, 15, 32, 255,
                    238, 147, 169, 24, 164, 45, 82, 188, 205, 28, 45, 202, 21, 236, 19,
                ],
                valid_act3: vec![
                    0, 191, 147, 87, 155, 193, 130, 203, 124, 248, 96, 240, 132, 93, 94, 115, 97,
                    100, 215, 244, 51, 217, 48, 3, 52, 254, 227, 168, 81, 130, 156, 111, 236, 117,
                    122, 222, 87, 191, 198, 6, 252, 91, 9, 101, 203, 66, 198, 187, 143, 255, 218,
                    60, 251, 221, 161, 188, 18, 177, 176, 141, 129, 84, 97, 160, 20,
                ],
            }
        }
    }

    macro_rules! assert_matches {
        ($e:expr, $state_match:pat) => {
            match $e {
                $state_match => (),
                _ => panic!(),
            }
        };
    }

    macro_rules! unwrap {
        ($v:expr) => {
            $v.unwrap().unwrap()
        };
    }

    // Initiator::Starting -> AwaitingActTwo
    #[test]
    fn starting_to_awaiting_act_two() {
        let mut test_ctx = TestCtx::new();
        let act1 = unwrap!(test_ctx.initiator.advance_handshake(&[]));

        assert_eq!(act1.as_ref(), test_ctx.valid_act1.as_slice());
        assert_matches!(test_ctx.initiator, InitiatorAwaitingActTwo(_));
    }

    //PR Comment: We have removed the requirement of empty bytes
    // in next() call of InitiatorStartingState. So this test is not needed.

    // Responder::AwaitingActOne -> AwaitingActThree
    // RFC test vector: transport-responder successful handshake
    #[test]
    fn awaiting_act_one_to_awaiting_act_three() {
        let mut test_ctx = TestCtx::new();
        let act2 = unwrap!(test_ctx.responder.advance_handshake(&test_ctx.valid_act1));

        assert_eq!(act2.as_ref(), test_ctx.valid_act2.as_slice());
        assert_matches!(test_ctx.responder, ResponderAwaitingActThree(_));
    }

    // Responder::AwaitingActOne -> AwaitingActThree (bad peer)
    // Act2 requires data from the initiator. If we receive a payload for act1
    // that is larger than expected it indicates a bad peer
    #[test]
    fn awaiting_act_one_to_awaiting_act_three_input_extra_bytes() {
        let mut test_ctx = TestCtx::new();
        let mut act1 = test_ctx.valid_act1;
        act1.extend_from_slice(&[1]);

        assert_eq!(
            test_ctx.responder.advance_handshake(&act1).unwrap_err(),
            HandshakeError::InvalidActLen {
                act: 1,
                expected: 50,
                found: 49,
            }
        );
    }

    // Responder::AwaitingActOne -> AwaitingActThree (segmented calls)
    // RFC test vector: transport-responder act1 short read test
    // Divergence from RFC tests due to not reading directly from the socket
    // (partial message OK)
    #[test]
    fn awaiting_act_one_to_awaiting_act_three_segmented() {
        let mut test_ctx = TestCtx::new();
        let act1_partial1 = &test_ctx.valid_act1[..25];
        let act1_partial2 = &test_ctx.valid_act1[25..];

        let next_state = test_ctx.responder.advance_handshake(act1_partial1).unwrap();
        assert_matches!(next_state, None);
        assert_matches!(test_ctx.responder, ResponderAwaitingActOne(_));
        assert_matches!(
            test_ctx.responder.advance_handshake(act1_partial2).unwrap(),
            Some(_)
        );
        assert_matches!(test_ctx.responder, ResponderAwaitingActThree(_))
    }

    // Responder::AwaitingActOne -> Error (bad version byte)
    // RFC test vector: transport-responder act1 bad version test
    #[test]
    fn awaiting_act_one_to_awaiting_act_three_input_bad_version() {
        let mut test_ctx = TestCtx::new();
        let act1 = Vec::<u8>::from_hex("01036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c").unwrap();

        assert_matches!(
            test_ctx.responder.advance_handshake(&act1),
            Err(HandshakeError::UnexpectedVersion { version: 1, act: 1 })
        );
    }

    // Responder::AwaitingActOne -> Error (invalid remote ephemeral key)
    // RFC test vector: transport-responder act1 bad key serialization test
    #[test]
    #[ignore] // TODO: We do not have correct testvec data for curve25519
    fn awaiting_act_one_to_awaiting_act_three_invalid_remote_ephemeral_key() {
        let mut test_ctx = TestCtx::new();
        let act1 = Vec::<u8>::from_hex("00046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c").unwrap();

        assert_matches!(
            test_ctx.responder.advance_handshake(&act1),
            Err(HandshakeError::InvalidEphemeralPubkey)
        );
    }

    // Responder::AwaitingActOne -> Error (invalid hmac)
    // RFC test vector: transport-responder act1 bad MAC test
    #[test]
    fn awaiting_act_one_to_awaiting_act_three_invalid_hmac() {
        let mut test_ctx = TestCtx::new();
        let act1 = Vec::<u8>::from_hex("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c").unwrap();

        assert_eq!(
            test_ctx.responder.advance_handshake(&act1).unwrap_err(),
            HandshakeError::Encryption(chacha20poly1305::aead::Error.into())
        );
    }

    // Initiator::AwaitingActTwo -> Complete (bad peer)
    // Initiator data is required to generate post-authentication messages. This
    // means any extra data indicates a bad peer.
    #[test]
    fn awaiting_act_two_to_complete_extra_bytes() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.initiator.advance_handshake(&[]));
        let mut act2 = test_ctx.valid_act2;
        act2.extend_from_slice(&[1]);

        assert_eq!(
            test_ctx.initiator.advance_handshake(&act2).err().unwrap(),
            HandshakeError::InvalidActLen {
                act: 2,
                expected: 50,
                found: 49,
            }
        );
    }

    // Initiator::AwaitingActTwo -> Complete
    // RFC test vector: transport-initiator successful handshake
    #[test]
    fn awaiting_act_two_to_complete() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.initiator.advance_handshake(&[]));
        let act3 = unwrap!(test_ctx.initiator.advance_handshake(&test_ctx.valid_act2));

        let Complete {
            encryptor,
            decryptor,
        } = test_ctx.initiator else {
            panic!();
        };

        assert_eq!(act3.as_ref(), test_ctx.valid_act3.as_slice());
        assert_eq!(
            encryptor.remote_pubkey,
            test_ctx.responder_static_public_key
        );
        assert_eq!(
            decryptor.remote_pubkey,
            test_ctx.responder_static_public_key
        );
    }

    // Initiator::AwaitingActTwo -> Complete (segmented calls)
    // RFC test vector: transport-initiator act2 short read test
    // Divergence from RFC tests due to not reading directly from the socket
    // (partial message OK)
    #[test]
    fn awaiting_act_two_to_complete_segmented() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.initiator.advance_handshake(&[]));

        let act2_partial1 = &test_ctx.valid_act2[..25];
        let act2_partial2 = &test_ctx.valid_act2[25..];

        assert_matches!(
            test_ctx.initiator.advance_handshake(act2_partial1),
            Ok(None)
        );
        assert_matches!(test_ctx.initiator, InitiatorAwaitingActTwo(_));
        assert_matches!(
            test_ctx.initiator.advance_handshake(act2_partial2),
            Ok(Some(_))
        );
        assert_matches!(test_ctx.initiator, Complete { .. });
    }

    // Initiator::AwaitingActTwo -> Error (bad version byte)
    // RFC test vector: transport-initiator act2 bad version test
    #[test]
    fn awaiting_act_two_bad_version_byte() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.initiator.advance_handshake(&[]));
        let act2 = Vec::<u8>::from_hex("0102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730").unwrap();

        assert_matches!(
            test_ctx.initiator.advance_handshake(&act2),
            Err(HandshakeError::UnexpectedVersion { version: 1, act: 2 })
        );
    }

    // Initiator::AwaitingActTwo -> Error (invalid ephemeral public key)
    // RFC test vector: transport-initiator act2 bad key serialization test
    #[test]
    #[ignore] // TODO: We do not have correct testvec data for curve25519
    fn awaiting_act_two_invalid_ephemeral_public_key() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.initiator.advance_handshake(&[]));
        let act2 = Vec::<u8>::from_hex("0004466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730").unwrap();

        assert_matches!(
            test_ctx.initiator.advance_handshake(&act2),
            Err(HandshakeError::InvalidEphemeralPubkey)
        );
    }

    // Initiator::AwaitingActTwo -> Error (invalid hmac)
    // RFC test vector: transport-initiator act2 bad MAC test
    #[test]
    fn awaiting_act_two_invalid_hmac() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.initiator.advance_handshake(&[]));
        let act2 = Vec::<u8>::from_hex("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730").unwrap();

        assert_matches!(
            test_ctx.initiator.advance_handshake(&act2),
            Err(HandshakeError::Encryption(EncryptionError::ChaCha(
                chacha20poly1305::aead::Error
            )))
        );
    }

    // Responder::AwaitingActThree -> Complete
    // RFC test vector: transport-responder successful handshake
    #[test]
    #[ignore] // TODO: We do not have correct testvec data for curve25519
    fn awaiting_act_three_to_complete() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.responder.advance_handshake(&test_ctx.valid_act1));

        assert_matches!(
            test_ctx.responder.advance_handshake(&test_ctx.valid_act3),
            Ok(None)
        );
        let (encryptor, decryptor) = test_ctx.responder.try_into_split().unwrap();

        assert_eq!(encryptor.remote_pubkey, test_ctx.initiator_public_key);
        assert_eq!(decryptor.remote_pubkey, test_ctx.initiator_public_key);
    }

    // Responder::AwaitingActThree -> None (with extra bytes)
    // Ensures that any remaining data in the read buffer is transferred to the
    // conduit once the handshake is complete
    #[test]
    #[ignore] // TODO: We do not have correct testvec data for curve25519
    fn awaiting_act_three_excess_bytes_after_complete_are_in_conduit() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.responder.advance_handshake(&test_ctx.valid_act1));
        let mut act3 = test_ctx.valid_act3.clone();
        act3.extend_from_slice(&[2; 100]);

        assert_matches!(
            test_ctx.responder.advance_handshake(&test_ctx.valid_act3),
            Ok(None)
        );
        let (encryptor, decryptor) = test_ctx.responder.try_into_split().unwrap();

        assert_eq!(encryptor.remote_pubkey, test_ctx.initiator_public_key);
        assert_eq!(decryptor.remote_pubkey, test_ctx.initiator_public_key);
    }

    // Responder::AwaitingActThree -> Error (bad version bytes)
    // RFC test vector: transport-responder act3 bad version test
    #[test]
    fn awaiting_act_three_bad_version_bytes() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.responder.advance_handshake(&test_ctx.valid_act1));
        let act3 = Vec::<u8>::from_hex("01b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap();

        assert_matches!(
            test_ctx.responder.advance_handshake(&act3),
            Err(HandshakeError::UnexpectedVersion { version: 1, act: 3 })
        );
    }

    // Responder::AwaitingActThree -> Complete (segmented calls)
    // RFC test vector: transport-responder act3 short read test
    // Divergence from RFC tests due to not reading directly from the socket
    // (partial message OK)
    #[test]
    #[ignore] // TODO: We do not have correct testvec data for curve25519
    fn awaiting_act_three_to_complete_segmented() {
        let mut test_ctx = TestCtx::new();
        unwrap!(test_ctx.responder.advance_handshake(&test_ctx.valid_act1));

        let act3_partial1 = &test_ctx.valid_act3[..35];
        let act3_partial2 = &test_ctx.valid_act3[35..];

        let next_state = test_ctx.responder.advance_handshake(act3_partial1).unwrap();
        assert_matches!(next_state, None);
        assert_matches!(
            test_ctx.responder.advance_handshake(act3_partial2),
            Ok(None)
        );
        assert_matches!(test_ctx.responder, Complete { .. })
    }

    // Responder::AwaitingActThree -> Error (invalid hmac)
    // RFC test vector: transport-responder act3 bad MAC for ciphertext test
    #[test]
    fn awaiting_act_three_invalid_hmac() {
        let mut test_ctx = TestCtx::new();
        test_ctx
            .responder
            .advance_handshake(&test_ctx.valid_act1)
            .unwrap()
            .unwrap();
        let act3 = Vec::<u8>::from_hex("00c9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap();

        assert_eq!(
            test_ctx.responder.advance_handshake(&act3).err().unwrap(),
            HandshakeError::Encryption(chacha20poly1305::aead::Error.into())
        );
    }

    // Responder::AwaitingActThree -> Error (invalid remote_static_key)
    // RFC test vector: transport-responder act3 bad rs test
    #[test]
    #[ignore] // TODO: We do not have correct testvec data for curve25519
    fn awaiting_act_three_invalid_rs() {
        let mut test_ctx = TestCtx::new();
        test_ctx
            .responder
            .advance_handshake(&test_ctx.valid_act1)
            .unwrap()
            .unwrap();
        let act3 = Vec::<u8>::from_hex("00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c").unwrap();

        assert_eq!(
            test_ctx.responder.advance_handshake(&act3).err().unwrap(),
            HandshakeError::InvalidInitiatorPubkey
        );
    }

    // Responder::AwaitingActThree -> Error (invalid tag hmac)
    // RFC test vector: transport-responder act3 bad MAC test
    #[test]
    fn awaiting_act_three_invalid_tag_hmac() {
        let mut test_ctx = TestCtx::new();
        test_ctx
            .responder
            .advance_handshake(&test_ctx.valid_act1)
            .unwrap()
            .unwrap();
        let act3 = Vec::<u8>::from_hex("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139bb").unwrap();

        assert_eq!(
            test_ctx.responder.advance_handshake(&act3).err().unwrap(),
            HandshakeError::Encryption(chacha20poly1305::aead::Error.into())
        );
    }

    // Initiator::Complete -> Error
    #[test]
    #[should_panic(expected = "nothing to process")]
    #[ignore] // TODO: We do not have correct testvec data for curve25519
    fn initiator_complete_next_fail() {
        let mut test_ctx = TestCtx::new();
        let act1 = test_ctx.initiator.advance_handshake(&[]).unwrap().unwrap();
        let act2 = unwrap!(test_ctx.responder.advance_handshake(&act1));
        unwrap!(test_ctx.initiator.advance_handshake(&act2));

        test_ctx.initiator.advance_handshake(&[]).unwrap();
    }

    // Initiator::Complete -> Error
    #[test]
    #[should_panic(expected = "nothing to process")]
    #[ignore] // TODO: We do not have correct testvec data for curve25519
    fn responder_complete_next_fail() {
        let mut test_ctx = TestCtx::new();
        let act1 = test_ctx.initiator.advance_handshake(&[]).unwrap().unwrap();
        let act2 = unwrap!(test_ctx.responder.advance_handshake(&act1));
        let act3 = unwrap!(test_ctx.initiator.advance_handshake(&act2));

        unwrap!(test_ctx.responder.advance_handshake(&act3));
        unwrap!(test_ctx.responder.advance_handshake(&[]));
    }

    // Test the Act byte generation against known good hard-coded values in case
    // the implementation changes in a symmetric way that makes the other
    // tests useless
    #[test]
    #[ignore] // TODO: We do not have correct testvec data for curve25519
    fn test_acts_against_reference_bytes() {
        let mut test_ctx = TestCtx::new();
        let act1 = test_ctx.initiator.advance_handshake(&[]).unwrap().unwrap();
        let act2 = unwrap!(test_ctx.responder.advance_handshake(&act1));
        let act3 = unwrap!(test_ctx.initiator.advance_handshake(&act2));

        assert_eq!(act1.as_ref().to_hex(),
				   "00052a50773ac8d91773f2dc9662e12f0defe915e415b8a1c8e20a5a3d6ab2b8435a390834e927487097032fd8abfa794b");
        assert_eq!(act2.as_ref().to_hex(),
				   "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");
        assert_eq!(act3.as_ref().to_hex(),
				   "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");
    }
}
