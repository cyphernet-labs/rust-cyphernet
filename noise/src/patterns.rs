// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2023 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2023 Cyphernet DAO, Switzerland
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use cypher::Ecdh;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
pub enum InitiatorPattern {
    #[display("N")]
    No,

    #[display("X")]
    Xmitted,

    #[display("K")]
    Known,

    #[display("I")]
    Immediately,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
pub enum OneWayPattern {
    #[display("N")]
    No,

    #[display("X")]
    Xmitted,

    #[display("L")]
    Known,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
pub enum PreMsgKeyPat {
    #[display("-> s")]
    InitiatorStatic,

    #[display("<- s")]
    ResponderStatic,

    #[display("")]
    Empty,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{initiator}{responder}")]
pub struct HandshakePattern {
    pub initiator: InitiatorPattern,
    pub responder: OneWayPattern,
}

impl HandshakePattern {
    pub fn nn() -> Self {
        Self {
            initiator: InitiatorPattern::No,
            responder: OneWayPattern::No,
        }
    }

    pub fn pre_messages(self) -> &'static [PreMsgKeyPat] {
        match (self.initiator, self.responder) {
            (InitiatorPattern::No, OneWayPattern::No) => &[PreMsgKeyPat::Empty],
            (InitiatorPattern::No, OneWayPattern::Known) => &[PreMsgKeyPat::ResponderStatic],
            (InitiatorPattern::No, OneWayPattern::Xmitted) => &[PreMsgKeyPat::Empty],
            (InitiatorPattern::Xmitted, OneWayPattern::No) => &[PreMsgKeyPat::Empty],
            (InitiatorPattern::Xmitted, OneWayPattern::Known) => &[PreMsgKeyPat::ResponderStatic],
            (InitiatorPattern::Xmitted, OneWayPattern::Xmitted) => &[PreMsgKeyPat::Empty],
            (InitiatorPattern::Known, OneWayPattern::No) => &[PreMsgKeyPat::InitiatorStatic],
            (InitiatorPattern::Known, OneWayPattern::Known) => {
                &[PreMsgKeyPat::InitiatorStatic, PreMsgKeyPat::ResponderStatic]
            }
            (InitiatorPattern::Known, OneWayPattern::Xmitted) => &[PreMsgKeyPat::InitiatorStatic],
            (InitiatorPattern::Immediately, OneWayPattern::No) => &[PreMsgKeyPat::Empty],
            (InitiatorPattern::Immediately, OneWayPattern::Known) => {
                &[PreMsgKeyPat::InitiatorStatic]
            }
            (InitiatorPattern::Immediately, OneWayPattern::Xmitted) => &[PreMsgKeyPat::Empty],
        }
    }

    pub fn message_patterns(self, is_initiator: bool) -> &'static [&'static [MessagePattern]] {
        if is_initiator {
            match (self.initiator, self.responder) {
                (InitiatorPattern::No, OneWayPattern::No) => &[&[MessagePattern::E]],
                (InitiatorPattern::No, OneWayPattern::Known) => {
                    &[&[MessagePattern::E, MessagePattern::ES]]
                }
                (InitiatorPattern::No, OneWayPattern::Xmitted) => &[&[MessagePattern::E]],
                (InitiatorPattern::Xmitted, OneWayPattern::No) => {
                    &[&[MessagePattern::E], &[MessagePattern::S, MessagePattern::SE]]
                }
                (InitiatorPattern::Xmitted, OneWayPattern::Known) => &[
                    &[MessagePattern::E, MessagePattern::ES],
                    &[MessagePattern::S, MessagePattern::SE],
                ],
                (InitiatorPattern::Xmitted, OneWayPattern::Xmitted) => {
                    &[&[MessagePattern::E], &[MessagePattern::S, MessagePattern::SE]]
                }
                (InitiatorPattern::Known, OneWayPattern::No) => &[&[MessagePattern::E]],
                (InitiatorPattern::Known, OneWayPattern::Known) => {
                    &[&[MessagePattern::E, MessagePattern::ES, MessagePattern::SS]]
                }
                (InitiatorPattern::Known, OneWayPattern::Xmitted) => &[&[MessagePattern::E]],
                (InitiatorPattern::Immediately, OneWayPattern::No) => {
                    &[&[MessagePattern::E, MessagePattern::S]]
                }
                (InitiatorPattern::Immediately, OneWayPattern::Known) => &[&[
                    MessagePattern::E,
                    MessagePattern::ES,
                    MessagePattern::S,
                    MessagePattern::SS,
                ]],
                (InitiatorPattern::Immediately, OneWayPattern::Xmitted) => {
                    &[&[MessagePattern::E, MessagePattern::S]]
                }
            }
        } else {
            match (self.initiator, self.responder) {
                (InitiatorPattern::No, OneWayPattern::No) => {
                    &[&[MessagePattern::E, MessagePattern::EE]]
                }
                (InitiatorPattern::No, OneWayPattern::Known) => {
                    &[&[MessagePattern::E, MessagePattern::EE]]
                }
                (InitiatorPattern::No, OneWayPattern::Xmitted) => &[&[
                    MessagePattern::E,
                    MessagePattern::EE,
                    MessagePattern::S,
                    MessagePattern::ES,
                ]],
                (InitiatorPattern::Xmitted, OneWayPattern::No) => {
                    &[&[MessagePattern::E, MessagePattern::EE]]
                }
                (InitiatorPattern::Xmitted, OneWayPattern::Known) => {
                    &[&[MessagePattern::E, MessagePattern::EE]]
                }
                (InitiatorPattern::Xmitted, OneWayPattern::Xmitted) => &[&[
                    MessagePattern::E,
                    MessagePattern::EE,
                    MessagePattern::S,
                    MessagePattern::ES,
                ]],
                (InitiatorPattern::Known, OneWayPattern::No) => {
                    &[&[MessagePattern::E, MessagePattern::EE, MessagePattern::SE]]
                }
                (InitiatorPattern::Known, OneWayPattern::Known) => {
                    &[&[MessagePattern::E, MessagePattern::EE, MessagePattern::SE]]
                }
                (InitiatorPattern::Known, OneWayPattern::Xmitted) => &[&[
                    MessagePattern::E,
                    MessagePattern::EE,
                    MessagePattern::SE,
                    MessagePattern::S,
                    MessagePattern::ES,
                ]],
                (InitiatorPattern::Immediately, OneWayPattern::No) => {
                    &[&[MessagePattern::E, MessagePattern::EE, MessagePattern::SE]]
                }
                (InitiatorPattern::Immediately, OneWayPattern::Known) => {
                    &[&[MessagePattern::E, MessagePattern::EE, MessagePattern::SE]]
                }
                (InitiatorPattern::Immediately, OneWayPattern::Xmitted) => &[&[
                    MessagePattern::E,
                    MessagePattern::EE,
                    MessagePattern::SE,
                    MessagePattern::S,
                    MessagePattern::ES,
                ]],
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Keyset<E: Ecdh> {
    pub e: E,
    pub s: Option<E>,
    pub re: Option<E::Pk>,
    pub rs: Option<E::Pk>,
}

impl<E: Ecdh> Keyset<E> {
    pub fn noise_nn() -> Self {
        let pair = E::generate_keypair();
        Self {
            e: pair.0,
            s: None,
            re: None,
            rs: None,
        }
    }

    pub fn pre_message_key(&self, pmkp: PreMsgKeyPat, is_initiator: bool) -> Option<E::Pk> {
        Some(match (pmkp, is_initiator) {
            (PreMsgKeyPat::InitiatorStatic, true) | (PreMsgKeyPat::ResponderStatic, false) => {
                self.expect_s().to_pk().expect("invalid static key")
            }
            (PreMsgKeyPat::ResponderStatic, true) | (PreMsgKeyPat::InitiatorStatic, false) => {
                self.expect_rs().clone()
            }
            (PreMsgKeyPat::Empty, _) => return None,
        })
    }

    pub fn expect_s(&self) -> &E { self.s.as_ref().expect("static key must be known") }

    pub fn expect_re(&self) -> &E::Pk {
        self.re.as_ref().expect("remote ephemeral key must be known at this stage")
    }

    pub fn expect_rs(&self) -> &E::Pk {
        self.rs.as_ref().expect("remote static key must be known at this stage")
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[non_exhaustive] // Future specifications might introduce other tokens.
pub enum MessagePattern {
    #[display("e")]
    E,

    #[display("s")]
    S,

    #[display("ee")]
    EE,

    #[display("es")]
    ES,

    #[display("se")]
    SE,

    #[display("ss")]
    SS,
    // TODO: Support PSK pattern
}
