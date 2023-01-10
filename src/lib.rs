// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2022-2023 Cyphernet Association, Switzerland
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

//! Cyphernet is a set of libraries for privacy-preserving networking & internet
//! applications.
//!
//! The set of libraries supports mix networks (Tor, I2P, Nym), proxies,
//! end-to-end encryption without central authorities/PKI (Noise-based
//! encryption protocols like lightning wire protocol, NTLS etc).
//! The library provides three main components, structured as modules:
//! - **Network addresses** (module `addr`), which allow simple use of
//! - Tor, Nym, I2P and other mix networks and SOCKS proxies
//! - P2P addresses with node public keys
//! - May be used in a way that prevents using DNS names (outside mixnet scope).
//! - **Noise protocol framework** (module `noise`) for end-to-end encrypted
//! network communications.
//!
//! The library tries to minimize number of dependencies. Most of its
//! functionality is available via non-default features, like:
//! - `noise`: support for noise protocols
//! - `mixnets`: supports for mixnet network addresses, including `tor`, `nym`, `i2p` (may require
//!   additional crypto libraries for parsing public keys)
//! - `serde`: encoding for addresses types
//! - `dns`: enable use of DNS names alongside IP addresses and mixnet names.
//!
//! Network addresses provided by the library include the following types:
//! * [`addr::InetHost`] - IP addr or DNS name
//! * [`addr::HostName`] - IP, DNS, Tor, I2P, Nym host name (no port or proxy information)
//! * [`addr::NetAddr`] - any type of host name + port information
//! * [`addr::PartialAddr`] - any type of host name + optional port, which defaults to generic const
//!   if not provided
//! * [`addr::PeerAddr`] - any of the above addresses + node public key for authentication
//! * [`addr::ProxiedHost`] - host name + proxy (there are IP/DNS w/o proxy and with proxy)
//! * [`addr::ProxiedAddr`] - any of the above addresses + proxy (thus IP/DNS is always proxied)

#[macro_use]
extern crate amplify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;
extern crate core;

pub mod addr;
pub mod crypto;
#[cfg(feature = "noise")]
pub mod noise;
#[cfg(test)]
mod test;
