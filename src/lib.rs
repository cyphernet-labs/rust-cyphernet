//! Cyphernet is a set of libraries for privacy-based internet applications.
//!
//! The set of libraries supports mix networks (Tor, I2P, Nym), proxies,
//! end-to-end encryption without central authorities/PKI (Noise-based
//! encryption protocols like lightning wire protocol, NTLS etc).

#[macro_use]
extern crate amplify_derive;
extern crate core;

pub mod addr;
pub mod crypto;