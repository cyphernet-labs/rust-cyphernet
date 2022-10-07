//! Cyphernet node address types

#[cfg(feature = "i2p")]
pub mod i2p;
mod net;
mod node;
#[cfg(feature = "nym")]
pub mod nym;
mod proxied;
mod universal;

pub use net::NetAddr;
pub use node::{LocalNode, NodeId, PeerAddr};
pub use proxied::ProxiedAddr;
pub use universal::UniversalAddr;
