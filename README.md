# Cyphernet Rust Library

![Build](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Build/badge.svg)
![Tests](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Tests/badge.svg)
![Lints](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/Cyphernet-WG/rust-cyphernet/branch/master/graph/badge.svg)](https://codecov.io/gh/Cyphernet-WG/rust-cyphernet)

[![crates.io](https://img.shields.io/crates/v/cyphernet)](https://crates.io/crates/cyphernet)
[![Docs](https://docs.rs/cyphernet/badge.svg)](https://docs.rs/cyphernet)
[![Apache-2 licensed](https://img.shields.io/crates/l/cyphernet)](./LICENSE)

Cyphernet is a set of libraries for privacy-preserving networking & internet
applications.

The set of libraries supports mix networks (Tor, I2P, Nym), proxies, end-to-end
encryption without central authorities/PKI (Noise-based encryption protocols 
like lightning wire protocol, NTLS etc).


    Language: Rust
    Minimal compiler version: 1.59
    Author: Maxim Orlovsky
    Maintained: Cyphernet Association, Switzerland
    Maintainers: Maxim Orlovsky (@dr-orlovsky)
                 Alexis Sellier (@cloudhead)
    Type: Free software
    License: Apache-2.0
 
## Overview

The library provides three main components, structured as modules:
- **Network addresses** (module `addr`), which allow simple use of
    - Tor, Nym, I2P and other mix networks and SOCKS proxies
    - P2P addresses with node public keys
    - May be used in a way that prevents using DNS names (outside mixnet scope).
- **Noise protocol framework** (module `noise`) for end-to-end encrypted
  network communications.

The library tries to minimize number of dependencies. Most of its functionality
is available via non-default features, like:
- `noise`: support for noise protocols
- `mixnets`: supports for mixnet network addresses, including `tor`, `nym`, 
             `i2p` (may require additional crypto libraries for parsing public 
             keys)
- `serde`: encoding for addresses types
- `dns`: enable use of DNS names alongside IP addresses and mixnet names.

Network addresses provided by the library include the following types:
* `InetHost` - IP addr or DNS name
* `HostName` - IP, DNS, Tor, I2P, Nym host name (no port or proxy information)
* `NetAddr` - any type of host name + port information
* `PartialAddr` - any type of host name + optional port, which defaults to 
                  generic const if not provided
* `PeerAddr` - any of the above addresses + node public key for authentication
* `ProxiedHost` - host name + proxy (there are IP/DNS w/o proxy and with proxy)
* `ProxiedAddr` - any of the above addresses + proxy (thus IP/DNS is always 
                  proxied)


## Documentation

API reference documentation for the library can be accessed at
<https://docs.rs/cyphernet/>.


## Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.
