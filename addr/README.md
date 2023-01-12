# Cypheraddr: network addresses supporting SOCKS5, Tor, I2P, Nym and P2P pubkeys

![Build](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Build/badge.svg)
![Tests](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Tests/badge.svg)
![Lints](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/Cyphernet-WG/rust-cyphernet/branch/master/graph/badge.svg)](https://codecov.io/gh/Cyphernet-WG/rust-cyphernet)

[![crates.io](https://img.shields.io/crates/v/cypheraddr)](https://crates.io/crates/cypheraddr)
[![Docs](https://docs.rs/cypheraddr/badge.svg)](https://docs.rs/cypheraddr)
[![Apache-2 licensed](https://img.shields.io/crates/l/cypheraddr)](./LICENSE)

Rust library providing a set of address data types with minimal dependencies
which allow simple use of.
- Tor, Nym, I2P and other mix networks and SOCKS proxies;
- P2P addresses with node public keys.

The crate may be used in a way that prevents using DNS names (outside mixnet 
scope).

The library is a part of [rust cyphernet suite](https://github.com/Cyphernet-WG/rust-cyphernet).


## Manifest

```yaml
Name: cypheraddr
Type: Library
Kind: Free software
License: Apache-2.0
Language: Rust
Compiler: 1.65
Author: Maxim Orlovsky
Maintained: Cyphernet Initiative, Switzerland
Maintainers:
  Maxim Orlovsky:
    GitHub: @dr-orlovsky
    GPG: EAE730CEC0C663763F028A5860094BAF18A26EC9
    SSH: BoSGFzbyOKC7Jm28MJElFboGepihCpHop60nS8OoG/A
    EMail: dr@orlovsky.ch
  Alexis Sellier:
    GitHub: @cloudhead
    SSH: iTDjRHSIaoL8dpHbQ0mv+y0IQqPufGl2hQwk4TbXFlw
```

## Overview

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

The library tries to minimize number of dependencies. Most of its functionality
is available via non-default features, like:
- `mixnets`: supports for mixnet network addresses, including `tor`, `nym`,
  `i2p` (may require additional crypto libraries for parsing public keys);
- `serde`: encoding for addresses types;
- `dns`: enable use of DNS names alongside IP addresses and mixnet names.


## Documentation

API reference documentation for the library can be accessed at
<https://docs.rs/cypheraddr/>.


## Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.
