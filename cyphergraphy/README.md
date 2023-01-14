# Cyphergraphy: Implementation-independent abstractions for main cryptographic algorithms

![Build](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Build/badge.svg)
![Tests](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Tests/badge.svg)
![Lints](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/Cyphernet-WG/rust-cyphernet/branch/master/graph/badge.svg)](https://codecov.io/gh/Cyphernet-WG/rust-cyphernet)

[![crates.io](https://img.shields.io/crates/v/cyphergraphy)](https://crates.io/crates/cyphergraphy)
[![Docs](https://docs.rs/cyphergraphy/badge.svg)](https://docs.rs/cyphergraphy)
[![Apache-2 licensed](https://img.shields.io/crates/l/cyphergraphy)](./LICENSE)


## Overview

Implementation-independent abstractions for main cryptographic algorithms used 
for end-to-end encryption and authorization:
- Algorithms based on Edwards curves:
  - ECDH with X25519 scheme using Curve25519 keys
  - EdDSA signatures with Ed25519 sheme using Edwards25519 keys
- Algorithms based on NSA Secp256k1 curve:
  - ECDH with normal Secp256k1 keys
  - ECDSA signatures with normal Secp256k1 keys
  - Schnorr signatures with BIP340 scheme and x-only public keys
- Digest algorithms with a unified API
  - SHA2: SHA256 & SHA512
  - SHA3: SHA3-256 & SHA3-512
  - Blake3

The library is a part of [rust cyphernet suite](https://github.com/Cyphernet-WG/rust-cyphernet)
and used by other libraries of the suite for handling internet addresses.


## Manifest

```yaml
Name: cyphergraphy
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


## Documentation

API reference documentation for the library can be accessed at
<https://docs.rs/cyphergraphy/>.


## Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.
