# Eidolon: network authentication separated from encryption

![Build](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Build/badge.svg)
![Tests](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Tests/badge.svg)
![Lints](https://github.com/Cyphernet-WG/rust-cyphernet/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/Cyphernet-WG/rust-cyphernet/branch/master/graph/badge.svg)](https://codecov.io/gh/Cyphernet-WG/rust-cyphernet)

[![crates.io](https://img.shields.io/crates/v/eidolon)](https://crates.io/crates/eidolon)
[![Docs](https://docs.rs/eidolon/badge.svg)](https://docs.rs/eidolon)
[![Apache-2 licensed](https://img.shields.io/crates/l/eidolon)](./LICENSE)


## Overview

Most of the existing network protocols providing encryption, such as TLS (or 
older SSL), SSH, Noise Framework combine both authentication and encryption.
However, in many cases the authentication is desired to be separate from the
encryption layer, which may operate with just an ephemeral keys.

Eidolon is a simple binary authentication protocol for network connections
abstracted from the encryption layer, which can be combined with virtually
any encryption protocols of today or a future.

The library is a part of [rust cyphernet suite](https://github.com/Cyphernet-WG/rust-cyphernet).


## Manifest

```yaml
Name: eidolon
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
