// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2022-2023 Cyphernet Initiative, Switzerland
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

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::string::FromUtf8Error;

use cypheraddr::{AddrParseError, HostName};

use super::*;

#[derive(Debug, Display, Error, From)]
pub enum EncodingError {
    #[from]
    #[display(inner)]
    Io(io::Error),

    /// not supported version of host information
    UnknownHostCode(u8),

    /// used address type is not supported
    AddrNotSupported,

    /// the provided domain name has length {0} exceeding max length of 256 bytes
    DomainNameTooLong(usize),

    #[from]
    #[display(inner)]
    InvalidDomainName(FromUtf8Error),

    /// invalid server response version {0}
    InvalidVersion(u8),

    /// invalid reserve byte value in server response
    InvalidReserveByte,

    #[from]
    #[display(inner)]
    InvalidAddress(AddrParseError),
}

pub trait Encoding: Sized {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError>;
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError>;
}

impl Encoding for u8 {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        let mut buf = [0; 1];
        reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        writer.write_all(&[*self][..])?;
        Ok(())
    }
}

impl Encoding for u16 {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        let mut buf = [0; 2];
        reader.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        writer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl Encoding for u32 {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        let mut buf = [0; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        writer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl Encoding for u128 {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        let mut buf = [0; 16];
        reader.read_exact(&mut buf)?;
        Ok(u128::from_be_bytes(buf))
    }
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        writer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl Encoding for Ipv4Addr {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        u32::decode(reader).map(Ipv4Addr::from)
    }
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        u32::from(*self).encode(writer)
    }
}

impl Encoding for Ipv6Addr {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        u128::decode(reader).map(Ipv6Addr::from)
    }
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        u128::from(*self).encode(writer)
    }
}

impl Encoding for SocketAddrV4 {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        let ip = Ipv4Addr::decode(reader)?;
        let port = u16::decode(reader)?;
        Ok(SocketAddrV4::new(ip, port))
    }
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        self.ip().encode(writer)?;
        self.port().encode(writer)
    }
}

impl Encoding for SocketAddrV6 {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        let ip = Ipv6Addr::decode(reader)?;
        let port = u16::decode(reader)?;
        Ok(SocketAddrV6::new(ip, port, 0, 0))
    }
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        self.ip().encode(writer)?;
        self.port().encode(writer)
    }
}

pub(crate) const IPV4: u8 = 1;
pub(crate) const IPV6: u8 = 4;
pub(crate) const DOMAIN: u8 = 3;

impl Encoding for HostName {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        match u8::decode(reader)? {
            IPV4 => Ok(HostName::Ip(Ipv4Addr::decode(reader)?.into())),
            IPV6 => Ok(HostName::Ip(Ipv6Addr::decode(reader)?.into())),
            DOMAIN => {
                let len = u8::decode(reader)?;
                let mut domain = vec![0; len as usize];
                reader.read_exact(&mut domain)?;
                let domain =
                    String::from_utf8(domain).map_err(|e| EncodingError::InvalidDomainName(e))?;
                HostName::from_str(&domain).map_err(EncodingError::from)
            }
            unknown => Err(EncodingError::UnknownHostCode(unknown)),
        }
    }

    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        let name = match self {
            HostName::Ip(IpAddr::V4(ip)) => {
                IPV4.encode(writer)?;
                return ip.encode(writer);
            }
            HostName::Ip(IpAddr::V6(ip)) => {
                IPV6.encode(writer)?;
                return ip.encode(writer);
            }
            HostName::Dns(name) => name.to_string(),
            HostName::Tor(addr) => addr.to_string(),
            HostName::I2p(addr) => addr.to_string(),
            HostName::Nym(addr) => addr.to_string(),
            _ => return Err(EncodingError::AddrNotSupported),
        };
        let len =
            u8::try_from(name.len()).map_err(|_| EncodingError::DomainNameTooLong(name.len()))?;
        len.encode(writer)?;
        writer.write_all(name.as_bytes()).map_err(EncodingError::from)
    }
}

impl Encoding for NetAddr<HostName> {
    fn decode(reader: &mut impl Read) -> Result<Self, EncodingError> {
        let host = HostName::decode(reader)?;
        let port = u16::decode(reader)?;
        Ok(NetAddr::new(host, port))
    }

    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodingError> {
        self.host.encode(writer)?;
        self.port.encode(writer).map_err(EncodingError::from)
    }
}
