// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2022-2023 Cyphernet DAO, Switzerland
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

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
#[repr(u8)]
pub enum ServerError {
    /// general SOCKS server failure
    GeneralFailure = 1,
    /// connection not allowed by ruleset
    NotAllowed = 2,
    /// network unreachable
    NetworkUnreachable = 3,
    /// host unreachable
    HostUnreachable = 4,
    /// connection refused
    ConnectionRefused = 5,
    /// TTL expired
    TtlExpired = 6,
    /// command not supported
    CommandNotSupported = 7,
    /// address kind not supported
    AddressNotSupported = 8,
    /// unknown error type
    Unknown = 0xFF,
}

impl From<u8> for ServerError {
    fn from(value: u8) -> Self {
        const ALL: [ServerError; 9] = [
            ServerError::GeneralFailure,
            ServerError::NotAllowed,
            ServerError::NetworkUnreachable,
            ServerError::HostUnreachable,
            ServerError::ConnectionRefused,
            ServerError::TtlExpired,
            ServerError::CommandNotSupported,
            ServerError::AddressNotSupported,
            ServerError::Unknown,
        ];

        for ty in ALL {
            if ty as u8 == value {
                return ty;
            }
        }

        unreachable!()
    }
}
