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

/// Authentication methods
#[derive(Debug)]
enum Authentication<'a> {
    Password {
        username: &'a str,
        password: &'a str,
    },
    None,
}

impl<'a> Authentication<'a> {
    fn id(&self) -> u8 {
        match *self {
            Authentication::Password { .. } => 2,
            Authentication::None => 0,
        }
    }

    fn is_no_auth(&self) -> bool {
        if let Authentication::None = *self {
            true
        } else {
            false
        }
    }
}
