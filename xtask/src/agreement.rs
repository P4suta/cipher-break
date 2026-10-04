// SPDX-License-Identifier: MIT OR Apache-2.0

pub fn matches_fixture(rust: Option<[u8; 6]>, reference: Option<[u8; 6]>) -> bool {
    rust == Some(*b"0.0438") && rust == reference
}
