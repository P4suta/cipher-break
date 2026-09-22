// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ciphers themselves: how each one transforms a text under a key.
//!
//! Nothing here searches for anything.
//! A cipher knows how to encipher and how to decipher, and that is all; the searching lives in [`crate::attack`], so that a new cipher can be added without touching a search and a new search can be added without touching a cipher.

pub mod autokey;
pub mod bifid;
pub mod enigma;
pub mod hill;
pub mod periodic;
pub mod playfair;
pub mod porta;
pub mod substitution;
pub mod transposition;
