// SPDX-License-Identifier: MIT OR Apache-2.0

//! A cryptanalysis workbench for classical ciphers.
//!
//! The library is organised around one conviction: a number is not evidence until something says what that number looks like when nothing is there.
//! Every attack in [`attack`] is run twice, once on the ciphertext and once on shuffles of it, and every statistic in [`triage`] is reported beside the distribution it has to stand out from.
//!
//! The second conviction is that the judge must not assume a language.
//! [`polyglot::Polyglot`] carries an n-gram model per language and scores a candidate under all of them, which is what lets a search recognise a plaintext it was never told to expect.

pub mod alphabet;
pub mod anneal;
pub mod attack;
pub mod ciphers;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod ngram;
pub mod polyglot;
pub mod report;
pub mod rng;
pub mod square;
pub mod stats;
pub mod sweep;
pub mod triage;

pub use alphabet::{Letter, Text, from_letters, to_letters};
