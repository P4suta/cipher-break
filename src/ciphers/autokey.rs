// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ciphers whose key is the message itself after a short primer.
//!
//! An autokey never repeats, so it has no period for superposition to find and no column for a frequency count to flatten.
//! What it does have is a primer short enough to exhaust: get it right and the whole message unrolls, get it wrong and every letter after the primer is wrong too.
//! That all-or-nothing behaviour is what lets a cheap judge decide.

use crate::alphabet::Letter;
use crate::ciphers::periodic::Family;

/// What the key stream continues with once the primer runs out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priming {
    /// The plaintext, as Vigenere originally proposed.
    Plaintext,
    /// The ciphertext, which needs no lookahead to decipher.
    Ciphertext,
}

/// Both, for attacks that sweep them.
pub const PRIMINGS: [Priming; 2] = [Priming::Plaintext, Priming::Ciphertext];

impl Priming {
    /// The short name used in reports and keys.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Priming::Plaintext => "plain-primed",
            Priming::Ciphertext => "cipher-primed",
        }
    }
}

/// Encipher under an autokey.
#[must_use]
pub fn encipher(mode: Priming, fam: Family, primer: &[Letter], pt: &[Letter]) -> Vec<Letter> {
    if primer.is_empty() {
        return pt.to_vec();
    }
    let m = primer.len();
    let mut ct = Vec::with_capacity(pt.len());
    for (i, &p) in pt.iter().enumerate() {
        let k = if i < m {
            primer[i]
        } else {
            match mode {
                Priming::Plaintext => pt[i - m],
                Priming::Ciphertext => ct[i - m],
            }
        };
        ct.push(fam.encipher_letter(k, p));
    }
    ct
}

/// Decipher an autokey into an existing buffer.
///
/// The key stream is defined in terms of the plaintext it is being used to produce.
/// That is not circular: position `i` only ever consults position `i - primer.len()`, so one forward pass unrolls it.
pub fn decipher_into(
    mode: Priming,
    fam: Family,
    primer: &[Letter],
    ct: &[Letter],
    out: &mut [Letter],
) {
    if primer.is_empty() {
        out.copy_from_slice(ct);
        return;
    }
    let m = primer.len();
    for i in 0..ct.len() {
        let k = if i < m {
            primer[i]
        } else {
            match mode {
                Priming::Plaintext => out[i - m],
                Priming::Ciphertext => ct[i - m],
            }
        };
        out[i] = fam.decipher_letter(k, ct[i]);
    }
}

/// Decipher an autokey.
#[must_use]
pub fn decipher(mode: Priming, fam: Family, primer: &[Letter], ct: &[Letter]) -> Vec<Letter> {
    let mut out = vec![0u8; ct.len()];
    decipher_into(mode, fam, primer, ct, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;
    use crate::ciphers::periodic::FAMILIES;

    const PLAIN: &str = "ITISACAPITALMISTAKETOTHEORIZEBEFOREONEHASDATAINSENSIBLY";

    #[test]
    fn deciphering_inverts_enciphering() {
        for mode in PRIMINGS {
            for fam in FAMILIES {
                for primer in ["K", "LEMON", "ZZ"] {
                    let p = to_letters(primer);
                    let msg = to_letters(PLAIN);
                    assert_eq!(decipher(mode, fam, &p, &encipher(mode, fam, &p, &msg)), msg);
                }
            }
        }
    }

    #[test]
    fn the_two_primings_differ() {
        let p = to_letters("K");
        let msg = to_letters(PLAIN);
        assert_ne!(
            encipher(Priming::Plaintext, Family::Vigenere, &p, &msg),
            encipher(Priming::Ciphertext, Family::Vigenere, &p, &msg)
        );
    }

    #[test]
    fn an_empty_primer_changes_nothing() {
        let msg = to_letters(PLAIN);
        assert_eq!(
            encipher(Priming::Plaintext, Family::Vigenere, &[], &msg),
            msg
        );
    }
}
