// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where a guessed word could sit, and where it could not.
//!
//! Enigma's reflector cannot send a letter back to itself, so a plaintext never agrees with its ciphertext at any position.
//! That is not a statistic and it does not weaken with the length of the message: one position of agreement refutes a placement outright, whatever the rotors, whatever the plugboard, whatever the language.
//!
//! It is the only exact tool this crate has.
//! Everything else weighs evidence;
//! this rules out.

use crate::alphabet::Letter;

/// A guessed fragment of plaintext, and where it could sit.
#[derive(Clone, Debug)]
pub struct Crib {
    /// The guessed letters.
    pub word: Vec<Letter>,
    /// Every offset the ciphertext does not refute.
    pub offsets: Vec<usize>,
}

/// Where a crib could sit in a ciphertext.
///
/// Every offset where no letter of the crib meets its own image.
#[must_use]
pub fn placements(ct: &[Letter], word: &[Letter]) -> Vec<usize> {
    if word.is_empty() || word.len() > ct.len() {
        return Vec::new();
    }
    (0..=ct.len() - word.len())
        .filter(|&offset| word.iter().zip(&ct[offset..]).all(|(a, b)| a != b))
        .collect()
}

impl Crib {
    /// A crib placed against a ciphertext.
    #[must_use]
    pub fn against(ct: &[Letter], word: &[Letter]) -> Crib {
        Crib { word: word.to_vec(), offsets: placements(ct, word) }
    }

    /// How much of the search a crib removes, as a share of the offsets.
    #[must_use]
    pub fn cut(&self, ct_len: usize) -> f64 {
        let total = ct_len.saturating_sub(self.word.len()) + 1;
        if total == 0 {
            return 0.0;
        }
        1.0 - self.offsets.len() as f64 / total as f64
    }
}

/// Words a Kriegsmarine signal is likely to contain.
///
/// Naval Enigma traffic was formulaic, which is what made it readable at all:
/// reports opened and closed the same way, numbers were spelled out, and `X` stood in for the punctuation the machine had no keys for.
pub const KRIEGSMARINE: &[&str] = &[
    "VONVON",
    "ANBDU",
    "UBOOT",
    "FEINDKONVOI",
    "MARQUADRAT",
    "STANDORT",
    "WETTER",
    "MELDE",
    "ANGRIFF",
    "TORPEDO",
    "GESENKT",
    "NICHTSZUMELDEN",
    "FUNKSPRUCH",
    "KEINEBESONDEREN",
    "EINSEINS",
    "ZWOZWO",
    "QUADRAT",
    "GELEITZUG",
    "ZERSTOERER",
    "TAUCHE",
    "BEGINN",
    "ENDEXX",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;
    use crate::ciphers::enigma::{Enigma, Plugboard, Settings};

    #[test]
    fn a_letter_over_itself_refutes_a_placement() {
        let ct = to_letters("ABCDEF");
        // "A" cannot sit at offset 0, where the ciphertext is also A.
        assert!(!placements(&ct, &to_letters("A")).contains(&0));
        assert!(placements(&ct, &to_letters("A")).contains(&1));
    }

    #[test]
    fn a_crib_longer_than_the_text_sits_nowhere() {
        assert!(placements(&to_letters("AB"), &to_letters("ABC")).is_empty());
    }

    #[test]
    fn an_empty_crib_sits_nowhere() {
        assert!(placements(&to_letters("ABC"), &[]).is_empty());
    }

    #[test]
    fn the_true_placement_is_never_refuted() {
        // The property the whole method rests on: whatever the machine, the real plaintext survives its own ciphertext.
        let settings = Settings::new([0, 1, 2], 0);
        let plain = to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXX");
        let ct = Enigma::new(settings, Plugboard::empty()).run(&plain);
        for start in [0usize, 3, 7, 11] {
            let word = &plain[start..start + 6];
            assert!(
                placements(&ct, word).contains(&start),
                "the true placement at {start} was refuted"
            );
        }
    }

    #[test]
    fn a_longer_crib_cuts_more() {
        let settings = Settings::new([0, 1, 2], 0);
        let plain = to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXXFEINDKONVOIINSICHT");
        let ct = Enigma::new(settings, Plugboard::empty()).run(&plain);
        let short = Crib::against(&ct, &to_letters("VON"));
        let long = Crib::against(&ct, &to_letters("VONVONJAWEGEN"));
        assert!(long.cut(ct.len()) > short.cut(ct.len()));
    }

    #[test]
    fn the_naval_cribs_are_letters_only() {
        for word in KRIEGSMARINE {
            assert_eq!(to_letters(word).len(), word.len(), "{word}");
        }
    }
}
