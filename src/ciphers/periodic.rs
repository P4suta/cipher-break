// SPDX-License-Identifier: MIT OR Apache-2.0

//! The three ciphers that reuse a key letter every `n` positions.
//!
//! They differ only in the arithmetic joining plaintext, key and ciphertext,
//! so one [`Family`] parameter lets every attack cover all three at once instead of being written three times.

use crate::alphabet::{ALPHABET, Letter};

/// Which member of the Vigenere family a key is read under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// `c = p + k`
    Vigenere,
    /// `c = k - p`, an involution: enciphering twice returns the plaintext.
    Beaufort,
    /// `c = p - k`, the Vigenere table used backwards.
    VariantBeaufort,
}

/// All three, for attacks that sweep the family.
pub const FAMILIES: [Family; 3] = [Family::Vigenere, Family::Beaufort, Family::VariantBeaufort];

impl Family {
    /// The short name used in reports and keys.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Family::Vigenere => "vigenere",
            Family::Beaufort => "beaufort",
            Family::VariantBeaufort => "variant",
        }
    }

    /// One plaintext letter under one key letter.
    #[inline]
    #[must_use]
    pub fn encipher_letter(self, k: Letter, p: Letter) -> Letter {
        let a = ALPHABET as u8;
        match self {
            Family::Vigenere => (p + k) % a,
            Family::Beaufort => (k + a - p % a) % a,
            Family::VariantBeaufort => (p + a - k % a) % a,
        }
    }

    /// One ciphertext letter under one key letter.
    #[inline]
    #[must_use]
    pub fn decipher_letter(self, k: Letter, c: Letter) -> Letter {
        let a = ALPHABET as u8;
        match self {
            Family::Vigenere => (c + a - k % a) % a,
            Family::Beaufort => (k + a - c % a) % a,
            Family::VariantBeaufort => (c + k) % a,
        }
    }
}

/// Encipher under a repeating key; an empty key is the identity.
#[must_use]
pub fn encipher(fam: Family, key: &[Letter], pt: &[Letter]) -> Vec<Letter> {
    if key.is_empty() {
        return pt.to_vec();
    }
    pt.iter()
        .enumerate()
        .map(|(i, &p)| fam.encipher_letter(key[i % key.len()], p))
        .collect()
}

/// The inverse of [`encipher`].
#[must_use]
pub fn decipher(fam: Family, key: &[Letter], ct: &[Letter]) -> Vec<Letter> {
    if key.is_empty() {
        return ct.to_vec();
    }
    ct.iter()
        .enumerate()
        .map(|(i, &c)| fam.decipher_letter(key[i % key.len()], c))
        .collect()
}

/// Decipher into an existing buffer, for search loops that cannot afford an allocation per key.
pub fn decipher_into(fam: Family, key: &[Letter], ct: &[Letter], out: &mut [Letter]) {
    if key.is_empty() {
        out.copy_from_slice(ct);
        return;
    }
    let n = key.len();
    for (i, (&c, slot)) in ct.iter().zip(out.iter_mut()).enumerate() {
        *slot = fam.decipher_letter(key[i % n], c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::{from_letters, to_letters};

    const PLAIN: &str = "ITISACAPITALMISTAKETOTHEORIZEBEFOREONEHASDATAINSENSIBLYONEBEGINS";

    #[test]
    fn vigenere_matches_the_textbook_vector() {
        let ct = encipher(
            Family::Vigenere,
            &to_letters("LEMON"),
            &to_letters("ATTACKATDAWN"),
        );
        assert_eq!(from_letters(&ct), "LXFOPVEFRNHR");
    }

    #[test]
    fn deciphering_inverts_enciphering() {
        for fam in FAMILIES {
            for key in ["A", "LEMON", "ZZ", "CRYPTO"] {
                let k = to_letters(key);
                let msg = to_letters(PLAIN);
                assert_eq!(decipher(fam, &k, &encipher(fam, &k, &msg)), msg);
            }
        }
    }

    #[test]
    fn beaufort_is_its_own_inverse() {
        let k = to_letters("LEMON");
        let msg = to_letters(PLAIN);
        assert_eq!(
            encipher(Family::Beaufort, &k, &encipher(Family::Beaufort, &k, &msg)),
            msg
        );
    }

    #[test]
    fn an_empty_key_changes_nothing() {
        let msg = to_letters(PLAIN);
        assert_eq!(encipher(Family::Vigenere, &[], &msg), msg);
    }

    #[test]
    fn the_buffered_path_agrees_with_the_allocating_one() {
        let k = to_letters("LEMON");
        let ct = to_letters(PLAIN);
        let mut buf = vec![0u8; ct.len()];
        decipher_into(Family::Beaufort, &k, &ct, &mut buf);
        assert_eq!(buf, decipher(Family::Beaufort, &k, &ct));
    }
}
