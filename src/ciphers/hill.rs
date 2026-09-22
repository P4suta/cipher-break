// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hill's cipher on pairs of letters.
//!
//! Enciphering two letters at a time flattens the single-letter statistics every classical attack relies on, so no amount of frequency work touches it.
//! It is also small: a two-by-two key over 26 letters has 157,248 invertible forms, and a machine can try all of them.
//! Searching the deciphering matrices directly avoids inverting anything, since every invertible matrix is the inverse of exactly one other.

use crate::alphabet::{ALPHABET, Letter};

/// A two-by-two matrix over the integers modulo 26.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Matrix(pub u8, pub u8, pub u8, pub u8);

impl std::fmt::Display for Matrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{} {}; {} {}]", self.0, self.1, self.2, self.3)
    }
}

impl Matrix {
    /// The determinant, modulo 26.
    #[must_use]
    pub fn determinant(self) -> u8 {
        let a = i32::from(self.0) * i32::from(self.3) - i32::from(self.1) * i32::from(self.2);
        a.rem_euclid(ALPHABET as i32) as u8
    }

    /// A matrix is usable exactly when its determinant has an inverse modulo 26.
    #[must_use]
    pub fn invertible(self) -> bool {
        gcd(u32::from(self.determinant()), ALPHABET as u32) == 1
    }

    /// Transform a text two letters at a time into an existing buffer; a trailing odd letter is left as it is.
    pub fn apply_into(self, ls: &[Letter], out: &mut [Letter]) {
        let a = ALPHABET as u16;
        let mut i = 0;
        while i + 1 < ls.len() {
            let (x, y) = (u16::from(ls[i]), u16::from(ls[i + 1]));
            out[i] = ((u16::from(self.0) * x + u16::from(self.1) * y) % a) as u8;
            out[i + 1] = ((u16::from(self.2) * x + u16::from(self.3) * y) % a) as u8;
            i += 2;
        }
        if i < ls.len() {
            out[i] = ls[i];
        }
    }

    /// Transform a text two letters at a time.
    #[must_use]
    pub fn apply(self, ls: &[Letter]) -> Vec<Letter> {
        let mut out = vec![0u8; ls.len()];
        self.apply_into(ls, &mut out);
        out
    }
}

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Every invertible two-by-two matrix.
#[must_use]
pub fn matrices() -> Vec<Matrix> {
    let n = ALPHABET as u8;
    let mut out = Vec::with_capacity(157_248);
    for a in 0..n {
        for b in 0..n {
            for c in 0..n {
                for d in 0..n {
                    let m = Matrix(a, b, c, d);
                    if m.invertible() {
                        out.push(m);
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;

    #[test]
    fn the_count_is_the_known_one() {
        assert_eq!(matrices().len(), 157_248);
    }

    #[test]
    fn a_singular_matrix_is_rejected() {
        assert!(!Matrix(2, 4, 6, 8).invertible());
    }

    #[test]
    fn the_determinant_is_taken_modulo_26() {
        assert_eq!(Matrix(3, 3, 2, 5).determinant(), 9);
    }

    #[test]
    fn a_matrix_and_its_inverse_undo_each_other() {
        let msg = to_letters("ITISACAPITALMISTAKETOTHEORIZE");
        let m = Matrix(3, 3, 2, 5);
        let inverse = Matrix(15, 17, 20, 9);
        assert_eq!(inverse.apply(&m.apply(&msg)), msg);
    }

    #[test]
    fn a_trailing_odd_letter_is_left_alone() {
        assert_eq!(Matrix(3, 3, 2, 5).apply(&to_letters("ABC")).len(), 3);
    }
}
