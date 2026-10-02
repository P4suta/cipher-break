// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::{ALPHABET, Letter};
use crate::rng::Rng;

pub const SIDE: usize = 5;

pub type Square = Vec<Letter>;

#[must_use]
pub fn omitting(missing: Letter) -> Square {
    (0..ALPHABET as u8).filter(|&l| l != missing).collect()
}

#[must_use]
pub fn omissions_for(ct: &[Letter]) -> Vec<Letter> {
    (0..ALPHABET as u8).filter(|l| !ct.contains(l)).collect()
}

#[must_use]
pub fn random(missing: Letter, rng: &mut Rng) -> Square {
    let mut sq = omitting(missing);
    rng.shuffle(&mut sq);
    sq
}

pub fn perturb(sq: &mut Square, rng: &mut Rng) {
    let n = sq.len();
    let i = rng.below(n);
    let j = rng.below(n);
    sq.swap(i, j);
}

#[must_use]
pub fn positions(sq: &[Letter]) -> [(u8, u8); ALPHABET] {
    let mut out = [(0u8, 0u8); ALPHABET];
    for (i, &l) in sq.iter().enumerate() {
        out[l as usize] = ((i / SIDE) as u8, (i % SIDE) as u8);
    }
    out
}

#[inline]
#[must_use]
pub fn at(sq: &[Letter], row: usize, col: usize) -> Letter {
    sq[(row % SIDE) * SIDE + (col % SIDE)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;

    #[test]
    fn a_square_omits_exactly_one_letter() {
        let sq = omitting(8);
        assert_eq!(sq.len(), 25);
        assert!(!sq.contains(&8));
    }

    #[test]
    fn omissions_follow_the_letters_the_text_lacks() {
        assert_eq!(
            omissions_for(&to_letters("ABCDEFGHIJKLMNOPQRSTUVWXY")),
            vec![25]
        );
    }

    #[test]
    fn perturbing_keeps_it_a_square() {
        let mut sq = omitting(8);
        perturb(&mut sq, &mut Rng::new(3));
        let mut sorted = sq.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, omitting(8));
    }

    #[test]
    fn a_random_square_is_still_a_square() {
        let mut sorted = random(8, &mut Rng::new(3));
        sorted.sort_unstable();
        assert_eq!(sorted, omitting(8));
    }
}
