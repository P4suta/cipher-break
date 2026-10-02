// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::Letter;
use crate::square::{Square, at, positions};

#[must_use]
pub fn encipher(period: usize, sq: &Square, pt: &[Letter]) -> Vec<Letter> {
    if period == 0 {
        return pt.to_vec();
    }
    let pos = positions(sq);
    let mut out = Vec::with_capacity(pt.len());
    for block in pt.chunks(period) {
        let mut flat = Vec::with_capacity(block.len() * 2);
        flat.extend(block.iter().map(|&l| pos[l as usize].0));
        flat.extend(block.iter().map(|&l| pos[l as usize].1));
        for pair in flat.chunks(2) {
            if pair.len() == 2 {
                out.push(at(sq, pair[0] as usize, pair[1] as usize));
            }
        }
    }
    out
}

pub fn decipher_into(period: usize, sq: &Square, ct: &[Letter], out: &mut [Letter]) {
    if period == 0 {
        out.copy_from_slice(ct);
        return;
    }
    let pos = positions(sq);
    let mut flat = Vec::with_capacity(period * 2);
    let mut written = 0usize;
    for block in ct.chunks(period) {
        flat.clear();
        for &l in block {
            let (r, c) = pos[l as usize];
            flat.push(r);
            flat.push(c);
        }
        let half = flat.len() / 2;
        for i in 0..half {
            out[written + i] = at(sq, flat[i] as usize, flat[half + i] as usize);
        }
        written += half;
    }
    debug_assert_eq!(written, ct.len());
}

#[must_use]
pub fn decipher(period: usize, sq: &Square, ct: &[Letter]) -> Vec<Letter> {
    let mut out = vec![0u8; ct.len()];
    decipher_into(period, sq, ct, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;
    use crate::rng::Rng;
    use crate::square::{omitting, random};

    const PLAIN: &str = "ITISACAPITALMISTAKETOTHEORIZEBEFOREONEHASDATAINSENSIBLYONEBEGINS";

    #[test]
    fn deciphering_inverts_enciphering() {
        for missing in [8u8, 9, 12] {
            let sq = omitting(missing);
            let msg: Vec<u8> = to_letters(PLAIN)
                .into_iter()
                .filter(|&l| l != missing)
                .collect();
            for period in [1usize, 2, 5, 7, 12] {
                assert_eq!(decipher(period, &sq, &encipher(period, &sq, &msg)), msg);
            }
        }
    }

    #[test]
    fn it_works_with_a_keyed_square_too() {
        let sq = random(8, &mut Rng::new(99));
        let msg: Vec<u8> = to_letters(PLAIN).into_iter().filter(|&l| l != 8).collect();
        assert_eq!(decipher(7, &sq, &encipher(7, &sq, &msg)), msg);
    }

    #[test]
    fn a_period_of_zero_changes_nothing() {
        let sq = omitting(8);
        let msg: Vec<u8> = to_letters(PLAIN).into_iter().filter(|&l| l != 8).collect();
        assert_eq!(encipher(0, &sq, &msg), msg);
        assert_eq!(decipher(0, &sq, &msg), msg);
    }

    #[test]
    fn a_period_of_one_is_a_substitution() {
        use crate::stats::index_of_coincidence;
        let sq = omitting(8);
        let msg: Vec<u8> = to_letters(PLAIN).into_iter().filter(|&l| l != 8).collect();
        let ct = encipher(1, &sq, &msg);
        assert!((index_of_coincidence(&ct) - index_of_coincidence(&msg)).abs() < 1e-12);
    }

    #[test]
    fn a_ragged_last_block_still_returns() {
        let sq = omitting(8);
        let msg: Vec<u8> = to_letters("ABCDEFG")
            .into_iter()
            .filter(|&l| l != 8)
            .collect();
        assert_eq!(decipher(5, &sq, &encipher(5, &sq, &msg)), msg);
    }

    #[test]
    fn it_flattens_the_index_of_coincidence() {
        use crate::stats::index_of_coincidence;
        let sq = omitting(8);
        let msg: Vec<u8> = to_letters(PLAIN).into_iter().filter(|&l| l != 8).collect();
        assert!(index_of_coincidence(&encipher(7, &sq, &msg)) < index_of_coincidence(&msg));
    }
}
