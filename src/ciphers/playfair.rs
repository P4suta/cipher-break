// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::Letter;
use crate::square::{Square, at, positions};

fn step(
    direction: i32,
    sq: &Square,
    pos: &[(u8, u8); 26],
    a: Letter,
    b: Letter,
) -> (Letter, Letter) {
    let (r1, c1) = pos[a as usize];
    let (r2, c2) = pos[b as usize];
    let shift = |x: u8| ((i32::from(x) + direction).rem_euclid(5)) as usize;
    if r1 == r2 {
        (
            at(sq, r1 as usize, shift(c1)),
            at(sq, r2 as usize, shift(c2)),
        )
    } else if c1 == c2 {
        (
            at(sq, shift(r1), c1 as usize),
            at(sq, shift(r2), c2 as usize),
        )
    } else {
        (
            at(sq, r1 as usize, c2 as usize),
            at(sq, r2 as usize, c1 as usize),
        )
    }
}

fn transform(direction: i32, sq: &Square, ls: &[Letter]) -> Vec<Letter> {
    let pos = positions(sq);
    let mut out = Vec::with_capacity(ls.len());
    let mut i = 0;
    while i + 1 < ls.len() {
        let (x, y) = step(direction, sq, &pos, ls[i], ls[i + 1]);
        out.push(x);
        out.push(y);
        i += 2;
    }
    if i < ls.len() {
        out.push(ls[i]);
    }
    out
}

#[must_use]
pub fn encipher(sq: &Square, pt: &[Letter]) -> Vec<Letter> {
    transform(1, sq, pt)
}

#[must_use]
pub fn decipher(sq: &Square, ct: &[Letter]) -> Vec<Letter> {
    transform(-1, sq, ct)
}

pub fn decipher_into(sq: &Square, ct: &[Letter], out: &mut [Letter]) {
    let pos = positions(sq);
    let mut i = 0;
    while i + 1 < ct.len() {
        let (x, y) = step(-1, sq, &pos, ct[i], ct[i + 1]);
        out[i] = x;
        out[i + 1] = y;
        i += 2;
    }
    if i < ct.len() {
        out[i] = ct[i];
    }
}

#[must_use]
pub fn possible(ct: &[Letter]) -> bool {
    ct.chunks(2).all(|p| p.len() < 2 || p[0] != p[1])
}

#[must_use]
pub fn encipher_four(
    top_right: &Square,
    bottom_left: &Square,
    plain: &Square,
    pt: &[Letter],
) -> Vec<Letter> {
    let pos = positions(plain);
    let mut out = Vec::with_capacity(pt.len());
    for pair in pt.chunks(2) {
        if pair.len() < 2 {
            out.push(pair[0]);
            break;
        }
        let (r1, c1) = pos[pair[0] as usize];
        let (r2, c2) = pos[pair[1] as usize];
        out.push(at(top_right, r1 as usize, c2 as usize));
        out.push(at(bottom_left, r2 as usize, c1 as usize));
    }
    out
}

pub fn decipher_four_into(
    top_right: &Square,
    bottom_left: &Square,
    plain: &Square,
    ct: &[Letter],
    out: &mut [Letter],
) {
    let tr = positions(top_right);
    let bl = positions(bottom_left);
    let mut i = 0;
    while i + 1 < ct.len() {
        let (r1, c2) = tr[ct[i] as usize];
        let (r2, c1) = bl[ct[i + 1] as usize];
        out[i] = at(plain, r1 as usize, c1 as usize);
        out[i + 1] = at(plain, r2 as usize, c2 as usize);
        i += 2;
    }
    if i < ct.len() {
        out[i] = ct[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;
    use crate::rng::Rng;
    use crate::square::{omitting, random};

    fn prepared(missing: u8) -> Vec<Letter> {
        let raw: Vec<u8> = to_letters("ITISACAPITALMISTAKETOTHEORIZEBEFOREONEHAS")
            .into_iter()
            .filter(|&l| l != missing)
            .collect();
        let mut out: Vec<u8> = Vec::new();
        for l in raw {
            if out.len() % 2 == 1 && *out.last().expect("non-empty") == l {
                out.push(if l == 23 { 0 } else { 23 });
            }
            out.push(l);
        }
        if out.len() % 2 == 1 {
            out.pop();
        }
        out
    }

    #[test]
    fn deciphering_inverts_enciphering() {
        let sq = random(8, &mut Rng::new(5));
        let msg = prepared(8);
        assert_eq!(decipher(&sq, &encipher(&sq, &msg)), msg);
    }

    #[test]
    fn it_never_emits_a_doubled_digraph() {
        let sq = random(8, &mut Rng::new(6));
        assert!(possible(&encipher(&sq, &prepared(8))));
    }

    #[test]
    fn a_doubled_digraph_rules_playfair_out() {
        assert!(!possible(&to_letters("ABPPCD")));
        assert!(possible(&to_letters("APPBCD")));
    }

    #[test]
    fn the_three_rules_are_three_different_rules() {
        let sq = omitting(9);
        assert_eq!(encipher(&sq, &to_letters("AB")), to_letters("BC"));
        assert_eq!(encipher(&sq, &to_letters("DE")), to_letters("EA"));
        assert_eq!(encipher(&sq, &to_letters("AF")), to_letters("FL"));
        assert_eq!(encipher(&sq, &to_letters("AG")), to_letters("BF"));
    }

    #[test]
    fn deciphering_reverses_each_rule() {
        let sq = omitting(9);
        for pair in ["AB", "DE", "AF", "AG"] {
            let ls = to_letters(pair);
            assert_eq!(decipher(&sq, &encipher(&sq, &ls)), ls, "{pair}");
        }
    }

    #[test]
    fn an_odd_trailing_letter_passes_through() {
        let sq = omitting(9);
        let ls = to_letters("ABC");
        let out = encipher(&sq, &ls);
        assert_eq!(out.len(), 3);
        assert_eq!(out[2], ls[2]);
    }

    #[test]
    fn a_text_of_one_letter_is_left_alone() {
        let sq = omitting(9);
        assert_eq!(encipher(&sq, &to_letters("A")), to_letters("A"));
        assert!(encipher(&sq, &[]).is_empty());
    }

    #[test]
    fn possible_looks_at_pairs_and_not_at_neighbours() {
        assert!(possible(&[]));
        assert!(possible(&to_letters("A")));
        assert!(!possible(&to_letters("AA")));
        assert!(
            possible(&to_letters("ABB")),
            "the odd letter is not in a pair"
        );
    }

    #[test]
    fn four_square_leaves_an_odd_letter_alone() {
        let tr = random(8, &mut Rng::new(11));
        let bl = random(8, &mut Rng::new(12));
        let plain = omitting(8);
        let out = encipher_four(&tr, &bl, &plain, &to_letters("ABC"));
        assert_eq!(out.len(), 3);
        assert_eq!(out[2], to_letters("C")[0]);
    }

    #[test]
    fn four_square_round_trips() {
        let tr = random(8, &mut Rng::new(11));
        let bl = random(8, &mut Rng::new(12));
        let plain = omitting(8);
        let msg = prepared(8);
        let ct = encipher_four(&tr, &bl, &plain, &msg);
        let mut back = vec![0u8; ct.len()];
        decipher_four_into(&tr, &bl, &plain, &ct, &mut back);
        assert_eq!(back, msg);
    }
}
