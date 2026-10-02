// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::{ALPHABET, Letter};

pub const TABLES: usize = ALPHABET / 2;

#[inline]
#[must_use]
pub fn substitute(table: usize, l: Letter) -> Letter {
    let half = TABLES as u8;
    let n = (table % TABLES) as u8;
    if l < half {
        (l + n) % half + half
    } else {
        (l + half - n) % half
    }
}

#[must_use]
pub fn apply(tables: &[usize], ls: &[Letter]) -> Vec<Letter> {
    if tables.is_empty() {
        return ls.to_vec();
    }
    ls.iter()
        .enumerate()
        .map(|(i, &l)| substitute(tables[i % tables.len()], l))
        .collect()
}

pub fn apply_into(tables: &[usize], ls: &[Letter], out: &mut [Letter]) {
    if tables.is_empty() {
        out.copy_from_slice(ls);
        return;
    }
    let n = tables.len();
    for (i, (&l, slot)) in ls.iter().zip(out.iter_mut()).enumerate() {
        *slot = substitute(tables[i % n], l);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;

    #[test]
    fn every_table_is_its_own_inverse() {
        for t in 0..TABLES {
            for l in 0..ALPHABET as u8 {
                assert_eq!(substitute(t, substitute(t, l)), l, "table {t}, letter {l}");
            }
        }
    }

    #[test]
    fn it_maps_across_the_halves() {
        assert_eq!(substitute(0, 0), 13);
        assert_eq!(substitute(0, 13), 0);
    }

    #[test]
    fn applying_twice_returns_the_text() {
        let msg = to_letters("ITISACAPITALMISTAKETOTHEORIZE");
        assert_eq!(apply(&[3, 7, 1], &apply(&[3, 7, 1], &msg)), msg);
    }

    #[test]
    fn an_empty_key_changes_nothing() {
        let msg = to_letters("ABCDEF");
        assert_eq!(apply(&[], &msg), msg);
    }
}
