// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::{ALPHABET, Letter};
use crate::rng::Rng;

pub type Key = [Letter; ALPHABET];

#[must_use]
pub fn identity() -> Key {
    std::array::from_fn(|i| i as u8)
}

pub fn apply_into(key: &Key, ls: &[Letter], out: &mut [Letter]) {
    for (&l, slot) in ls.iter().zip(out.iter_mut()) {
        *slot = key[l as usize % ALPHABET];
    }
}

#[must_use]
pub fn apply(key: &Key, ls: &[Letter]) -> Vec<Letter> {
    ls.iter().map(|&l| key[l as usize % ALPHABET]).collect()
}

#[must_use]
pub fn invert(key: &Key) -> Key {
    let mut out = [0u8; ALPHABET];
    for (i, &k) in key.iter().enumerate() {
        out[k as usize % ALPHABET] = i as u8;
    }
    out
}

#[must_use]
pub fn shift(n: u8) -> Key {
    std::array::from_fn(|i| ((i as u8) + n) % ALPHABET as u8)
}

#[must_use]
pub fn affine(a: u8, b: u8) -> Key {
    std::array::from_fn(|i| ((a as usize * i + b as usize) % ALPHABET) as u8)
}

#[must_use]
pub fn affine_keys() -> Vec<(String, Key)> {
    let mut out = Vec::new();
    for a in 1..ALPHABET as u8 {
        if gcd(u32::from(a), ALPHABET as u32) != 1 {
            continue;
        }
        for b in 0..ALPHABET as u8 {
            out.push((format!("a={a} b={b}"), affine(a, b)));
        }
    }
    out
}

#[must_use]
pub fn atbash() -> Key {
    std::array::from_fn(|i| (ALPHABET - 1 - i) as u8)
}

#[must_use]
pub fn random(rng: &mut Rng) -> Key {
    let mut v: Vec<u8> = (0..ALPHABET as u8).collect();
    rng.shuffle(&mut v);
    std::array::from_fn(|i| v[i])
}

pub fn perturb(key: &mut Key, rng: &mut Rng) {
    let i = rng.below(ALPHABET);
    let j = rng.below(ALPHABET);
    key.swap(i, j);
}

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 { a } else { gcd(b, a % b) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::{from_letters, to_letters};

    #[test]
    fn a_key_and_its_inverse_undo_each_other() {
        let key = random(&mut Rng::new(4));
        let msg = to_letters("ITISACAPITALMISTAKE");
        assert_eq!(apply(&invert(&key), &apply(&key, &msg)), msg);
    }

    #[test]
    fn rot13_is_its_own_inverse() {
        let msg = to_letters("HELLO");
        assert_eq!(apply(&shift(13), &apply(&shift(13), &msg)), msg);
    }

    #[test]
    fn atbash_reverses_the_alphabet() {
        assert_eq!(from_letters(&apply(&atbash(), &to_letters("ABZ"))), "ZYA");
    }

    #[test]
    fn every_affine_key_is_a_permutation() {
        for (name, key) in affine_keys() {
            let mut sorted = key;
            sorted.sort_unstable();
            assert_eq!(sorted, identity(), "{name} was not a permutation");
        }
    }

    #[test]
    fn the_affine_keys_include_the_shifts_and_atbash() {
        let keys: Vec<Key> = affine_keys().into_iter().map(|(_, k)| k).collect();
        assert!(keys.contains(&shift(7)), "a=1 b=7 is a shift");
        assert!(keys.contains(&atbash()), "a=25 b=25 is Atbash");
        assert!(keys.contains(&identity()));
    }

    #[test]
    fn a_random_key_is_a_permutation() {
        let mut sorted = random(&mut Rng::new(31));
        sorted.sort_unstable();
        assert_eq!(sorted, identity());
    }

    #[test]
    fn there_are_312_affine_keys() {
        assert_eq!(affine_keys().len(), 312);
    }

    #[test]
    fn identity_changes_nothing() {
        let msg = to_letters("ABCDEF");
        assert_eq!(apply(&identity(), &msg), msg);
    }

    #[test]
    fn a_perturbed_key_is_still_a_permutation() {
        let mut key = identity();
        perturb(&mut key, &mut Rng::new(2));
        let mut sorted = key;
        sorted.sort_unstable();
        assert_eq!(sorted, identity());
    }
}
