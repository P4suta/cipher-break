// SPDX-License-Identifier: MIT OR Apache-2.0

//! The plain substitution cipher, and the affine and shift ciphers inside it.
//!
//! This is the cipher most puzzles turn out to be, and the one a general tool has least excuse for missing.
//! Its key space is 26 factorial, far past enumeration, but its landscape is the friendliest in classical cryptography: swapping two letters of a wrong key changes two letters of the plaintext and nothing else, so a search always knows which way is uphill.
//!
//! It is also the class a single statistic disposes of.
//! A substitution preserves letter counts exactly, so it preserves the index of coincidence;
//! a ciphertext whose index of coincidence is not that of some language did not come from one of these.

use crate::alphabet::{ALPHABET, Letter};
use crate::rng::Rng;

/// Where each of the 26 letters goes.
pub type Key = [Letter; ALPHABET];

/// The key that changes nothing.
#[must_use]
pub fn identity() -> Key {
    std::array::from_fn(|i| i as u8)
}

/// Apply a key into an existing buffer.
pub fn apply_into(key: &Key, ls: &[Letter], out: &mut [Letter]) {
    for (&l, slot) in ls.iter().zip(out.iter_mut()) {
        *slot = key[l as usize % ALPHABET];
    }
}

/// Apply a key.
#[must_use]
pub fn apply(key: &Key, ls: &[Letter]) -> Vec<Letter> {
    ls.iter().map(|&l| key[l as usize % ALPHABET]).collect()
}

/// The key that undoes another.
#[must_use]
pub fn invert(key: &Key) -> Key {
    let mut out = [0u8; ALPHABET];
    for (i, &k) in key.iter().enumerate() {
        out[k as usize % ALPHABET] = i as u8;
    }
    out
}

/// A Caesar shift.
#[must_use]
pub fn shift(n: u8) -> Key {
    std::array::from_fn(|i| ((i as u8) + n) % ALPHABET as u8)
}

/// `l -> a*l + b`, meaningful only when `a` is coprime with 26.
#[must_use]
pub fn affine(a: u8, b: u8) -> Key {
    std::array::from_fn(|i| ((a as usize * i + b as usize) % ALPHABET) as u8)
}

/// Every affine key: twelve multipliers, 26 offsets.
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

/// The alphabet reversed.
#[must_use]
pub fn atbash() -> Key {
    std::array::from_fn(|i| (ALPHABET - 1 - i) as u8)
}

/// A key drawn at random.
#[must_use]
pub fn random(rng: &mut Rng) -> Key {
    let mut v: Vec<u8> = (0..ALPHABET as u8).collect();
    rng.shuffle(&mut v);
    std::array::from_fn(|i| v[i])
}

/// Exchange two letters, the move a substitution search is built from.
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
