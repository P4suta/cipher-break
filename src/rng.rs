// SPDX-License-Identifier: MIT OR Apache-2.0

//! A small deterministic generator.
//!
//! Searches restart from arbitrary places and nulls are built from shuffles,
//! so randomness is needed everywhere.
//! It is carried here rather than taken from the system, so that a run which breaks a cipher can be replayed exactly — and so that a null computed today is the null computed tomorrow.

/// An xorshift64 generator.
#[derive(Clone, Copy, Debug)]
pub struct Rng(u64);

impl Rng {
    /// A generator from any number; zero would be a fixed point, so it is replaced.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Rng(if seed == 0 {
            0x2545_F491_4F6C_DD1D
        } else {
            seed
        })
    }

    /// One step.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A number below `n`.
    #[inline]
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// A draw from the unit interval.
    #[inline]
    pub fn unit(&mut self) -> f64 {
        self.next_u64() as f64 / u64::MAX as f64
    }

    /// Shuffle in place, by Fisher and Yates.
    pub fn shuffle<T>(&mut self, xs: &mut [T]) {
        for i in (1..xs.len()).rev() {
            let j = self.below(i + 1);
            xs.swap(i, j);
        }
    }

    /// A fresh shuffle of a slice.
    #[must_use]
    pub fn shuffled<T: Clone>(&mut self, xs: &[T]) -> Vec<T> {
        let mut out = xs.to_vec();
        self.shuffle(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_replays() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        assert_eq!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn different_seeds_diverge() {
        assert_ne!(Rng::new(1).next_u64(), Rng::new(2).next_u64());
    }

    #[test]
    fn a_shuffle_keeps_every_element() {
        let xs: Vec<u8> = (0..50).collect();
        let mut shuffled = Rng::new(7).shuffled(&xs);
        shuffled.sort_unstable();
        assert_eq!(shuffled, xs);
    }

    #[test]
    fn zero_is_not_a_fixed_point() {
        assert_ne!(Rng::new(0).next_u64(), 0);
    }
}
