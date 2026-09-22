// SPDX-License-Identifier: MIT OR Apache-2.0

//! An n-gram model of a language, and the fitness function built from it.
//!
//! Single-letter frequency is a poor judge of a short candidate: it cannot tell `THEREFORE` from an anagram of it.
//! An n-gram model judges the order of the letters too, which is what lets a search climb towards a plaintext instead of merely recognising one it has already found.
//!
//! The on-disk format is shared with the Haskell reference implementation under `reference/`, so a model trained by either can be read by both.

use crate::alphabet::{ALPHABET, Letter, from_letters, to_letters};
use std::fmt::Write as _;

/// Log probabilities for every gram of a fixed order.
#[derive(Clone, Debug)]
pub struct Model {
    order: usize,
    total: f64,
    counts: Vec<u32>,
    logp: Vec<f32>,
}

fn slots(order: usize) -> usize {
    ALPHABET.pow(order as u32)
}

impl Model {
    /// Build a model from raw gram counts.
    ///
    /// A gram the corpus never showed is not impossible, only unseen, so it gets a floor rather than negative infinity; without one a single unlucky gram would veto an otherwise perfect plaintext.
    #[must_use]
    pub fn from_counts(order: usize, counts: Vec<u32>) -> Self {
        let total = counts.iter().map(|&c| f64::from(c)).sum::<f64>().max(1.0);
        let unseen = (0.01 / total).ln() as f32;
        let logp = counts
            .iter()
            .map(|&c| {
                if c == 0 {
                    unseen
                } else {
                    (f64::from(c) / total).ln() as f32
                }
            })
            .collect();
        Model {
            order,
            total,
            counts,
            logp,
        }
    }

    /// Count every gram of a corpus.
    #[must_use]
    pub fn train(order: usize, corpus: &[Letter]) -> Self {
        let mut counts = vec![0u32; slots(order)];
        for g in Grams::new(order, corpus) {
            counts[g] += 1;
        }
        Self::from_counts(order, counts)
    }

    /// The order of the model.
    #[must_use]
    pub fn order(&self) -> usize {
        self.order
    }

    /// How many grams the corpus held.
    #[must_use]
    pub fn total(&self) -> f64 {
        self.total
    }

    /// Mean log probability per gram, so texts of different lengths compare.
    #[must_use]
    pub fn score(&self, ls: &[Letter]) -> f64 {
        let mut sum = 0.0f64;
        let mut n = 0usize;
        for g in Grams::new(self.order, ls) {
            sum += f64::from(self.logp[g]);
            n += 1;
        }
        if n == 0 { 0.0 } else { sum / n as f64 }
    }

    /// The log probability of one gram index, for callers that batch the index arithmetic themselves.
    #[inline]
    #[must_use]
    pub fn logp_at(&self, gram: usize) -> f32 {
        self.logp[gram]
    }

    /// Generate text from the model.
    ///
    /// This is what lets the tool calibrate itself.
    /// Deciding whether a candidate "looks like a language" needs to know what a real text of that length scores, and asking for a corpus at solve time is a burden no user should carry.
    /// The models already hold the answer: text drawn from a language's own model scores like text from that language.
    #[must_use]
    pub fn sample(&self, len: usize, rng: &mut crate::rng::Rng) -> Vec<Letter> {
        let context_slots = ALPHABET.pow((self.order - 1) as u32);
        let mut out = Vec::with_capacity(len);
        let mut context = 0usize;
        for i in 0..len {
            let next = if i + 1 < self.order {
                rng.below(ALPHABET)
            } else {
                let base = (context % context_slots) * ALPHABET;
                let weights = &self.counts[base..base + ALPHABET];
                let total: u64 = weights.iter().map(|&c| u64::from(c)).sum();
                if total == 0 {
                    rng.below(ALPHABET)
                } else {
                    let mut pick = rng.next_u64() % total;
                    let mut chosen = ALPHABET - 1;
                    for (c, &w) in weights.iter().enumerate() {
                        if pick < u64::from(w) {
                            chosen = c;
                            break;
                        }
                        pick -= u64::from(w);
                    }
                    chosen
                }
            };
            out.push(next as u8);
            context = (context * ALPHABET + next) % context_slots.max(1);
        }
        out
    }

    /// The whole log-probability table, for a device that wants its own copy.
    #[must_use]
    pub fn log_table(&self) -> &[f32] {
        &self.logp
    }

    /// The model as text: a header, then one line per gram above the cutoff.
    #[must_use]
    pub fn render(&self, cutoff: u32) -> String {
        let mut out = format!("order {}\n", self.order);
        for (i, &c) in self.counts.iter().enumerate() {
            if c >= cutoff {
                let _ = writeln!(out, "{} {}", from_letters(&spell(self.order, i)), c);
            }
        }
        out
    }

    /// Read a model back.
    #[must_use]
    pub fn parse(text: &str) -> Option<Model> {
        let mut lines = text.lines();
        let header = lines.next()?;
        let order: usize = header.strip_prefix("order ")?.trim().parse().ok()?;
        let mut counts = vec![0u32; slots(order)];
        for line in lines {
            let mut parts = line.split_whitespace();
            let (Some(gram), Some(count)) = (parts.next(), parts.next()) else {
                continue;
            };
            if gram.len() != order {
                continue;
            }
            let ls = to_letters(gram);
            if ls.len() != order {
                continue;
            }
            let idx = ls
                .iter()
                .fold(0usize, |acc, &l| acc * ALPHABET + l as usize);
            counts[idx] += count.parse::<u32>().unwrap_or(0);
        }
        Some(Model::from_counts(order, counts))
    }
}

/// The letters a gram index stands for.
#[must_use]
pub fn spell(order: usize, mut i: usize) -> Vec<Letter> {
    let mut out = vec![0u8; order];
    for slot in out.iter_mut().rev() {
        *slot = (i % ALPHABET) as u8;
        i /= ALPHABET;
    }
    out
}

/// The gram indices of a text, as base-26 numbers.
///
/// The index is carried forward one letter at a time rather than rebuilt from each window, which is what keeps training over millions of letters linear.
pub struct Grams<'a> {
    order: usize,
    modulus: usize,
    acc: usize,
    seen: usize,
    rest: &'a [Letter],
}

impl<'a> Grams<'a> {
    /// Iterate the grams of a text.
    #[must_use]
    pub fn new(order: usize, ls: &'a [Letter]) -> Self {
        Grams {
            order,
            modulus: slots(order),
            acc: 0,
            seen: 0,
            rest: ls,
        }
    }
}

impl Iterator for Grams<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        while let Some((&l, tail)) = self.rest.split_first() {
            self.rest = tail;
            self.acc = (self.acc * ALPHABET + l as usize) % self.modulus;
            self.seen += 1;
            if self.seen >= self.order {
                return Some(self.acc);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORPUS: &str = "ITISACAPITALMISTAKETOTHEORIZEBEFOREONEHASDATAINSENSIBLYONEBEGINS\
                          TOTWISTFACTSTOSUITTHEORIESINSTEADOFTHEORIESTOSUITFACTS";

    #[test]
    fn a_model_prefers_the_text_it_learned() {
        let m = Model::train(3, &to_letters(CORPUS));
        assert!(m.score(&to_letters(CORPUS)) > m.score(&to_letters("ZQXJZQXJZQXJ")));
    }

    #[test]
    fn rendering_round_trips() {
        let m = Model::train(3, &to_letters(CORPUS));
        let back = Model::parse(&m.render(1)).expect("parses");
        assert_eq!(back.order(), 3);
        assert!((back.score(&to_letters(CORPUS)) - m.score(&to_letters(CORPUS))).abs() < 1e-9);
    }

    #[test]
    fn spelling_inverts_the_index() {
        for i in [0usize, 1, 25, 26, 675, 17_575] {
            let ls = spell(3, i);
            let back = ls
                .iter()
                .fold(0usize, |acc, &l| acc * ALPHABET + l as usize);
            assert_eq!(back, i);
        }
    }

    #[test]
    fn sampled_text_scores_like_the_language_it_came_from() {
        use crate::rng::Rng;
        let m = Model::train(3, &to_letters(CORPUS));
        let mut rng = Rng::new(3);
        let drawn = m.sample(200, &mut rng);
        let noise: Vec<u8> = (0..200).map(|_| rng.below(26) as u8).collect();
        assert_eq!(drawn.len(), 200);
        assert!(m.score(&drawn) > m.score(&noise));
    }

    #[test]
    fn grams_counts_windows() {
        assert_eq!(Grams::new(3, &to_letters("ABCDE")).count(), 3);
        assert_eq!(Grams::new(3, &to_letters("AB")).count(), 0);
    }
}
