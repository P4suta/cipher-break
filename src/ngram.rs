// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::{ALPHABET, Letter, from_letters, to_letters};

const UNSEEN_WEIGHT: f64 = 0.01;
use std::fmt::Write as _;

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
    #[must_use]
    pub fn from_counts(order: usize, counts: Vec<u32>) -> Self {
        let total = counts.iter().map(|&c| f64::from(c)).sum::<f64>().max(1.0);
        let unseen = (UNSEEN_WEIGHT / total).ln() as f32;
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

    #[must_use]
    pub fn train(order: usize, corpus: &[Letter]) -> Self {
        let mut counts = vec![0u32; slots(order)];
        for g in Grams::new(order, corpus) {
            counts[g] += 1;
        }
        Self::from_counts(order, counts)
    }

    #[must_use]
    pub fn order(&self) -> usize {
        self.order
    }

    #[must_use]
    pub fn total(&self) -> f64 {
        self.total
    }

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

    #[inline]
    #[must_use]
    pub fn logp_at(&self, gram: usize) -> f32 {
        self.logp[gram]
    }

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

    #[must_use]
    pub fn log_table(&self) -> &[f32] {
        &self.logp
    }

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

#[must_use]
pub fn spell(order: usize, mut i: usize) -> Vec<Letter> {
    let mut out = vec![0u8; order];
    for slot in out.iter_mut().rev() {
        *slot = (i % ALPHABET) as u8;
        i /= ALPHABET;
    }
    out
}

pub struct Grams<'a> {
    order: usize,
    modulus: usize,
    acc: usize,
    seen: usize,
    rest: &'a [Letter],
}

impl<'a> Grams<'a> {
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
        if self.order == 0 {
            return None;
        }
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
    fn an_order_of_zero_has_no_grams() {
        assert_eq!(Grams::new(0, &to_letters("ABCDEF")).count(), 0);
    }

    #[test]
    fn a_model_scores_nothing_on_a_text_too_short_for_it() {
        let m = Model::train(3, &to_letters(CORPUS));
        assert_eq!(m.score(&to_letters("AB")), 0.0);
    }

    #[test]
    fn an_unseen_gram_gets_the_floor_and_not_infinity() {
        let m = Model::train(3, &to_letters("AAAAAA"));
        let score = m.score(&to_letters("QXZ"));
        assert!(score.is_finite(), "an unseen gram was fatal");
        assert!(score < m.score(&to_letters("AAA")));
    }

    #[test]
    fn a_models_total_is_the_grams_it_counted() {
        let corpus = to_letters(CORPUS);
        let m = Model::train(3, &corpus);
        assert!((m.total() - (corpus.len() - 2) as f64).abs() < 1e-9);
    }

    #[test]
    fn the_log_table_has_a_slot_for_every_gram() {
        let m = Model::train(3, &to_letters(CORPUS));
        assert_eq!(m.log_table().len(), 26usize.pow(3));
    }

    #[test]
    fn a_header_without_an_order_is_refused() {
        assert!(Model::parse("").is_none());
        assert!(Model::parse("orderly 3\n").is_none());
        assert!(Model::parse("order x\n").is_none());
    }

    #[test]
    fn a_line_whose_gram_is_the_wrong_length_is_skipped() {
        let m = Model::parse("order 3\nABCD 5\nABC 7\n").expect("parses");
        assert!((m.total() - 7.0).abs() < 1e-9);
    }

    #[test]
    fn rendering_honours_its_cutoff() {
        let m = Model::train(3, &to_letters(CORPUS));
        let all = m.render(1).lines().count();
        let some = m.render(2).lines().count();
        assert!(some < all, "a higher cutoff kept as much");
        assert_eq!(
            m.render(u32::MAX).lines().count(),
            1,
            "only the header should remain"
        );
    }

    #[test]
    fn grams_counts_windows() {
        assert_eq!(Grams::new(3, &to_letters("ABCDE")).count(), 3);
        assert_eq!(Grams::new(3, &to_letters("AB")).count(), 0);
    }
}
