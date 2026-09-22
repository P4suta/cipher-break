// SPDX-License-Identifier: MIT OR Apache-2.0

//! What kind of thing is this, before any attempt to read it.
//!
//! Every attack assumes something: a period, a family, a language.
//! Before assuming any of them it is worth asking the question with no assumptions in it — does this text differ from letters drawn at random?
//! — and then the question that pins down half the catalogue: could it be a text in some language with its letters merely renamed or rearranged?
//!
//! The second question is the valuable one.
//! A substitution and a transposition both hand the plaintext's letter counts through untouched, so they hand the index of coincidence through untouched too.
//! A ciphertext flatter than any real language did not come from either, nor from any stack of the two, and that is most of classical cryptography ruled out by one number.

use crate::alphabet::{ALPHABET, Letter, letter_char};
use crate::polyglot::Polyglot;
use crate::rng::Rng;
use crate::stats::{index_of_coincidence, moments};
use std::collections::HashMap;

/// Which end of a null distribution counts as surprising.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tail {
    /// A high value is the surprising one.
    Upper,
    /// A low value is the surprising one.
    Lower,
}

/// What a statistic measures, as a function of a text.
pub type Measure = Box<dyn Fn(&[Letter]) -> f64 + Sync + Send>;

/// A number computed from a text, with the name to report it under.
pub struct Statistic {
    /// How it is named in reports.
    pub name: &'static str,
    /// Which tail is surprising.
    pub tail: Tail,
    /// What it measures.
    pub of: Measure,
}

/// Adjacent equal letters.
#[must_use]
pub fn doubles(ls: &[Letter]) -> f64 {
    ls.windows(2).filter(|w| w[0] == w[1]).count() as f64
}

/// Occurrences of an n-gram beyond its first, summed over all n-grams.
#[must_use]
pub fn repetition(n: usize, ls: &[Letter]) -> f64 {
    if ls.len() < n {
        return 0.0;
    }
    let mut seen: HashMap<&[Letter], usize> = HashMap::new();
    for w in ls.windows(n) {
        *seen.entry(w).or_insert(0) += 1;
    }
    (ls.len() - n + 1 - seen.len()) as f64
}

/// Index of coincidence over non-overlapping pairs, where a cipher that enciphers two letters at a time leaves its fingerprint.
#[must_use]
pub fn digraph_ic(ls: &[Letter]) -> f64 {
    let pairs: Vec<(Letter, Letter)> = ls
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| (c[0], c[1]))
        .collect();
    let n = pairs.len();
    if n < 2 {
        return 0.0;
    }
    let mut seen: HashMap<(Letter, Letter), u64> = HashMap::new();
    for p in pairs {
        *seen.entry(p).or_insert(0) += 1;
    }
    seen.values().map(|&c| c * c.saturating_sub(1)).sum::<u64>() as f64 / (n * (n - 1)) as f64
}

/// How many of the 26 letters appear at all.
#[must_use]
pub fn coverage(ls: &[Letter]) -> f64 {
    let mut seen = [false; ALPHABET];
    for &l in ls {
        seen[l as usize % ALPHABET] = true;
    }
    seen.iter().filter(|&&b| b).count() as f64
}

/// How many of the letters are vowels.
///
/// Worth a line of its own because a person inventing a random-looking string avoids vowels without meaning to: letters that would make the result read like a word get passed over.
/// A cipher has no such preference.
#[must_use]
pub fn vowels(ls: &[Letter]) -> f64 {
    ls.iter()
        .filter(|&&l| matches!(l, 0 | 4 | 8 | 14 | 20))
        .count() as f64
}

/// Adjacent letters that neighbour each other on a QWERTY keyboard.
///
/// The other half of the same suspicion: a mashed keyboard leaves its own geometry behind, and this is what that looks like when counted.
#[must_use]
pub fn qwerty_neighbours(ls: &[Letter]) -> f64 {
    const ROWS: [&str; 3] = ["QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"];
    let place = |l: Letter| -> Option<(i32, i32)> {
        let c = letter_char(l);
        ROWS.iter()
            .enumerate()
            .find_map(|(r, row)| row.find(c).map(|i| (r as i32, i as i32)))
    };
    ls.windows(2)
        .filter(|w| match (place(w[0]), place(w[1])) {
            (Some(a), Some(b)) => (a.0 - b.0).abs() <= 1 && (a.1 - b.1).abs() <= 1 && a != b,
            _ => false,
        })
        .count() as f64
}

/// The battery, in the order a report reads best.
#[must_use]
pub fn statistics(bank: Option<&Polyglot>) -> Vec<Statistic> {
    let mut out: Vec<Statistic> = vec![
        Statistic {
            name: "index of coincidence",
            tail: Tail::Upper,
            of: Box::new(index_of_coincidence),
        },
        Statistic {
            name: "adjacent doubles",
            tail: Tail::Upper,
            of: Box::new(doubles),
        },
        Statistic {
            name: "repeated bigrams",
            tail: Tail::Upper,
            of: Box::new(|l| repetition(2, l)),
        },
        Statistic {
            name: "repeated trigrams",
            tail: Tail::Upper,
            of: Box::new(|l| repetition(3, l)),
        },
        Statistic {
            name: "digraph IC",
            tail: Tail::Upper,
            of: Box::new(digraph_ic),
        },
        Statistic {
            name: "distinct letters",
            tail: Tail::Lower,
            of: Box::new(coverage),
        },
        Statistic {
            name: "vowels",
            tail: Tail::Lower,
            of: Box::new(vowels),
        },
        Statistic {
            name: "QWERTY neighbours",
            tail: Tail::Upper,
            of: Box::new(qwerty_neighbours),
        },
    ];
    if let Some(bank) = bank {
        let cloned = bank.clone();
        out.push(Statistic {
            name: "language fit",
            tail: Tail::Upper,
            of: Box::new(move |l| cloned.score(l)),
        });
    }
    out
}

/// An observed statistic beside the distribution it has to stand out from.
#[derive(Clone, Debug)]
pub struct Verdict {
    /// The statistic's name.
    pub name: &'static str,
    /// What the text scored.
    pub observed: f64,
    /// What the comparison population scores on average.
    pub mean: f64,
    /// The deviation of that population.
    pub sd: f64,
    /// How far out the observation is, in deviations.
    pub z: f64,
    /// The share of the population that matched or beat the observation.
    pub p: f64,
}

/// Compare one statistic against a population.
#[must_use]
pub fn assess(st: &Statistic, ls: &[Letter], population: &[Vec<Letter>]) -> Verdict {
    let observed = (st.of)(ls);
    let values: Vec<f64> = population.iter().map(|t| (st.of)(t)).collect();
    let (mean, sd) = moments(&values);
    let beaten = values
        .iter()
        .filter(|&&v| match st.tail {
            Tail::Upper => v >= observed,
            Tail::Lower => v <= observed,
        })
        .count();
    Verdict {
        name: st.name,
        observed,
        mean,
        sd,
        z: (observed - mean) / sd,
        p: beaten as f64 / values.len().max(1) as f64,
    }
}

/// A sample of uniform random texts of a given length.
#[must_use]
pub fn random_population(len: usize, count: usize, rng: &mut Rng) -> Vec<Vec<Letter>> {
    (0..count)
        .map(|_| (0..len).map(|_| rng.below(ALPHABET) as u8).collect())
        .collect()
}

/// Evenly spaced, non-overlapping windows of a corpus.
#[must_use]
pub fn windows(width: usize, count: usize, corpus: &[Letter]) -> Vec<Vec<Letter>> {
    if width == 0 || count == 0 || corpus.len() < width {
        return Vec::new();
    }
    let chunks: Vec<&[Letter]> = corpus.chunks_exact(width).collect();
    let stride = (chunks.len() / count).max(1);
    chunks
        .iter()
        .step_by(stride)
        .take(count)
        .map(|c| c.to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;

    #[test]
    fn doubles_counts_adjacent_pairs() {
        assert_eq!(doubles(&to_letters("AABBC")), 2.0);
        assert_eq!(doubles(&to_letters("ABABA")), 0.0);
    }

    #[test]
    fn repetition_counts_extra_occurrences() {
        assert_eq!(repetition(2, &to_letters("ABAB")), 1.0);
        assert_eq!(repetition(3, &to_letters("ABCDEF")), 0.0);
    }

    #[test]
    fn vowels_are_counted() {
        assert_eq!(vowels(&to_letters("AEIOUBCD")), 5.0);
    }

    #[test]
    fn qwerty_neighbours_sees_the_keyboard() {
        assert_eq!(qwerty_neighbours(&to_letters("QW")), 1.0);
        assert_eq!(qwerty_neighbours(&to_letters("QP")), 0.0);
    }

    #[test]
    fn a_text_of_one_letter_is_flagged_by_coverage() {
        assert_eq!(coverage(&to_letters("AAAA")), 1.0);
    }

    #[test]
    fn windows_are_the_width_asked_for() {
        let corpus: Vec<u8> = (0..100).map(|i| (i % 26) as u8).collect();
        let w = windows(10, 4, &corpus);
        assert_eq!(w.len(), 4);
        assert!(w.iter().all(|x| x.len() == 10));
    }

    #[test]
    fn assess_puts_a_constant_text_far_out() {
        let mut rng = Rng::new(5);
        let population = random_population(60, 200, &mut rng);
        let st = &statistics(None)[0];
        let v = assess(st, &[0u8; 60], &population);
        assert!(v.p < 0.01, "p was {}", v.p);
    }
}
