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

/// The vowels, as letters.
const VOWELS: [Letter; 5] = [0, 4, 8, 14, 20];

/// The three rows of a QWERTY keyboard.
const QWERTY: [&str; 3] = ["QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"];

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
    ls.iter().filter(|l| VOWELS.contains(l)).count() as f64
}

/// Adjacent letters that neighbour each other on a QWERTY keyboard.
///
/// The other half of the same suspicion: a mashed keyboard leaves its own geometry behind, and this is what that looks like when counted.
#[must_use]
pub fn qwerty_neighbours(ls: &[Letter]) -> f64 {
    let place = |l: Letter| -> Option<(i32, i32)> {
        let c = letter_char(l);
        QWERTY
            .iter()
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

/// The longest stretch of one repeated letter.
///
/// The Haskell reference has carried this since the first day and the Rust implementation did not, which a test written against the reference is what found.
/// Two implementations are only worth having while they answer alike.
#[must_use]
pub fn longest_run(ls: &[Letter]) -> f64 {
    let mut best = 0usize;
    let mut run = 0usize;
    let mut previous: Option<Letter> = None;
    for &l in ls {
        run = if previous == Some(l) { run + 1 } else { 1 };
        previous = Some(l);
        best = best.max(run);
    }
    best as f64
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
            name: "longest vowel-free run",
            tail: Tail::Upper,
            of: Box::new(longest_vowel_free_run),
        },
        Statistic {
            name: "QWERTY neighbours",
            tail: Tail::Upper,
            of: Box::new(qwerty_neighbours),
        },
        Statistic {
            name: "longest run",
            tail: Tail::Upper,
            of: Box::new(longest_run),
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

/// The longest stretch containing no vowel at all.
///
/// A count of vowels says how many there are; this says whether they are spread through the message or gathered at one end of it.
/// The two come apart: a message can hold the ordinary number of vowels and still have half of itself without one, and that is a message that is probably two things rather than one — a preamble and a body, two ciphers, or a key group carried in front of the text it opens.
#[must_use]
pub fn longest_vowel_free_run(ls: &[Letter]) -> f64 {
    let mut best = 0usize;
    let mut run = 0usize;
    for &l in ls {
        run = if VOWELS.contains(&l) { 0 } else { run + 1 };
        best = best.max(run);
    }
    best as f64
}

/// Ciphertexts an Enigma would actually produce, for comparing a message against the machine it is supposed to have come out of.
///
/// The usual null — letters drawn uniformly — answers "is this random", which is not the question anyone is asking.
/// The question is whether the message looks like what the assumed cipher emits, and for a rotor machine that is not the same thing: no letter ever enciphers to itself, so the ciphertext is thinned of whatever the plaintext is rich in, and a null of uniform letters would call that thinning an anomaly in every Enigma message ever sent.
///
/// Each draw is a fresh machine — rotor order, rings, starting position, and ten plugboard leads — enciphering fresh text sampled from the language model.
#[must_use]
pub fn enigma_population(
    len: usize,
    count: usize,
    plaintext: &crate::ngram::Model,
    rng: &mut Rng,
) -> Vec<Vec<Letter>> {
    use crate::ciphers::enigma::{Enigma, Plugboard, ROTOR_COUNT, Settings, rotor_orders};

    let orders = rotor_orders(ROTOR_COUNT);
    (0..count)
        .map(|_| {
            let rotors = orders[rng.below(orders.len())];
            let pick = |rng: &mut Rng| {
                [
                    rng.below(ALPHABET) as u8,
                    rng.below(ALPHABET) as u8,
                    rng.below(ALPHABET) as u8,
                ]
            };
            let rings = pick(rng);
            let positions = pick(rng);
            let mut board = Plugboard::empty();
            let mut free: Vec<u8> = (0..ALPHABET as u8).collect();
            for _ in 0..PLUGBOARD_LEADS {
                let a = free.swap_remove(rng.below(free.len()));
                let b = free.swap_remove(rng.below(free.len()));
                board.connect(a, b);
            }
            let settings = Settings::at(rotors, rng.below(2), rings, positions);
            Enigma::new(settings, board).run(&plaintext.sample(len, rng))
        })
        .collect()
}

/// How many plugboard leads a wartime naval Enigma carried.
const PLUGBOARD_LEADS: usize = 10;

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
    #[test]
    fn the_longest_vowel_free_run_is_counted_across_the_whole_text() {
        use super::longest_vowel_free_run as run;
        use crate::alphabet::to_letters;

        assert_eq!(run(&to_letters("")), 0.0);
        assert_eq!(run(&to_letters("AEIOU")), 0.0, "every letter a vowel, so no run at all");
        assert_eq!(run(&to_letters("BCDFG")), 5.0, "no vowel anywhere, so the whole text");
        assert_eq!(run(&to_letters("BCAdEfG")), 2.0, "the longest of several, not the last");
        assert_eq!(run(&to_letters("ABCD")), 3.0, "a run that reaches the end still counts");
    }

    #[test]
    fn a_vowel_count_and_a_vowel_run_are_different_questions() {
        use super::{longest_vowel_free_run as run, vowels};
        use crate::alphabet::to_letters;

        // The same number of vowels, spread out or gathered up.
        let spread = to_letters("BAB BAB BAB BAB".replace(' ', "").as_str());
        let heaped = to_letters("AAAA BBBB BBBB BBBB".replace(' ', "").as_str());
        assert_eq!(vowels(&spread), vowels(&heaped), "the same vowels either way");
        assert!(
            run(&heaped) > run(&spread),
            "and only the run can tell that one of them is gathered at an end: {} vs {}",
            run(&heaped),
            run(&spread)
        );
    }

    #[test]
    fn an_enigma_null_is_thinned_of_what_its_plaintext_was_rich_in() {
        use crate::alphabet::ALPHABET;
        use crate::polyglot::Polyglot;

        // The property the null exists to capture, and the reason uniform letters are the wrong comparison: a letter never enciphers to itself, so a vowel-rich plaintext yields a vowel-poor ciphertext.
        // The effect is small — a plaintext vowel only bars its own letter, not every vowel — and getting that wrong once turned a real anomaly into an imagined artefact.
        let bank = Polyglot::from_bundle(include_str!("../data/models.bundle"));
        let Some(german) = bank.model_named("de") else {
            return;
        };
        let mut rng = Rng::new(11);
        let draws = enigma_population(200, 400, german, &mut rng);

        let vowels = |t: &[Letter]| {
            t.iter().filter(|&&l| b"AEIOU".contains(&(l + b'A'))).count() as f64
                / t.len() as f64
        };
        let machine: f64 = draws.iter().map(|t| vowels(t)).sum::<f64>() / draws.len() as f64;
        let uniform = 5.0 / ALPHABET as f64;

        assert!(
            machine < uniform,
            "an Enigma null should be thinner in vowels than uniform letters: {machine} vs {uniform}"
        );
        // And only a little thinner.
        // A plaintext vowel bars one letter of twenty-five, not five.
        assert!(
            machine > uniform - 0.02,
            "the thinning is small, and a null that overshoots it would excuse a real anomaly: {machine} vs {uniform}"
        );
    }

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
    fn repetition_needs_a_text_longer_than_the_gram() {
        assert_eq!(repetition(3, &to_letters("AB")), 0.0);
        assert_eq!(repetition(3, &to_letters("ABC")), 0.0);
        assert_eq!(repetition(2, &to_letters("AAA")), 1.0);
    }

    #[test]
    fn the_digraph_index_counts_repeated_pairs() {
        // Three identical pairs: three of them, three ordered matches out of the six ordered draws, so one half.
        assert_eq!(digraph_ic(&to_letters("ABABAB")), 1.0);
        assert_eq!(digraph_ic(&to_letters("ABCDEF")), 0.0);
        assert_eq!(digraph_ic(&to_letters("AB")), 0.0);
        assert_eq!(digraph_ic(&[]), 0.0);
    }

    #[test]
    fn an_odd_trailing_letter_is_not_a_pair() {
        assert_eq!(
            digraph_ic(&to_letters("ABABX")),
            digraph_ic(&to_letters("ABAB"))
        );
    }

    #[test]
    fn coverage_counts_letters_once_each() {
        assert_eq!(coverage(&to_letters("ABCABC")), 3.0);
        assert_eq!(coverage(&[]), 0.0);
    }

    #[test]
    fn the_longest_run_is_the_longest_run() {
        assert_eq!(longest_run(&to_letters("AABBBC")), 3.0);
        assert_eq!(longest_run(&to_letters("ABCDEF")), 1.0);
        assert_eq!(longest_run(&[]), 0.0);
    }

    #[test]
    fn qwerty_neighbours_are_symmetric_and_exclude_repeats() {
        assert_eq!(qwerty_neighbours(&to_letters("WQ")), 1.0);
        assert_eq!(
            qwerty_neighbours(&to_letters("QQ")),
            0.0,
            "a letter is not its own neighbour"
        );
        assert_eq!(
            qwerty_neighbours(&to_letters("QA")),
            1.0,
            "rows below count"
        );
        assert_eq!(
            qwerty_neighbours(&to_letters("QZ")),
            0.0,
            "two rows away do not"
        );
    }

    #[test]
    fn a_lower_tailed_statistic_is_judged_from_below() {
        let mut rng = Rng::new(9);
        let population = random_population(60, 200, &mut rng);
        let lower = Statistic {
            name: "vowels",
            tail: Tail::Lower,
            of: Box::new(vowels),
        };
        // A text with no vowels at all is extreme at the low end.
        let none: Vec<Letter> = vec![1; 60];
        assert!(assess(&lower, &none, &population).p < 0.01);
        // And a text stuffed with them is not, on that tail.
        let all: Vec<Letter> = vec![0; 60];
        assert!(assess(&lower, &all, &population).p > 0.99);
    }

    #[test]
    fn assess_reports_the_observation_it_was_given() {
        let mut rng = Rng::new(2);
        let population = random_population(40, 50, &mut rng);
        let text = vec![0u8; 40];
        let st = &statistics(None)[1];
        let v = assess(st, &text, &population);
        assert_eq!(v.name, "adjacent doubles");
        assert_eq!(v.observed, 39.0);
        assert!(v.z > 0.0);
    }

    #[test]
    fn the_battery_grows_when_a_bank_is_offered() {
        let without = statistics(None).len();
        let bank = crate::polyglot::Polyglot::default();
        assert_eq!(statistics(Some(&bank)).len(), without + 1);
    }

    #[test]
    fn windows_refuse_what_they_cannot_cut() {
        let corpus: Vec<u8> = (0..10).collect();
        assert!(windows(0, 4, &corpus).is_empty());
        assert!(windows(4, 0, &corpus).is_empty());
        assert!(windows(20, 4, &corpus).is_empty());
    }

    #[test]
    fn windows_never_overlap() {
        let corpus: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let w = windows(10, 10, &corpus);
        assert_eq!(w.len(), 10);
        let flat: Vec<u8> = w.concat();
        let mut sorted = flat.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), flat.len(), "a letter appeared in two windows");
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
