// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning evidence into a conclusion, and a conclusion into something to read.
//!
//! The rule the whole tool is built on applies here most of all: a leading score is not a solution.
//! A candidate is reported as a reading only when it clears the bar real text of that length clears, *and* stands clear of what the same search found in shuffled text.
//! Anything else is reported as what it is — the best of a large number of tries, which is a different thing.

use crate::alphabet::{Letter, from_letters};
use crate::attack::Coverage;
use crate::polyglot::{Calibration, Polyglot, Scale};
use crate::rng::Rng;
use crate::sweep::Outcome;
use crate::triage::Verdict as StatVerdict;
use std::collections::HashMap;
use std::fmt::Write as _;

/// How a run ended.
pub enum Conclusion {
    /// A candidate reads as language and stands clear of its null.
    Read {
        /// Which attack found it.
        attack: String,
        /// The key.
        key: String,
        /// The plaintext.
        plain: Vec<Letter>,
        /// The language it was recognised as.
        language: String,
        /// What it scored.
        score: f64,
        /// What real text of *that candidate's* length scores.
        reference: Calibration,
    },
    /// Nothing read.
    /// The best of what was tried is reported for what it is.
    Unread {
        /// The best score anything reached.
        best: f64,
        /// What noise reached under the same searches.
        noise: f64,
        /// How many keys were tried in total.
        keys: u64,
        /// How many attacks were exhaustive.
        exhaustive: usize,
        /// Attacks ruled out with no key tried, and why.
        impossible: Vec<(String, &'static str)>,
    },
}

/// How much a candidate outruns what its own attack achieves on noise.
///
/// This, and not the raw score, is what decides.
/// A sixteen-letter Vigenere key has sixteen free choices over a short text and can bend it towards a language whatever the text is; a Caesar shift has one choice and cannot.
/// If both reach the same score, only one of them has said anything, and the difference shows in what the same search does to shuffled text.
///
/// This tool read a plain Caesar cipher as a sixteen-letter Vigenere key until selection was changed from the score to this.
#[must_use]
pub fn merit(outcome: &Outcome, score: f64) -> f64 {
    match outcome.z() {
        Some(_) => {
            let (mean, sd) = outcome.null_moments();
            (score - mean) / sd
        }
        None => f64::NAN,
    }
}

/// How far above its null a candidate must stand before it is called a reading.
pub const MERIT_BAR: f64 = 4.0;

/// Decide what a set of outcomes amounts to.
///
///
/// The margin over the null is required as well as the language bar, because an annealing search over 25 factorial squares will clear the language bar on pure noise given enough restarts.
/// That is not a hypothetical: on a 72-letter text this tool does exactly that, and the null is the only thing that catches it.
/// Calibrations, one per text length, computed as they are needed.
///
/// A candidate is not always as long as the ciphertext.
/// A null cipher hides 49 letters inside 147, and 49 letters of English score lower than 147 do under the same models — shorter samples are noisier and the mean drifts with them.
/// Judging the short candidate against the long calibration is how this tool missed a message hidden as every third letter.
pub struct Calibrator<'a> {
    bank: Option<(&'a Polyglot, &'a Scale)>,
    fixed: Option<Calibration>,
    seed: u64,
    cache: HashMap<usize, Calibration>,
}

impl<'a> Calibrator<'a> {
    /// A calibrator over a bank of models and the scale they are read on.
    #[must_use]
    pub fn new(bank: &'a Polyglot, scale: &'a Scale, seed: u64) -> Self {
        Calibrator {
            bank: Some((bank, scale)),
            fixed: None,
            seed,
            cache: HashMap::new(),
        }
    }

    /// A calibrator that answers the same way at every length.
    #[must_use]
    pub fn fixed(calibration: Calibration) -> Self {
        Calibrator {
            bank: None,
            fixed: Some(calibration),
            seed: 0,
            cache: HashMap::new(),
        }
    }

    /// The calibration for texts of a given length.
    ///
    /// # Panics
    ///
    /// Panics if the calibrator was built with neither a bank nor a fixed answer, which the constructors make impossible.
    pub fn at(&mut self, len: usize) -> Calibration {
        if let Some(c) = self.fixed {
            return c;
        }
        let seed = self.seed;
        let (bank, scale) = self
            .bank
            .expect("a calibrator has a bank or a fixed answer");
        *self
            .cache
            .entry(len)
            .or_insert_with(|| bank.calibrate(scale, len, 120, &mut Rng::new(seed ^ len as u64)))
    }
}

/// Weigh every candidate against the language bar, its own null, and the size of the key space that produced it.
#[must_use]
pub fn conclude(
    outcomes: &[Outcome],
    calibrator: &mut Calibrator,
    judge_name: impl Fn(&[Letter]) -> String,
) -> Conclusion {
    // Every candidate that clears both bars, with what it costs to believe it.
    // A Caesar shift and a period-three Vigenere key of DDD produce the same plaintext; the first is the explanation worth printing, and "smallest key space that suffices" is what says so without a table of special cases.
    let mut passing: Vec<(&Outcome, usize, u64, f64)> = Vec::new();
    for outcome in outcomes {
        for (i, candidate) in outcome.best.iter().enumerate() {
            if !calibrator
                .at(candidate.plain.len())
                .reads_as_language(candidate.score)
            {
                continue;
            }
            let clear = match outcome.null_max() {
                n if n.is_finite() => candidate.score > n,
                _ => true,
            };
            if !clear {
                continue;
            }
            let m = merit(outcome, candidate.score);
            if !m.is_nan() && m < MERIT_BAR {
                continue;
            }
            let cost = match outcome.coverage {
                Coverage::Exhaustive(n) => n,
                _ => u64::MAX,
            };
            passing.push((
                outcome,
                i,
                cost,
                if m.is_nan() { candidate.score } else { m },
            ));
        }
    }
    passing.sort_by(|a, b| a.2.cmp(&b.2).then(b.3.total_cmp(&a.3)));
    let best_read = passing.first().map(|&(o, i, _, m)| (o, i, m));
    if let Some((outcome, i, _)) = best_read {
        let candidate = &outcome.best[i];
        let score = candidate.score;
        return Conclusion::Read {
            attack: outcome.name.clone(),
            key: candidate.key.clone(),
            plain: candidate.plain.clone(),
            language: judge_name(&candidate.plain),
            score,
            reference: calibrator.at(candidate.plain.len()),
        };
    }
    let best = outcomes
        .iter()
        .map(Outcome::leader)
        .fold(f64::NEG_INFINITY, f64::max);
    let noise = outcomes
        .iter()
        .map(Outcome::null_max)
        .fold(f64::NEG_INFINITY, f64::max);
    let keys = outcomes.iter().map(|o| o.coverage.keys()).sum();
    let exhaustive = outcomes
        .iter()
        .filter(|o| matches!(o.coverage, Coverage::Exhaustive(_)))
        .count();
    let impossible = outcomes
        .iter()
        .filter_map(|o| o.impossible().map(|why| (o.name.clone(), why)))
        .collect();
    Conclusion::Unread {
        best,
        noise,
        keys,
        exhaustive,
        impossible,
    }
}

/// A heading with a rule under it.
#[must_use]
pub fn heading(title: &str) -> String {
    let rule = "─".repeat(72usize.saturating_sub(title.chars().count() + 3));
    format!("\n\x1b[1m{title}\x1b[0m {rule}\n")
}

/// Render the statistics table.
#[must_use]
pub fn statistics_table(verdicts: &[StatVerdict], population: &str) -> String {
    let mut out = format!(
        "  {:<22} {:>10} {:>11} {:>8} {:>8}\n",
        "statistic", "observed", population, "z", "P"
    );
    for v in verdicts {
        let _ = writeln!(
            out,
            "  {:<22} {:>10.4} {:>11.4} {:>+8.2} {:>8.4}",
            v.name, v.observed, v.mean, v.z, v.p
        );
    }
    out
}

/// Render one sweep's result as a table row.
#[must_use]
pub fn outcome_row(o: &Outcome) -> String {
    if let Some(why) = o.impossible() {
        return format!("  {:<34} {:>12}  impossible: {}\n", o.name, "-", why);
    }
    let keys = match o.coverage {
        Coverage::Exhaustive(n) => format!("{n} all"),
        Coverage::Searched(_) => "searched".into(),
        Coverage::Impossible(_) => "-".into(),
    };
    let z = o.z().map_or_else(|| "-".into(), |z| format!("{z:+.2}"));
    format!(
        "  {:<34} {:>12} {:>9.3} {:>9.3} {:>7}\n",
        o.name,
        keys,
        o.leader(),
        o.null_max(),
        z
    )
}

/// The header of the sweep table.
#[must_use]
pub fn outcome_header() -> String {
    format!(
        "  {:<34} {:>12} {:>9} {:>9} {:>7}\n",
        "attack", "keys", "best", "noise", "z"
    )
}

/// Render a conclusion.
#[must_use]
pub fn conclusion(c: &Conclusion, cal: &Calibration) -> String {
    match c {
        Conclusion::Read {
            attack,
            key,
            plain,
            language,
            score,
            reference,
        } => format!(
            "  \x1b[1;32mREAD\x1b[0m  {attack}\n  key       {key}\n  language  {language}  (fit {score:+.3}, \
             text of this length reaches {:+.1})\n\n  {}\n",
            reference.language_mean,
            from_letters(plain)
        ),
        Conclusion::Unread {
            best,
            noise,
            keys,
            exhaustive,
            impossible,
        } => {
            let mut out = format!(
                "  \x1b[1;33mUNREAD\x1b[0m  nothing tried produced a language.\n\n  \
                 {keys} keys across the catalogue, {exhaustive} of the attacks exhaustive.\n  \
                 best fit {best:+.1}s; the same searches on shuffled text reach {noise:+.1}s.\n  \
                 real text of this length reaches {:+.1}s. (s = deviations above random letters.)\n",
                cal.language_mean
            );
            if !impossible.is_empty() {
                out.push_str("\n  ruled out with no key tried:\n");
                let mut grouped: Vec<(&'static str, Vec<&str>)> = Vec::new();
                for (name, why) in impossible {
                    match grouped.iter_mut().find(|(w, _)| w == why) {
                        Some((_, names)) => names.push(name),
                        None => grouped.push((why, vec![name])),
                    }
                }
                for (why, names) in grouped {
                    let _ = writeln!(out, "    {why}");
                    let _ = writeln!(out, "      {}", names.join(", "));
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::Candidate;

    fn cal() -> Calibration {
        Calibration {
            language_mean: 20.0,
            language_sd: 1.0,
            language_floor: 17.0,
            noise_mean: 0.0,
            noise_sd: 1.0,
        }
    }

    #[test]
    fn the_bar_sits_between_noise_and_language() {
        let c = cal();
        assert!(c.floor() > c.noise_mean);
        assert!(c.floor() < c.language_mean);
        // Real prose scores below model-drawn text; the bar has to allow for it.
        assert!(c.reads_as_language(13.0));
    }

    fn outcome(best: f64, null: Vec<f64>) -> Outcome {
        Outcome {
            name: "test".into(),
            family: "test",
            coverage: Coverage::Exhaustive(10),
            best: vec![Candidate {
                score: best,
                key: "k".into(),
                plain: vec![0, 1, 2],
            }],
            null,
        }
    }

    #[test]
    fn a_clear_winner_is_read() {
        let outcomes = vec![outcome(20.0, vec![1.0, 1.5, 0.8, 1.2])];
        assert!(matches!(
            conclude(&outcomes, &mut Calibrator::fixed(cal()), |_| "en".into()),
            Conclusion::Read { .. }
        ));
    }

    #[test]
    fn the_simpler_attack_wins_a_tie_on_score() {
        // Both reach -7.0.
        // The one whose null stays far below has said something; the one whose null follows it up has not.
        let mut narrow = outcome(20.0, vec![1.0, 1.1, 0.9, 1.0]);
        narrow.name = "caesar".into();
        let mut loose = outcome(20.0, vec![19.4, 19.6, 19.5, 19.5]);
        loose.name = "sixteen-letter climb".into();
        match conclude(&[loose, narrow], &mut Calibrator::fixed(cal()), |_| {
            "en".into()
        }) {
            Conclusion::Read { attack, .. } => assert_eq!(attack, "caesar"),
            Conclusion::Unread { .. } => panic!("should have read the narrow one"),
        }
    }

    #[test]
    fn a_score_below_the_language_floor_is_not_read() {
        let outcomes = vec![outcome(5.0, vec![1.0, 1.2, 0.9, 1.1])];
        assert!(matches!(
            conclude(&outcomes, &mut Calibrator::fixed(cal()), |_| "en".into()),
            Conclusion::Unread { .. }
        ));
    }

    #[test]
    fn a_score_the_null_also_reaches_is_not_read() {
        // The annealing trap: a high score that noise reaches just as easily.
        let outcomes = vec![outcome(20.0, vec![20.5, 19.2, 20.1, 19.9])];
        assert!(matches!(
            conclude(&outcomes, &mut Calibrator::fixed(cal()), |_| "en".into()),
            Conclusion::Unread { .. }
        ));
    }

    #[test]
    fn impossible_attacks_are_carried_into_the_conclusion() {
        let mut o = outcome(5.0, vec![1.0, 1.1, 0.9, 1.0]);
        o.coverage = Coverage::Impossible("because");
        o.best.clear();
        match conclude(&[o], &mut Calibrator::fixed(cal()), |_| "en".into()) {
            Conclusion::Unread { impossible, .. } => assert_eq!(impossible.len(), 1),
            Conclusion::Read { .. } => panic!("should not read"),
        }
    }
}
