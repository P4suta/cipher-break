// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::{ALPHABET, Letter, from_letters};
use crate::attack::Coverage;
use crate::polyglot::{Calibration, Polyglot, Scale};
use crate::rng::Rng;
use crate::sweep::Outcome;
use crate::triage::Verdict as StatVerdict;
use std::collections::HashMap;
use std::fmt::Write as _;

pub enum Conclusion {
    Read {
        attack: String,
        key: String,
        plain: Vec<Letter>,
        language: String,
        score: f64,
        reference: Calibration,
    },
    Unread {
        best: f64,
        noise: f64,
        keys: u64,
        exhaustive: usize,
        unjudged: Vec<(String, usize, usize)>,
        impossible: Vec<(String, &'static str)>,
    },
}

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

pub const MERIT_BAR: f64 = 4.0;

pub const MIN_NULLS_EXHAUSTIVE: usize = 3;

pub const MIN_NULLS_SEARCHED: usize = 8;

#[must_use]
pub fn nulls_required(coverage: Coverage) -> usize {
    match coverage {
        Coverage::Exhaustive(_) => MIN_NULLS_EXHAUSTIVE,
        Coverage::Searched(_) => MIN_NULLS_SEARCHED,
        Coverage::Impossible(_) => 0,
    }
}

pub struct Calibrator<'a> {
    bank: Option<(&'a Polyglot, &'a Scale)>,
    fixed: Option<Calibration>,
    seed: u64,
    cache: HashMap<usize, Calibration>,
}

impl<'a> Calibrator<'a> {
    #[must_use]
    pub fn new(bank: &'a Polyglot, scale: &'a Scale, seed: u64) -> Self {
        Calibrator {
            bank: Some((bank, scale)),
            fixed: None,
            seed,
            cache: HashMap::new(),
        }
    }

    #[must_use]
    pub fn fixed(calibration: Calibration) -> Self {
        Calibrator {
            bank: None,
            fixed: Some(calibration),
            seed: 0,
            cache: HashMap::new(),
        }
    }

    /// # Panics
    /// Panics if neither a fixed calibration nor a model bank is present.
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

#[must_use]
pub fn conclude(
    outcomes: &[Outcome],
    calibrator: &mut Calibrator,
    judge_name: impl Fn(&[Letter]) -> String,
) -> Conclusion {
    let mut passing: Vec<(&Outcome, usize, u64, f64)> = Vec::new();
    for outcome in outcomes {
        for (i, candidate) in outcome.best.iter().enumerate() {
            if !calibrator
                .at(candidate.plain.len())
                .reads_as_language(candidate.score)
            {
                continue;
            }
            if outcome.null.len() < nulls_required(outcome.coverage) {
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
            if !(m.is_finite() && m >= MERIT_BAR) {
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
    let unjudged = outcomes
        .iter()
        .filter(|o| o.impossible().is_none())
        .filter(|o| o.null.len() < nulls_required(o.coverage))
        .map(|o| (o.name.clone(), o.null.len(), nulls_required(o.coverage)))
        .collect();
    Conclusion::Unread {
        best,
        noise,
        keys,
        exhaustive,
        impossible,
        unjudged,
    }
}

#[must_use]
pub fn heading(title: &str) -> String {
    let rule = "─".repeat(72usize.saturating_sub(title.chars().count() + 3));
    format!("\n\x1b[1m{title}\x1b[0m {rule}\n")
}

#[must_use]
pub fn statistics_table(verdicts: &[StatVerdict], population: &str) -> String {
    let mut out = format!(
        "  {:<22} {:>10} {:>11} {:>8} {:>8} {:>10}\n",
        "statistic", "observed", population, "z", "P", "P in table"
    );
    for v in verdicts {
        let _ = writeln!(
            out,
            "  {:<22} {:>10.4} {:>11.4} {:>+8.2} {:>8.4} {:>10}",
            v.name,
            v.observed,
            v.mean,
            v.z,
            v.p,
            if v.family_p.is_nan() {
                "-".to_string()
            } else {
                format!("{:.4}", v.family_p)
            }
        );
    }
    out
}

#[must_use]
pub fn best_of_n(samples: &[f64], n: u64) -> f64 {
    best_of_n_fit(samples, n).map_or(f64::INFINITY, |fit| fit.median)
}

#[derive(Clone, Copy, Debug)]
pub struct BestOfN {
    pub median: f64,
    pub spread: f64,
}

impl BestOfN {
    #[must_use]
    pub fn chance_of_reaching(&self, score: f64) -> f64 {
        if self.spread <= 0.0 || !self.spread.is_finite() {
            return if score > self.median { 0.0 } else { 1.0 };
        }
        let location = self.median - self.spread * (1.0 / std::f64::consts::LN_2).ln();
        let z = (score - location) / self.spread;
        -(-(-z).exp()).exp_m1()
    }
}

#[must_use]
pub fn best_of_n_fit(samples: &[f64], n: u64) -> Option<BestOfN> {
    if samples.len() < BLOCKS_FOR_GROWTH.iter().max().copied().unwrap_or(1) || n == 0 {
        return None;
    }
    let mut points: Vec<(f64, f64)> = Vec::new();
    for &size in BLOCKS_FOR_GROWTH {
        let mut tops: Vec<f64> = samples
            .chunks(size)
            .filter(|c| c.len() == size)
            .map(|c| c.iter().copied().fold(f64::NEG_INFINITY, f64::max))
            .collect();
        if tops.is_empty() {
            continue;
        }
        tops.sort_by(f64::total_cmp);
        points.push(((size as f64).ln(), tops[tops.len() / 2]));
    }
    if points.len() < 2 {
        return None;
    }
    let count = points.len() as f64;
    let sx: f64 = points.iter().map(|p| p.0).sum();
    let sy: f64 = points.iter().map(|p| p.1).sum();
    let sxy: f64 = points.iter().map(|p| p.0 * p.1).sum();
    let sxx: f64 = points.iter().map(|p| p.0 * p.0).sum();
    let denominator = count * sxx - sx * sx;
    if denominator.abs() < f64::EPSILON {
        return None;
    }
    let slope = (count * sxy - sx * sy) / denominator;
    let intercept = (sy - slope * sx) / count;
    Some(BestOfN {
        median: intercept + slope * (n as f64).ln(),
        spread: slope,
    })
}

const BLOCKS_FOR_GROWTH: &[usize] = &[100, 400, 1_600, 6_400, 25_600];

#[must_use]
pub fn unicity_distance(keys: u64, redundancy: f64) -> f64 {
    if keys <= 1 || redundancy <= 0.0 {
        return 0.0;
    }
    (keys as f64).log2() / redundancy
}

#[must_use]
pub fn redundancy(gram_score_nats: f64, order: usize) -> f64 {
    let per_letter = -gram_score_nats / order.max(1) as f64;
    (ALPHABET as f64).log2() - per_letter / std::f64::consts::LN_2
}

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

#[must_use]
pub fn outcome_header() -> String {
    format!(
        "  {:<34} {:>12} {:>9} {:>9} {:>7}\n",
        "attack", "keys", "best", "noise", "z"
    )
}

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
            unjudged,
        } => {
            let mut out = format!(
                "  \x1b[1;33mUNREAD\x1b[0m  nothing tried produced a language.\n\n  \
                 {keys} keys across the catalogue, {exhaustive} of the attacks exhaustive.\n  \
                 best fit {best:+.1}s; the same searches on shuffled text reach {noise:+.1}s.\n  \
                 real text of this length reaches {:+.1}s. (s = deviations above random letters.)\n",
                cal.language_mean
            );
            if !unjudged.is_empty() {
                let _ = writeln!(
                    out,
                    "\n  {} attacks could not be judged: a margin needs more shuffles than this run gave it.",
                    unjudged.len()
                );
                for (name, had, wanted) in unjudged.iter().take(4) {
                    let _ = writeln!(out, "    {name}: {had} of {wanted}");
                }
            }
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
    #[test]
    fn the_bar_a_search_must_clear_rises_with_the_size_of_the_search() {
        use super::best_of_n;

        let mut rng = crate::rng::Rng::new(5);
        let samples: Vec<f64> = (0..30_000)
            .map(|_| (0..12).map(|_| rng.unit()).sum::<f64>() - 6.0)
            .collect();

        let few = best_of_n(&samples, 1_000);
        let many = best_of_n(&samples, 1_000_000_000);
        assert!(
            many > few,
            "the best of a billion tries has to beat the best of a thousand: {many} vs {few}"
        );
        let more = best_of_n(&samples, 1_000_000);
        assert!(
            (many - more - (more - few)).abs() < (more - few),
            "the growth should be in the logarithm: {few} {more} {many}"
        );
    }

    #[test]
    fn a_bar_cannot_be_measured_from_too_few_samples() {
        use super::best_of_n;

        assert_eq!(super::best_of_n(&[1.0, 2.0, 3.0], 1_000), f64::INFINITY);
        assert_eq!(best_of_n(&[], 1_000), f64::INFINITY);
    }

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
    fn a_null_that_could_not_discriminate_is_not_a_licence() {
        let mut searched = outcome(20.0, vec![1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]);
        searched.coverage = Coverage::Searched(0);
        assert!(matches!(
            conclude(&[searched], &mut Calibrator::fixed(cal()), |_| "de".into()),
            Conclusion::Unread { .. }
        ));
    }

    #[test]
    fn with_no_null_at_all_nothing_can_be_read() {
        let mut o = outcome(20.0, vec![]);
        o.coverage = Coverage::Exhaustive(10);
        match conclude(&[o], &mut Calibrator::fixed(cal()), |_| "en".into()) {
            Conclusion::Unread { unjudged, .. } => assert_eq!(unjudged.len(), 1),
            Conclusion::Read { .. } => panic!("read something with no null at all"),
        }
    }

    #[test]
    fn a_margin_from_too_few_nulls_is_not_believed() {
        let mut searched = outcome(16.7, vec![15.5, 14.9, 15.2]);
        searched.coverage = Coverage::Searched(0);
        assert!(matches!(
            conclude(&[searched], &mut Calibrator::fixed(cal()), |_| "de".into()),
            Conclusion::Unread { .. }
        ));
    }

    #[test]
    fn an_unjudged_attack_is_named_in_the_conclusion() {
        let mut searched = outcome(16.7, vec![15.5, 14.9, 15.2]);
        searched.coverage = Coverage::Searched(0);
        match conclude(&[searched], &mut Calibrator::fixed(cal()), |_| "de".into()) {
            Conclusion::Unread { unjudged, .. } => {
                assert_eq!(unjudged.len(), 1);
                assert_eq!(unjudged[0].1, 3);
                assert_eq!(unjudged[0].2, MIN_NULLS_SEARCHED);
            }
            Conclusion::Read { .. } => panic!("should not read"),
        }
    }

    #[test]
    fn the_same_margin_with_enough_nulls_is_believed() {
        let mut searched = outcome(16.7, vec![15.5, 14.9, 15.2, 15.1, 15.3, 15.0, 15.4, 15.2]);
        searched.coverage = Coverage::Searched(0);
        assert!(matches!(
            conclude(&[searched], &mut Calibrator::fixed(cal()), |_| "de".into()),
            Conclusion::Read { .. }
        ));
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
        let outcomes = vec![outcome(20.0, vec![20.5, 19.2, 20.1, 19.9])];
        assert!(matches!(
            conclude(&outcomes, &mut Calibrator::fixed(cal()), |_| "en".into()),
            Conclusion::Unread { .. }
        ));
    }

    #[test]
    fn an_impossible_coverage_needs_no_nulls() {
        assert_eq!(nulls_required(Coverage::Impossible("x")), 0);
        assert_eq!(
            nulls_required(Coverage::Exhaustive(1)),
            MIN_NULLS_EXHAUSTIVE
        );
        assert_eq!(nulls_required(Coverage::Searched(1)), MIN_NULLS_SEARCHED);
    }

    #[test]
    fn a_candidate_below_its_own_null_is_not_read() {
        let outcomes = vec![outcome(20.0, vec![21.0, 20.5, 22.0, 20.1])];
        assert!(matches!(
            conclude(&outcomes, &mut Calibrator::fixed(cal()), |_| "en".into()),
            Conclusion::Unread { .. }
        ));
    }

    #[test]
    fn every_outcome_is_considered_and_not_just_the_first() {
        let weak = outcome(1.0, vec![1.0, 1.1, 0.9, 1.0]);
        let strong = outcome(20.0, vec![1.0, 1.1, 0.9, 1.0]);
        assert!(matches!(
            conclude(&[weak, strong], &mut Calibrator::fixed(cal()), |_| "en"
                .into()),
            Conclusion::Read { .. }
        ));
    }

    #[test]
    fn several_candidates_of_one_outcome_are_all_considered() {
        let mut o = outcome(1.0, vec![1.0, 1.1, 0.9, 1.0]);
        o.best.push(Candidate {
            score: 20.0,
            key: "second".into(),
            plain: vec![1, 2, 3],
        });
        match conclude(&[o], &mut Calibrator::fixed(cal()), |_| "en".into()) {
            Conclusion::Read { key, .. } => assert_eq!(key, "second"),
            Conclusion::Unread { .. } => panic!("the second candidate was never looked at"),
        }
    }

    #[test]
    fn the_unread_summary_counts_what_it_saw() {
        let mut exhaustive = outcome(1.0, vec![1.0, 1.1, 0.9, 1.0]);
        exhaustive.coverage = Coverage::Exhaustive(100);
        let mut searched = outcome(1.0, vec![1.0, 1.1, 0.9, 1.0, 1.0, 1.0, 1.0, 1.0]);
        searched.coverage = Coverage::Searched(50);
        match conclude(
            &[exhaustive, searched],
            &mut Calibrator::fixed(cal()),
            |_| "en".into(),
        ) {
            Conclusion::Unread {
                keys, exhaustive, ..
            } => {
                assert_eq!(keys, 150);
                assert_eq!(exhaustive, 1);
            }
            Conclusion::Read { .. } => panic!("should not read"),
        }
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
