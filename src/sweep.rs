// SPDX-License-Identifier: MIT OR Apache-2.0

//! Running a key space, and knowing what its best result is worth.
//!
//! Trying 157,248 keys and keeping the one that scores highest is not evidence of anything on its own: the largest of 157,248 draws from a harmless distribution is large too.
//! Every sweep here therefore runs twice — once on the ciphertext and once on shuffles of it, which have the same letters in an order known to mean nothing — and reports both.
//! The margin between them is the finding.

use crate::alphabet::Letter;
use crate::attack::{Attack, Candidate, Context, Coverage};
use crate::rng::Rng;
use crate::stats::moments;

/// What a sweep found, and what the same sweep finds in noise.
pub struct Outcome {
    /// The attack that produced it.
    pub name: String,
    /// The family the attack belongs to.
    pub family: &'static str,
    /// How much of the key space was covered.
    pub coverage: Coverage,
    /// The best candidates, highest first.
    pub best: Vec<Candidate>,
    /// The best score the same attack reached on each shuffled text.
    pub null: Vec<f64>,
}

impl Outcome {
    /// The score of the leading candidate.
    #[must_use]
    pub fn leader(&self) -> f64 {
        self.best.first().map_or(f64::NEG_INFINITY, |c| c.score)
    }

    /// The highest score noise reached.
    #[must_use]
    pub fn null_max(&self) -> f64 {
        self.null.iter().copied().fold(f64::NEG_INFINITY, f64::max)
    }

    /// Mean and deviation of the null.
    #[must_use]
    pub fn null_moments(&self) -> (f64, f64) {
        moments(&self.null)
    }

    /// How far the leader stands above the null, in deviations of the null.
    ///
    /// Returns `None` when no null was run, because then there is nothing to stand above and the leading score means nothing on its own.
    #[must_use]
    pub fn z(&self) -> Option<f64> {
        if self.null.len() < 2 {
            return None;
        }
        let (mean, sd) = self.null_moments();
        Some((self.leader() - mean) / sd)
    }

    /// Whether the attack was ruled out without trying a key.
    #[must_use]
    pub fn impossible(&self) -> Option<&'static str> {
        match self.coverage {
            Coverage::Impossible(why) => Some(why),
            _ => None,
        }
    }
}

/// Run an attack on a ciphertext, then on shuffles of it.
#[must_use]
pub fn run(attack: &dyn Attack, ct: &[Letter], ctx: &Context, nulls: usize) -> Outcome {
    let coverage = attack.coverage(ct);
    if let Coverage::Impossible(_) = coverage {
        return Outcome {
            name: attack.name(),
            family: attack.family(),
            coverage,
            best: Vec::new(),
            null: Vec::new(),
        };
    }
    let best = attack.best(ct, ctx);
    let mut rng = Rng::new(ctx.seed ^ 0x5DEE_CE66_D000_0001);
    let shuffles: Vec<Vec<Letter>> = (0..nulls).map(|_| rng.shuffled(ct)).collect();
    let null = shuffles
        .iter()
        .map(|s| {
            let noise = Context {
                judge: ctx.judge,
                scale: ctx.scale,
                plan: ctx.plan,
                seed: ctx.seed,
                keep: 1,
                focus: ctx.focus,
                focus_scale: ctx.focus_scale,
                trace: &crate::trace::QUIET,
            };
            attack
                .best(s, &noise)
                .first()
                .map_or(f64::NEG_INFINITY, |c| c.score)
        })
        .collect();
    Outcome {
        name: attack.name(),
        family: attack.family(),
        coverage,
        best,
        null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;
    use crate::anneal::Schedule;
    use crate::attack::AffineSweep;
    use crate::ngram::Model;
    use crate::polyglot::{Polyglot, Scale};
    use crate::rng::Rng;

    #[test]
    fn an_affine_sweep_recovers_a_planted_shift() {
        let corpus = to_letters(
            "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGTHETHETHEANDANDANDTHATTHATTHERETHERE\
             THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGTHETHETHEANDANDANDTHATTHATTHERETHERE",
        );
        let judge = Polyglot::new(vec![("en".into(), Model::train(3, &corpus))]);
        let plain = to_letters("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHEREANDTHAT");
        let ct =
            crate::ciphers::substitution::apply(&crate::ciphers::substitution::shift(7), &plain);
        let scale = Scale::build(&judge, ct.len(), 40, &mut Rng::new(1));
        let ctx = Context {
            judge: &judge,
            scale: &scale,
            plan: Schedule::default(),
            seed: 1,
            keep: 3,
            focus: None,
            focus_scale: None,
            trace: &crate::trace::QUIET,
        };
        let outcome = run(&AffineSweep, &ct, &ctx, 0);
        assert_eq!(
            outcome.best[0].plain,
            plain,
            "recovered {}",
            crate::from_letters(&outcome.best[0].plain)
        );
    }

    #[test]
    fn an_impossible_attack_reports_why_and_tries_nothing() {
        let judge = Polyglot::default();
        let scale = Scale::build(&judge, 8, 2, &mut Rng::new(1));
        let ctx = Context {
            judge: &judge,
            scale: &scale,
            plan: Schedule::default(),
            seed: 1,
            keep: 1,
            focus: None,
            focus_scale: None,
            trace: &crate::trace::QUIET,
        };
        let ct = to_letters("ABPPCD");
        let outcome = run(&crate::attack::PlayfairAnneal, &ct, &ctx, 4);
        assert!(outcome.impossible().is_some());
        assert!(outcome.best.is_empty());
        assert!(outcome.null.is_empty());
    }

    fn made(best: Option<f64>, null: Vec<f64>) -> Outcome {
        Outcome {
            name: "test".into(),
            family: "test",
            coverage: Coverage::Exhaustive(10),
            best: best
                .map(|score| {
                    vec![crate::attack::Candidate {
                        score,
                        key: "k".into(),
                        plain: vec![0],
                    }]
                })
                .unwrap_or_default(),
            null,
        }
    }

    #[test]
    fn an_outcome_with_no_candidate_leads_with_nothing() {
        assert_eq!(made(None, vec![]).leader(), f64::NEG_INFINITY);
        assert_eq!(made(None, vec![]).null_max(), f64::NEG_INFINITY);
    }

    #[test]
    fn the_leader_is_the_first_candidate() {
        assert_eq!(made(Some(3.5), vec![]).leader(), 3.5);
    }

    #[test]
    fn the_null_maximum_is_the_maximum() {
        assert_eq!(made(None, vec![1.0, 5.0, 2.0]).null_max(), 5.0);
    }

    #[test]
    fn the_null_moments_are_its_mean_and_spread() {
        let (mean, sd) = made(None, vec![1.0, 3.0]).null_moments();
        assert!((mean - 2.0).abs() < 1e-12);
        assert!((sd - 1.0).abs() < 1e-12);
    }

    #[test]
    fn z_is_the_margin_in_deviations_of_the_null() {
        // Leader 5, null mean 2, deviation 1: three deviations clear.
        let z = made(Some(5.0), vec![1.0, 3.0])
            .z()
            .expect("two nulls are enough");
        assert!((z - 3.0).abs() < 1e-9, "z was {z}");
    }

    #[test]
    fn one_null_is_not_enough_for_a_z() {
        assert!(made(Some(5.0), vec![1.0]).z().is_none());
        assert!(made(Some(5.0), vec![1.0, 3.0]).z().is_some());
    }

    #[test]
    fn only_an_impossible_coverage_reports_why() {
        assert!(made(None, vec![]).impossible().is_none());
        let mut o = made(None, vec![]);
        o.coverage = Coverage::Impossible("because");
        assert_eq!(o.impossible(), Some("because"));
    }

    #[test]
    fn a_run_with_no_nulls_records_none() {
        let judge = Polyglot::default();
        let scale = Scale::build(&judge, 8, 2, &mut Rng::new(1));
        let ctx = Context {
            judge: &judge,
            scale: &scale,
            plan: Schedule::default(),
            seed: 1,
            keep: 1,
            focus: None,
            focus_scale: None,
            trace: &crate::trace::QUIET,
        };
        let outcome = run(
            &crate::attack::AffineSweep,
            &to_letters("ABCDEFGH"),
            &ctx,
            0,
        );
        assert!(outcome.null.is_empty());
        assert!(outcome.z().is_none());
    }

    #[test]
    fn a_run_records_one_null_per_shuffle_asked_for() {
        let judge = Polyglot::default();
        let scale = Scale::build(&judge, 8, 2, &mut Rng::new(1));
        let ctx = Context {
            judge: &judge,
            scale: &scale,
            plan: Schedule::default(),
            seed: 1,
            keep: 1,
            focus: None,
            focus_scale: None,
            trace: &crate::trace::QUIET,
        };
        let outcome = run(
            &crate::attack::AffineSweep,
            &to_letters("ABCDEFGH"),
            &ctx,
            5,
        );
        assert_eq!(outcome.null.len(), 5);
    }

    #[test]
    fn z_needs_a_null_to_exist() {
        let outcome = Outcome {
            name: "x".into(),
            family: "y",
            coverage: Coverage::Exhaustive(1),
            best: Vec::new(),
            null: Vec::new(),
        };
        assert!(outcome.z().is_none());
    }
}
