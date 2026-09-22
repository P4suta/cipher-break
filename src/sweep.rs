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
