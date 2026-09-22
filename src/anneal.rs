// SPDX-License-Identifier: MIT OR Apache-2.0

//! Simulated annealing, for the key spaces too large to enumerate.
//!
//! A keyed square has 25 factorial arrangements and can only ever be searched.
//! That changes what a result means: a search with this much freedom finds something that scores well in any text at all, including text with nothing in it.
//! Annealing earns its place here only alongside the same run on shuffled text.
//!
//! The temperatures have to match the scale of the score rather than look plausible on their own.
//! One swap in a square moves a bifid plaintext everywhere at once, so the steps in the score are large, and a schedule tuned for small ones never accepts an uphill move and is a greedy climb wearing a disguise.
//! That mistake cost this tool a working bifid attack until a planted key proved it was not working.

use crate::rng::Rng;

/// Moves a default run proposes.
///
/// Measured rather than chosen: a keyed bifid square over three hundred letters is recovered reliably at this many and unreliably at a quarter of it.
const DEFAULT_STEPS: usize = 40_000;

/// How many times a default run starts over.
const DEFAULT_RESTARTS: usize = 6;

/// The temperature a default run starts at.
///
/// It has to match the scale of the score, not look plausible on its own.
/// One swap in a square moves a bifid plaintext everywhere at once, so the steps in the score are whole units; a schedule that starts near a hundredth never accepts an uphill move and is a greedy climb wearing a disguise.
const DEFAULT_HOT: f64 = 4.0;

/// The temperature a default run ends at.
const DEFAULT_COLD: f64 = 0.05;

/// How long a run is, how often it starts over, and the temperatures it falls between.
#[derive(Clone, Copy, Debug)]
pub struct Schedule {
    /// Moves proposed per run.
    pub steps: usize,
    /// How many times to start over from a fresh random state.
    pub restarts: usize,
    /// The temperature a run starts at.
    pub hot: f64,
    /// The temperature a run ends at.
    pub cold: f64,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule {
            steps: DEFAULT_STEPS,
            restarts: DEFAULT_RESTARTS,
            hot: DEFAULT_HOT,
            cold: DEFAULT_COLD,
        }
    }
}

impl Schedule {
    /// A schedule scaled by an effort multiplier.
    #[must_use]
    pub fn scaled(self, factor: f64) -> Self {
        Schedule {
            steps: ((self.steps as f64) * factor).round() as usize,
            restarts: ((self.restarts as f64) * factor).round().max(1.0) as usize,
            ..self
        }
    }
}

/// Climb, accepting a worse state with a probability that falls over time.
///
/// Accepting a loss early is the whole point: these landscapes are rugged and a pure climb settles into the first hollow it meets.
pub fn anneal<S, F, M>(mut state: S, score: F, mut mv: M, plan: Schedule, rng: &mut Rng) -> (S, f64)
where
    S: Clone,
    F: Fn(&S) -> f64,
    M: FnMut(&mut S, &mut Rng),
{
    let mut current = score(&state);
    let mut best_state = state.clone();
    let mut best = current;
    let ratio = if plan.steps <= 1 || plan.hot <= 0.0 {
        1.0
    } else {
        (plan.cold / plan.hot).powf(1.0 / (plan.steps - 1) as f64)
    };
    let mut temperature = plan.hot;
    for _ in 0..plan.steps {
        let mut candidate = state.clone();
        mv(&mut candidate, rng);
        let value = score(&candidate);
        let accept = value >= current
            || (temperature > 0.0 && rng.unit() < ((value - current) / temperature).exp());
        if accept {
            state = candidate;
            current = value;
            if value > best {
                best = value;
                best_state = state.clone();
            }
        }
        temperature *= ratio;
    }
    (best_state, best)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_finds_the_maximum_of_a_simple_landscape() {
        let target: Vec<i32> = vec![3, 1, 4, 1, 5];
        let score = |xs: &Vec<i32>| -> f64 {
            -f64::from(
                xs.iter()
                    .zip(&target)
                    .map(|(a, b)| (a - b).abs())
                    .sum::<i32>(),
            )
        };
        let mv = |xs: &mut Vec<i32>, rng: &mut Rng| {
            let i = rng.below(xs.len());
            xs[i] = rng.below(6) as i32;
        };
        let plan = Schedule {
            steps: 20_000,
            restarts: 1,
            hot: 2.0,
            cold: 0.01,
        };
        let (_, best) = anneal(vec![0; 5], score, mv, plan, &mut Rng::new(1));
        assert!((best - 0.0).abs() < 1e-9, "best was {best}");
    }

    #[test]
    fn a_scaled_schedule_keeps_at_least_one_restart() {
        assert_eq!(Schedule::default().scaled(0.0).restarts, 1);
    }
}
