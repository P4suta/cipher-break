// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::rng::Rng;

const DEFAULT_STEPS: usize = 40_000;

const DEFAULT_RESTARTS: usize = 6;

const DEFAULT_HOT: f64 = 4.0;

const DEFAULT_COLD: f64 = 0.05;

#[derive(Clone, Copy, Debug)]
pub struct Schedule {
    pub steps: usize,
    pub restarts: usize,
    pub hot: f64,
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
    #[must_use]
    pub fn scaled(self, factor: f64) -> Self {
        Schedule {
            steps: ((self.steps as f64) * factor).round() as usize,
            restarts: ((self.restarts as f64) * factor).round().max(1.0) as usize,
            ..self
        }
    }
}

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

    fn trapped() -> (impl Fn(&i32) -> f64, impl FnMut(&mut i32, &mut Rng)) {
        let score = |x: &i32| match x {
            0 => 0.0,
            1 => 5.0,
            2 => -10.0,
            3 => 9.0,
            _ => -50.0,
        };
        let mv = |x: &mut i32, rng: &mut Rng| {
            *x = (*x + if rng.below(2) == 0 { 1 } else { 3 }) % 4;
        };
        (score, mv)
    }

    #[test]
    fn a_cold_schedule_never_leaves_the_first_peak() {
        let (score, mv) = trapped();
        let plan = Schedule {
            steps: 500,
            restarts: 1,
            hot: 0.0,
            cold: 0.0,
        };
        let (_, best) = anneal(1, score, mv, plan, &mut Rng::new(2));
        assert!((best - 5.0).abs() < 1e-9, "a cold run reached {best}");
    }

    #[test]
    fn a_hot_schedule_crosses_the_valley() {
        let (score, mv) = trapped();
        let plan = Schedule {
            steps: 2000,
            restarts: 1,
            hot: 20.0,
            cold: 0.01,
        };
        let (_, best) = anneal(1, score, mv, plan, &mut Rng::new(2));
        assert!((best - 9.0).abs() < 1e-9, "a hot run reached {best}");
    }

    #[test]
    fn the_best_seen_is_returned_even_when_the_walk_wanders_off() {
        let (score, mv) = trapped();
        let plan = Schedule {
            steps: 3000,
            restarts: 1,
            hot: 50.0,
            cold: 40.0,
        };
        let (state, best) = anneal(0, &score, mv, plan, &mut Rng::new(5));
        assert!(best >= 5.0, "the best seen was {best}");
        assert!(
            (score(&state) - best).abs() < 1e-9,
            "the state and its score disagree"
        );
    }

    #[test]
    fn a_single_step_proposes_once() {
        let calls = std::cell::Cell::new(0usize);
        let score = |_: &i32| 0.0;
        let mv = |_: &mut i32, _: &mut Rng| calls.set(calls.get() + 1);
        let plan = Schedule {
            steps: 1,
            restarts: 1,
            hot: 1.0,
            cold: 1.0,
        };
        let _ = anneal(0, score, mv, plan, &mut Rng::new(1));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn no_steps_proposes_nothing_and_keeps_the_start() {
        let score = |x: &i32| f64::from(*x);
        let mv = |x: &mut i32, _: &mut Rng| *x += 100;
        let plan = Schedule {
            steps: 0,
            restarts: 1,
            hot: 1.0,
            cold: 1.0,
        };
        let (state, best) = anneal(7, score, mv, plan, &mut Rng::new(1));
        assert_eq!(state, 7);
        assert!((best - 7.0).abs() < 1e-9);
    }

    #[test]
    fn scaling_multiplies_steps_and_restarts_and_leaves_the_temperatures() {
        let base = Schedule {
            steps: 100,
            restarts: 4,
            hot: 3.0,
            cold: 0.5,
        };
        let doubled = base.scaled(2.0);
        assert_eq!(doubled.steps, 200);
        assert_eq!(doubled.restarts, 8);
        assert!((doubled.hot - 3.0).abs() < 1e-12);
        assert!((doubled.cold - 0.5).abs() < 1e-12);
    }

    #[test]
    fn a_scaled_schedule_keeps_at_least_one_restart() {
        assert_eq!(Schedule::default().scaled(0.0).restarts, 1);
    }
}
