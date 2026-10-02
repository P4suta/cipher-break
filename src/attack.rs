// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::{ALPHABET, Letter, from_letters};
use crate::anneal::{Schedule, anneal};
use crate::bombe::{Menu, Positions, Scratch, Stop, scan_all_with, scan_with};
use crate::ciphers::enigma::{self, Enigma, Plugboard, Settings};
use crate::ciphers::{
    autokey, bifid, hill, periodic, playfair, porta, substitution, transposition,
};
#[cfg(feature = "gpu")]
use crate::enigma_types::Indicator;
use crate::enigma_types::Ring;
use crate::polyglot::{Polyglot, Scale};
use crate::rng::Rng;
use crate::square::{self, Square};
use crate::stats::index_of_coincidence;
use rayon::prelude::*;

pub struct Context<'a> {
    pub judge: &'a Polyglot,
    pub scale: &'a Scale,
    pub plan: Schedule,
    pub seed: u64,
    pub keep: usize,
    pub trace: &'a crate::trace::Trace,
    pub focus_scale: Option<&'a Scale>,
    pub focus: Option<&'a crate::ngram::Model>,
}

impl Context<'_> {
    #[inline]
    #[must_use]
    pub fn score(&self, plain: &[Letter]) -> f64 {
        match (self.focus, self.focus_scale) {
            (Some(model), Some(scale)) => scale.standardise(plain.len(), model.score(plain)),
            _ => self.scale.standardise(plain.len(), self.judge.score(plain)),
        }
    }

    #[inline]
    #[must_use]
    pub fn refine(&self, plain: &[Letter]) -> f64 {
        match self.focus {
            Some(model) => model.score(plain),
            None => self.score(plain),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    Exhaustive(u64),
    Searched(u64),
    Impossible(&'static str),
}

impl Coverage {
    #[must_use]
    pub fn keys(self) -> u64 {
        match self {
            Coverage::Exhaustive(n) | Coverage::Searched(n) => n,
            Coverage::Impossible(_) => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub score: f64,
    pub key: String,
    pub plain: Vec<Letter>,
}

pub trait Attack: Sync + Send {
    fn name(&self) -> String;

    fn family(&self) -> &'static str;

    fn coverage(&self, ct: &[Letter]) -> Coverage;

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate>;

    fn own_null(&self) -> Option<Vec<f64>> {
        None
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn coverage_reports_the_keys_it_will_look_at() {
        assert_eq!(Coverage::Exhaustive(1234).keys(), 1234);
        assert_eq!(Coverage::Searched(99).keys(), 99);
        assert_eq!(Coverage::Impossible("x").keys(), 0);
    }

    #[test]
    fn a_periodic_sweep_counts_three_families() {
        let ct = vec![0u8; 20];
        assert_eq!(
            PeriodicSweep { period: 2 }.coverage(&ct),
            Coverage::Exhaustive(3 * 26 * 26)
        );
    }

    #[test]
    fn a_porta_sweep_counts_in_thirteens() {
        let ct = vec![0u8; 20];
        assert_eq!(
            PortaSweep { period: 2 }.coverage(&ct),
            Coverage::Exhaustive(169)
        );
    }

    #[test]
    fn an_autokey_sweep_counts_six_variants() {
        let ct = vec![0u8; 20];
        assert_eq!(
            AutokeySweep { length: 1 }.coverage(&ct),
            Coverage::Exhaustive(6 * 26)
        );
    }

    #[test]
    fn a_columnar_sweep_counts_factorially() {
        let ct = vec![0u8; 20];
        assert_eq!(
            ColumnarSweep { width: 4 }.coverage(&ct),
            Coverage::Exhaustive(24)
        );
    }

    #[test]
    fn the_penalty_is_zero_for_a_board_with_no_leads() {
        assert!((penalised(5.0, 0, 70) - 5.0).abs() < 1e-12);
        assert!(penalised(5.0, 1, 70) < 5.0);
        assert!(penalised(5.0, 2, 70) < penalised(5.0, 1, 70));
    }

    #[test]
    fn the_plugboard_has_every_unordered_pair() {
        assert_eq!(PLUGBOARD_PAIRS, 325);
    }
}

#[derive(Clone, Debug)]
struct TopScores {
    keep: usize,
    items: Vec<(f64, u64)>,
}

impl TopScores {
    fn new(keep: usize) -> Self {
        TopScores {
            keep: keep.max(1),
            items: Vec::with_capacity(keep * 2 + 8),
        }
    }

    fn push(&mut self, score: f64, index: u64) {
        self.items.push((score, index));
        if self.items.len() >= self.keep * 4 + 16 {
            self.trim();
        }
    }

    fn trim(&mut self) {
        self.items.sort_unstable_by(|a, b| b.0.total_cmp(&a.0));
        self.items.truncate(self.keep);
    }

    fn merge(mut self, other: Self) -> Self {
        self.items.extend(other.items);
        self.trim();
        self
    }

    fn finish(mut self) -> Vec<(f64, u64)> {
        self.trim();
        self.items
    }
}

fn sweep_indices<F>(total: u64, keep: usize, width: usize, score: F) -> Vec<(f64, u64)>
where
    F: Fn(u64, &mut [Letter]) -> f64 + Sync,
{
    sweep_indices_with(total, keep, || vec![0u8; width], |i, buf| score(i, buf))
}

fn sweep_indices_with<S, M, F>(total: u64, keep: usize, make: M, score: F) -> Vec<(f64, u64)>
where
    S: Send,
    M: Fn() -> S + Sync + Send,
    F: Fn(u64, &mut S) -> f64 + Sync,
{
    (0..total)
        .into_par_iter()
        .fold(
            || (TopScores::new(keep), make()),
            |(mut top, mut state), i| {
                let s = score(i, &mut state);
                top.push(s, i);
                (top, state)
            },
        )
        .map(|(top, _)| top)
        .reduce(|| TopScores::new(keep), TopScores::merge)
        .finish()
}

pub const LEAD_MARGIN: f64 = 0.02;

pub const PLUGBOARD_PAIRS: usize = ALPHABET * (ALPHABET - 1) / 2;

pub const RERANK_DEPTH: usize = 60_000;

pub const HILL_KEYS: u64 = 157_248;

pub const COLUMNAR_WIDTHS: std::ops::RangeInclusive<usize> = 2..=8;

pub const SELECTION_STRIDES: std::ops::RangeInclusive<usize> = 2..=12;

pub const BIFID_PERIODS: std::ops::RangeInclusive<usize> = 1..=24;

pub const KEYED_BIFID_PERIODS: std::ops::RangeInclusive<usize> = 3..=16;

pub const CLIMB_MAX_PERIOD: usize = 16;

pub const CLIMB_RESTARTS: usize = 12;

pub const CPU_ENIGMA_SHORTLIST: usize = 400;

pub const ENIGMA_LEADS: usize = 10;

pub const MAX_KEY: usize = 16;

#[inline]
fn spell_key(mut index: u64, length: usize, out: &mut [Letter; MAX_KEY]) {
    for slot in out[..length].iter_mut().rev() {
        *slot = (index % ALPHABET as u64) as u8;
        index /= ALPHABET as u64;
    }
}

#[inline]
fn spell_digits(mut index: u64, length: usize, base: u64, out: &mut [usize; MAX_KEY]) {
    for slot in out[..length].iter_mut().rev() {
        *slot = (index % base) as usize;
        index /= base;
    }
}

pub struct PeriodicSweep {
    pub period: usize,
}

impl Attack for PeriodicSweep {
    fn name(&self) -> String {
        format!("vigenere period {}", self.period)
    }

    fn family(&self) -> &'static str {
        "periodic"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive(3 * (ALPHABET as u64).pow(self.period as u32))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let per_family = (ALPHABET as u64).pow(self.period as u32);
        let total = per_family * 3;
        let period = self.period;
        let decode = |index: u64, buf: &mut [Letter]| {
            let fam = periodic::FAMILIES[(index / per_family) as usize];
            let mut key = [0u8; MAX_KEY];
            spell_key(index % per_family, period, &mut key);
            periodic::decipher_into(fam, &key[..period], ct, buf);
            (fam, key)
        };
        let found = sweep_indices(total, ctx.keep, ct.len(), |index, buf| {
            decode(index, buf);
            ctx.score(buf)
        });
        found
            .into_iter()
            .map(|(score, index)| {
                let mut buf = vec![0u8; ct.len()];
                let (fam, key) = decode(index, &mut buf);
                Candidate {
                    score,
                    key: format!("{} {}", fam.name(), from_letters(&key[..period])),
                    plain: buf,
                }
            })
            .collect()
    }
}

pub struct PeriodicClimb {
    pub max_period: usize,
    pub restarts: usize,
}

impl Attack for PeriodicClimb {
    fn name(&self) -> String {
        format!("vigenere climb to period {}", self.max_period)
    }

    fn family(&self) -> &'static str {
        "periodic"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        let per = (self.restarts as u64 + 1) * ALPHABET as u64 * 4;
        Coverage::Searched(per * self.max_period as u64 * 3)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let jobs: Vec<(usize, periodic::Family, usize)> = (1..=self.max_period)
            .flat_map(|p| {
                periodic::FAMILIES
                    .into_iter()
                    .flat_map(move |f| (0..=self.restarts).map(move |r| (p, f, r)))
            })
            .collect();
        let mut found: Vec<Candidate> = jobs
            .par_iter()
            .map(|&(period, fam, restart)| {
                let mut rng = Rng::new(
                    ctx.seed
                        ^ ((period * 131 + restart) as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
                );
                let mut key: Vec<Letter> = if restart == 0 {
                    vec![0; period]
                } else {
                    (0..period).map(|_| rng.below(ALPHABET) as u8).collect()
                };
                let mut buf = vec![0u8; ct.len()];
                periodic::decipher_into(fam, &key, ct, &mut buf);
                let mut best = ctx.score(&buf);
                loop {
                    let mut improved = false;
                    for i in 0..period {
                        let original = key[i];
                        let mut chosen = original;
                        for candidate in 0..ALPHABET as u8 {
                            key[i] = candidate;
                            periodic::decipher_into(fam, &key, ct, &mut buf);
                            let s = ctx.score(&buf);
                            if s > best {
                                best = s;
                                chosen = candidate;
                                improved = true;
                            }
                        }
                        key[i] = chosen;
                    }
                    if !improved {
                        break;
                    }
                }
                periodic::decipher_into(fam, &key, ct, &mut buf);
                Candidate {
                    score: best,
                    key: format!("{} {}", fam.name(), from_letters(&key)),
                    plain: buf,
                }
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

pub struct PortaSweep {
    pub period: usize,
}

impl Attack for PortaSweep {
    fn name(&self) -> String {
        format!("porta period {}", self.period)
    }

    fn family(&self) -> &'static str {
        "periodic"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive((porta::TABLES as u64).pow(self.period as u32))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let total = (porta::TABLES as u64).pow(self.period as u32);
        let period = self.period;
        let found = sweep_indices(total, ctx.keep, ct.len(), |index, buf| {
            let mut tables = [0usize; MAX_KEY];
            spell_digits(index, period, porta::TABLES as u64, &mut tables);
            porta::apply_into(&tables[..period], ct, buf);
            ctx.score(buf)
        });
        found
            .into_iter()
            .map(|(score, index)| {
                let mut tables = [0usize; MAX_KEY];
                spell_digits(index, period, porta::TABLES as u64, &mut tables);
                let plain = porta::apply(&tables[..period], ct);
                let key = tables[..period]
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("-");
                Candidate { score, key, plain }
            })
            .collect()
    }
}

pub struct AutokeySweep {
    pub length: usize,
}

impl Attack for AutokeySweep {
    fn name(&self) -> String {
        format!("autokey primer {}", self.length)
    }

    fn family(&self) -> &'static str {
        "autokey"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive(6 * (ALPHABET as u64).pow(self.length as u32))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let per = (ALPHABET as u64).pow(self.length as u32);
        let total = per * 6;
        let length = self.length;
        let decode = |index: u64| {
            let variant = (index / per) as usize;
            let mode = autokey::PRIMINGS[variant / 3];
            let fam = periodic::FAMILIES[variant % 3];
            let mut primer = [0u8; MAX_KEY];
            spell_key(index % per, length, &mut primer);
            (mode, fam, primer)
        };
        let found = sweep_indices(total, ctx.keep, ct.len(), |index, buf| {
            let (mode, fam, primer) = decode(index);
            autokey::decipher_into(mode, fam, &primer[..length], ct, buf);
            ctx.score(buf)
        });
        found
            .into_iter()
            .map(|(score, index)| {
                let (mode, fam, primer) = decode(index);
                let plain = autokey::decipher(mode, fam, &primer[..length], ct);
                Candidate {
                    score,
                    key: format!(
                        "{} {} {}",
                        mode.name(),
                        fam.name(),
                        from_letters(&primer[..length])
                    ),
                    plain,
                }
            })
            .collect()
    }
}

pub struct HillSweep;

impl Attack for HillSweep {
    fn name(&self) -> String {
        "hill 2x2".into()
    }

    fn family(&self) -> &'static str {
        "polygraphic"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive(HILL_KEYS)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let keys = hill::matrices();
        let found = sweep_indices(keys.len() as u64, ctx.keep, ct.len(), |index, buf| {
            keys[index as usize].apply_into(ct, buf);
            ctx.score(buf)
        });
        found
            .into_iter()
            .map(|(score, index)| {
                let m = keys[index as usize];
                Candidate {
                    score,
                    key: m.to_string(),
                    plain: m.apply(ct),
                }
            })
            .collect()
    }
}

pub struct AffineSweep;

impl Attack for AffineSweep {
    fn name(&self) -> String {
        "affine and caesar".into()
    }

    fn family(&self) -> &'static str {
        "monoalphabetic"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive(312)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = substitution::affine_keys()
            .into_par_iter()
            .map(|(name, key)| {
                let plain = substitution::apply(&key, ct);
                Candidate {
                    score: ctx.score(&plain),
                    key: name,
                    plain,
                }
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

pub struct SubstitutionAnneal;

impl Attack for SubstitutionAnneal {
    fn name(&self) -> String {
        "simple substitution".into()
    }

    fn family(&self) -> &'static str {
        "monoalphabetic"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Searched(0)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = (0..ctx.plan.restarts)
            .into_par_iter()
            .map(|restart| {
                let mut rng = Rng::new(
                    ctx.seed ^ (restart as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5,
                );
                let start = substitution::random(&mut rng);
                let (key, score) = anneal(
                    start,
                    |k| ctx.score(&substitution::apply(k, ct)),
                    substitution::perturb,
                    ctx.plan,
                    &mut rng,
                );
                Candidate {
                    score,
                    key: from_letters(&key),
                    plain: substitution::apply(&key, ct),
                }
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

pub struct ColumnarSweep {
    pub width: usize,
}

impl Attack for ColumnarSweep {
    fn name(&self) -> String {
        format!("columnar transposition width {}", self.width)
    }

    fn family(&self) -> &'static str {
        "transposition"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive((1..=self.width as u64).product())
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let keys = transposition::permutations(self.width);
        let mut found: Vec<Candidate> = keys
            .into_par_iter()
            .map(|key| {
                let plain = transposition::columnar(&key, ct);
                let label = key
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("-");
                Candidate {
                    score: ctx.score(&plain),
                    key: label,
                    plain,
                }
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

pub struct RailFenceSweep;

impl Attack for RailFenceSweep {
    fn name(&self) -> String {
        "rail fence".into()
    }

    fn family(&self) -> &'static str {
        "transposition"
    }

    fn coverage(&self, ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive((ct.len() / 2).saturating_sub(1) as u64)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = (2..=(ct.len() / 2).max(2))
            .into_par_iter()
            .map(|rails| {
                let plain = transposition::rail_fence(rails, ct);
                Candidate {
                    score: ctx.score(&plain),
                    key: format!("{rails} rails"),
                    plain,
                }
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

pub struct SelectionSweep;

impl Attack for SelectionSweep {
    fn name(&self) -> String {
        "null cipher: every nth letter".into()
    }

    fn family(&self) -> &'static str {
        "concealment"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive(2 * SELECTION_STRIDES.map(|k| k as u64).sum::<u64>())
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = SELECTION_STRIDES
            .flat_map(|k| (0..k).map(move |j| (k, j)))
            .collect::<Vec<_>>()
            .into_par_iter()
            .flat_map(|(k, j)| {
                let taken: Vec<Letter> = ct.iter().skip(j).step_by(k).copied().collect();
                let backwards: Vec<Letter> = taken.iter().rev().copied().collect();
                vec![
                    Candidate {
                        score: ctx.score(&taken),
                        key: format!("every {k} from {j}"),
                        plain: taken,
                    },
                    Candidate {
                        score: ctx.score(&backwards),
                        key: format!("every {k} from {j}, reversed"),
                        plain: backwards,
                    },
                ]
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

pub struct BifidPlain;

impl Attack for BifidPlain {
    fn name(&self) -> String {
        "bifid, unkeyed square".into()
    }

    fn family(&self) -> &'static str {
        "fractionating"
    }

    fn coverage(&self, ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive(square::omissions_for(ct).len() as u64 * BIFID_PERIODS.count() as u64)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let jobs: Vec<(Letter, usize)> = square::omissions_for(ct)
            .into_iter()
            .flat_map(|m| BIFID_PERIODS.map(move |p| (m, p)))
            .collect();
        let mut found: Vec<Candidate> = jobs
            .into_par_iter()
            .map(|(missing, period)| {
                let sq = square::omitting(missing);
                let plain = bifid::decipher(period, &sq, ct);
                Candidate {
                    score: ctx.score(&plain),
                    key: format!(
                        "omits {} period {period}",
                        crate::alphabet::letter_char(missing)
                    ),
                    plain,
                }
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

pub struct BifidAnneal {
    pub period: usize,
}

impl Attack for BifidAnneal {
    fn name(&self) -> String {
        format!("bifid keyed square, period {}", self.period)
    }

    fn family(&self) -> &'static str {
        "fractionating"
    }

    fn coverage(&self, ct: &[Letter]) -> Coverage {
        if square::omissions_for(ct).is_empty() {
            return Coverage::Impossible(
                "the ciphertext uses all 26 letters, so no 25-letter square fits",
            );
        }
        Coverage::Searched(0)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let period = self.period;
        let jobs: Vec<(Letter, usize)> = square::omissions_for(ct)
            .into_iter()
            .flat_map(|m| (0..ctx.plan.restarts).map(move |r| (m, r)))
            .collect();
        let mut found: Vec<Candidate> = jobs
            .into_par_iter()
            .map(|(missing, restart)| {
                let mut rng = Rng::new(
                    ctx.seed
                        ^ ((period * 2003 + missing as usize * 37 + restart) as u64)
                            .wrapping_mul(0x9E37_79B9_7F4A_7C15),
                );
                let start = square::random(missing, &mut rng);
                let mut scratch = vec![0u8; ct.len()];
                let (sq, score) = anneal(
                    start,
                    |s: &Square| {
                        let mut buf = vec![0u8; ct.len()];
                        bifid::decipher_into(period, s, ct, &mut buf);
                        ctx.score(&buf)
                    },
                    square::perturb,
                    ctx.plan,
                    &mut rng,
                );
                bifid::decipher_into(period, &sq, ct, &mut scratch);
                Candidate {
                    score,
                    key: format!(
                        "omits {} {}",
                        crate::alphabet::letter_char(missing),
                        from_letters(&sq)
                    ),
                    plain: scratch,
                }
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

pub struct PlayfairAnneal;

impl Attack for PlayfairAnneal {
    fn name(&self) -> String {
        "playfair".into()
    }

    fn family(&self) -> &'static str {
        "polygraphic"
    }

    fn coverage(&self, ct: &[Letter]) -> Coverage {
        if !playfair::possible(ct) {
            return Coverage::Impossible(
                "a digraph of two equal letters, which Playfair cannot emit",
            );
        }
        if square::omissions_for(ct).is_empty() {
            return Coverage::Impossible(
                "the ciphertext uses all 26 letters, so no 25-letter square fits",
            );
        }
        Coverage::Searched(0)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        if !playfair::possible(ct) {
            return Vec::new();
        }
        let jobs: Vec<(Letter, usize)> = square::omissions_for(ct)
            .into_iter()
            .flat_map(|m| (0..ctx.plan.restarts).map(move |r| (m, r)))
            .collect();
        let mut found: Vec<Candidate> = jobs
            .into_par_iter()
            .map(|(missing, restart)| {
                let mut rng = Rng::new(
                    ctx.seed
                        ^ ((missing as usize * 61 + restart) as u64)
                            .wrapping_mul(0x9E37_79B9_7F4A_7C15),
                );
                let start = square::random(missing, &mut rng);
                let (sq, score) = anneal(
                    start,
                    |s: &Square| {
                        let mut buf = vec![0u8; ct.len()];
                        playfair::decipher_into(s, ct, &mut buf);
                        ctx.score(&buf)
                    },
                    square::perturb,
                    ctx.plan,
                    &mut rng,
                );
                Candidate {
                    score,
                    key: format!(
                        "omits {} {}",
                        crate::alphabet::letter_char(missing),
                        from_letters(&sq)
                    ),
                    plain: playfair::decipher(&sq, ct),
                }
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

pub struct FourSquareAnneal;

impl Attack for FourSquareAnneal {
    fn name(&self) -> String {
        "four-square".into()
    }

    fn family(&self) -> &'static str {
        "polygraphic"
    }

    fn coverage(&self, ct: &[Letter]) -> Coverage {
        if square::omissions_for(ct).is_empty() {
            return Coverage::Impossible(
                "the ciphertext uses all 26 letters, so no 25-letter square fits",
            );
        }
        Coverage::Searched(0)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let jobs: Vec<(Letter, usize)> = square::omissions_for(ct)
            .into_iter()
            .flat_map(|m| (0..ctx.plan.restarts).map(move |r| (m, r)))
            .collect();
        let mut found: Vec<Candidate> = jobs
            .into_par_iter()
            .map(|(missing, restart)| {
                let mut rng = Rng::new(
                    ctx.seed
                        ^ ((missing as usize * 97 + restart) as u64)
                            .wrapping_mul(0x9E37_79B9_7F4A_7C15),
                );
                let plain = square::omitting(missing);
                let start = (
                    square::random(missing, &mut rng),
                    square::random(missing, &mut rng),
                );
                let ((tr, bl), score) = anneal(
                    start,
                    |(a, b): &(Square, Square)| {
                        let mut buf = vec![0u8; ct.len()];
                        playfair::decipher_four_into(a, b, &plain, ct, &mut buf);
                        ctx.score(&buf)
                    },
                    |(a, b): &mut (Square, Square), rng: &mut Rng| {
                        if rng.below(2) == 0 {
                            square::perturb(a, rng);
                        } else {
                            square::perturb(b, rng);
                        }
                    },
                    ctx.plan,
                    &mut rng,
                );
                let mut buf = vec![0u8; ct.len()];
                playfair::decipher_four_into(&tr, &bl, &plain, ct, &mut buf);
                Candidate {
                    score,
                    key: format!(
                        "omits {} {} / {}",
                        crate::alphabet::letter_char(missing),
                        from_letters(&tr),
                        from_letters(&bl)
                    ),
                    plain: buf,
                }
            })
            .collect();
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(ctx.keep);
        found
    }
}

#[cfg(feature = "gpu")]
pub struct GpuPeriodicSweep {
    pub period: usize,
    pub gpu: std::sync::Arc<crate::gpu::Gpu>,
}

#[cfg(feature = "gpu")]
impl Attack for GpuPeriodicSweep {
    fn name(&self) -> String {
        format!("vigenere period {} (gpu)", self.period)
    }

    fn family(&self) -> &'static str {
        "periodic"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Exhaustive(3 * (ALPHABET as u64).pow(self.period as u32))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let found = self.gpu.sweep_periodic(
            ct,
            ctx.judge.table(),
            ctx.judge.langs(),
            ctx.judge.order(),
            self.period,
            ctx.keep,
        );
        let mut out: Vec<Candidate> = found
            .into_iter()
            .map(|(_, fam, key)| {
                let plain = periodic::decipher(fam, &key, ct);
                Candidate {
                    score: ctx.score(&plain),
                    key: format!("{} {}", fam.name(), from_letters(&key)),
                    plain,
                }
            })
            .collect();
        out.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        out
    }
}

pub struct EnigmaAttack {
    pub rotors_available: usize,
    pub shortlist: usize,
    pub leads: usize,
}

#[must_use]
pub fn climb_plugboard(
    settings: Settings,
    reflector: [u8; ALPHABET],
    leads: usize,
    margin: f64,
    ct: &[Letter],
    ctx: &Context,
) -> (Plugboard, f64, Vec<Letter>) {
    let mut board = Plugboard::empty();
    let mut machine = Enigma::with_reflector(settings, reflector, board);
    let mut buf = vec![0u8; ct.len()];
    machine.run_into(ct, &mut buf);
    let mut best = ctx.refine(&buf);
    let mut best_plain = buf.clone();
    for _ in 0..leads {
        let mut improved = None;
        for a in 0..ALPHABET as u8 {
            for b in (a + 1)..ALPHABET as u8 {
                let mut trial = board;
                trial.connect(a, b);
                if trial.pairs().len() > leads {
                    continue;
                }
                machine.aim(settings, reflector);
                machine.replug(trial);
                machine.run_into(ct, &mut buf);
                let s = ctx.refine(&buf);
                if s > best + margin {
                    best = s;
                    improved = Some((a, b));
                    best_plain.copy_from_slice(&buf);
                }
            }
        }
        match improved {
            Some((a, b)) => board.connect(a, b),
            None => break,
        }
    }

    loop {
        let mut improved = None;
        for (x, y) in board.pairs() {
            let mut without = board;
            without.disconnect(x);
            for a in 0..ALPHABET as u8 {
                for b in (a + 1)..ALPHABET as u8 {
                    let mut trial = without;
                    trial.connect(a, b);
                    if trial.pairs().len() > leads {
                        continue;
                    }
                    machine.aim(settings, reflector);
                    machine.replug(trial);
                    machine.run_into(ct, &mut buf);
                    let s = ctx.refine(&buf);
                    if s > best + margin {
                        best = s;
                        improved = Some(trial);
                        best_plain.copy_from_slice(&buf);
                    }
                }
            }
            let _ = (x, y);
        }
        match improved {
            Some(better) => board = better,
            None => break,
        }
    }

    (board, ctx.score(&best_plain), best_plain)
}

fn refine_rings(
    settings: Settings,
    reflector: [u8; ALPHABET],
    ct: &[Letter],
    ctx: &Context,
    board: Plugboard,
) -> (Settings, f64) {
    let side = ALPHABET as u8;
    let held = [
        settings.positions[0].against(settings.rings[0]),
        settings.positions[1].against(settings.rings[1]),
        settings.positions[2].against(settings.rings[2]),
    ];
    let mut machine = Enigma::with_reflector(settings, reflector, board);
    let mut buf = vec![0u8; ct.len()];
    machine.run_into(ct, &mut buf);
    let mut best = (settings, ctx.refine(&buf));
    for middle in 0..side {
        for right in 0..side {
            let (middle, right) = (Ring::new(middle), Ring::new(right));
            let trial = Settings {
                rings: [settings.rings[0], middle, right],
                positions: [
                    settings.positions[0],
                    held[1].with_ring(middle),
                    held[2].with_ring(right),
                ],
                ..settings
            };
            machine.aim(trial, reflector);
            machine.replug(board);
            machine.run_into(ct, &mut buf);
            let s = ctx.refine(&buf);
            if s > best.1 {
                best = (trial, s);
            }
        }
    }
    best
}

fn finish_enigma(
    settings: Settings,
    reflector: [u8; ALPHABET],
    leads: usize,
    ct: &[Letter],
    ctx: &Context,
) -> (Settings, Plugboard, f64, Vec<Letter>) {
    let (board, _, _) = climb_plugboard(settings, reflector, leads, LEAD_MARGIN, ct, ctx);
    let (tuned, _) = refine_rings(settings, reflector, ct, ctx, board);
    let (board, score, plain) = climb_plugboard(tuned, reflector, leads, 0.0, ct, ctx);
    (tuned, board, score, plain)
}

#[must_use]
pub fn penalised(score: f64, leads: usize, grams: usize) -> f64 {
    score - (PLUGBOARD_PAIRS as f64).ln() / grams.max(1) as f64 * leads as f64
}

#[cfg(feature = "gpu")]
fn describe_hits<'a, I>(
    orders: &[[usize; 3]],
    named: &[(String, [u8; ALPHABET])],
    hits: I,
) -> String
where
    I: Iterator<Item = (&'a crate::gpu::EnigmaHit, f64)>,
{
    hits.map(|(h, score)| {
        format!(
            "{:?}{} ring {} start {} {score:.4}",
            orders[h.order].map(|r| r + 1),
            named[h.reflector].0,
            crate::alphabet::letter_char(h.ring.value()),
            from_letters(&h.positions.map(Indicator::value))
        )
    })
    .collect::<Vec<_>>()
    .join(" | ")
}

fn rank_enigma(mut found: Vec<(Candidate, usize)>, grams: usize, keep: usize) -> Vec<Candidate> {
    found.sort_unstable_by(|a, b| {
        penalised(b.0.score, b.1, grams).total_cmp(&penalised(a.0.score, a.1, grams))
    });
    found
        .into_iter()
        .map(|(candidate, _)| candidate)
        .take(keep.max(1))
        .collect()
}

#[must_use]
pub fn describe_leads(board: &Plugboard) -> String {
    let leads: Vec<String> = board
        .pairs()
        .iter()
        .map(|&(a, b)| {
            format!(
                "{}{}",
                crate::alphabet::letter_char(a),
                crate::alphabet::letter_char(b)
            )
        })
        .collect();
    if leads.is_empty() {
        "none".to_string()
    } else {
        leads.join(" ")
    }
}

impl Attack for EnigmaAttack {
    fn name(&self) -> String {
        format!("enigma, {} rotors", self.rotors_available)
    }

    fn family(&self) -> &'static str {
        "rotor"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        let orders = enigma::rotor_orders(self.rotors_available).len() as u64;
        Coverage::Searched(orders * 2 * (ALPHABET as u64).pow(3))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let orders = enigma::rotor_orders(self.rotors_available);
        let positions = (ALPHABET as u64).pow(3);
        let total = orders.len() as u64 * 2 * positions;

        let decode = |index: u64| {
            let order = orders[(index / (2 * positions)) as usize];
            let reflector = ((index / positions) % 2) as usize;
            let p = index % positions;
            Settings::at(
                order,
                reflector,
                [0; 3],
                [
                    (p / (ALPHABET as u64 * ALPHABET as u64)) as u8,
                    ((p / ALPHABET as u64) % ALPHABET as u64) as u8,
                    (p % ALPHABET as u64) as u8,
                ],
            )
        };
        let found = sweep_indices_with(
            total,
            self.shortlist,
            || {
                (
                    Enigma::new(decode(0), Plugboard::empty()),
                    vec![0u8; ct.len()],
                )
            },
            |index, (machine, buf)| {
                let settings = decode(index);
                machine.aim(settings, enigma::reflector_wiring(settings.reflector));
                machine.run_into(ct, buf);
                ctx.score(buf)
            },
        );

        let grams = ct.len().saturating_sub(2).max(1);
        let scored: Vec<(Candidate, usize)> = found
            .par_iter()
            .map(|&(_, index)| {
                let found = decode(index);
                let reflector = enigma::reflector_wiring(found.reflector);
                let (settings, board, score, plain) =
                    finish_enigma(found, reflector, self.leads, ct, ctx);
                (
                    Candidate {
                        score,
                        key: format!(
                            "rotors {:?} reflector {} rings {} start {} plugs {}",
                            settings.rotors.map(|r| r + 1),
                            if settings.reflector == 0 { "B" } else { "C" },
                            from_letters(&settings.ring_letters()),
                            from_letters(&settings.position_letters()),
                            describe_leads(&board)
                        ),
                        plain,
                    },
                    board.pairs().len(),
                )
            })
            .collect();
        rank_enigma(scored, grams, ctx.keep)
    }
}

pub struct EnigmaNaval {
    pub shortlist: usize,
    pub leads: usize,
    pub focus: Option<String>,
}

impl Attack for EnigmaNaval {
    fn name(&self) -> String {
        match &self.focus {
            Some(language) => format!("enigma M4 naval ({language})"),
            None => "enigma M4 naval".to_string(),
        }
    }

    fn family(&self) -> &'static str {
        "rotor"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        let orders = enigma::rotor_orders(enigma::ROTOR_COUNT).len() as u64;
        Coverage::Searched(orders * enigma::NAVAL_REFLECTOR_COUNT as u64 * (ALPHABET as u64).pow(3))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let orders = enigma::rotor_orders(enigma::ROTOR_COUNT);
        let reflectors = enigma::naval_reflectors();
        let positions = (ALPHABET as u64).pow(3);
        let per_order = reflectors.len() as u64 * positions;
        let total = orders.len() as u64 * per_order;

        let decode = |index: u64| {
            let order = orders[(index / per_order) as usize];
            let reflector = ((index % per_order) / positions) as usize;
            let p = index % positions;
            (
                reflector,
                Settings::at(
                    order,
                    0,
                    [0; 3],
                    [
                        (p / (ALPHABET as u64 * ALPHABET as u64)) as u8,
                        ((p / ALPHABET as u64) % ALPHABET as u64) as u8,
                        (p % ALPHABET as u64) as u8,
                    ],
                ),
            )
        };

        let steer = self
            .focus
            .as_deref()
            .and_then(|name| ctx.judge.model_named(name));
        let found = sweep_indices_with(
            total,
            self.shortlist,
            || {
                let (r, settings) = decode(0);
                (
                    Enigma::with_reflector(settings, reflectors[r].1, Plugboard::empty()),
                    vec![0u8; ct.len()],
                )
            },
            |index, (machine, buf)| {
                let (reflector, settings) = decode(index);
                machine.aim(settings, reflectors[reflector].1);
                machine.run_into(ct, buf);
                match steer {
                    Some(model) => model.score(buf),
                    None => ctx.score(buf),
                }
            },
        );

        let scored: Vec<(Candidate, usize)> = found
            .par_iter()
            .map(|&(_, index)| {
                let (reflector, found) = decode(index);
                let (settings, board, score, plain) =
                    finish_enigma(found, reflectors[reflector].1, self.leads, ct, ctx);
                (
                    Candidate {
                        score,
                        key: format!(
                            "rotors {:?} {} rings {} start {} plugs {}",
                            settings.rotors.map(|r| r + 1),
                            reflectors[reflector].0,
                            from_letters(&settings.ring_letters()),
                            from_letters(&settings.position_letters()),
                            describe_leads(&board)
                        ),
                        plain,
                    },
                    board.pairs().len(),
                )
            })
            .collect();
        rank_enigma(scored, ct.len().saturating_sub(2).max(1), ctx.keep)
    }
}

#[cfg(feature = "gpu")]
pub struct GpuEnigmaNaval {
    pub shortlist: usize,
    pub leads: usize,
    pub focus: String,
    pub rings: usize,
    pub middles: usize,
    pub finish: usize,
    pub gpu: std::sync::Arc<crate::gpu::Gpu>,
}

#[cfg(feature = "gpu")]
fn rerank_on(
    ctx: &Context,
    ct: &[Letter],
    ranked: &[(f64, usize)],
    found: &[crate::gpu::EnigmaHit],
    boards: &[(f64, [u8; ALPHABET])],
    orders: &[[usize; 3]],
    wirings: &[[u8; ALPHABET]],
) -> Vec<(f64, usize)> {
    let Some(sharper) = ctx.focus else {
        return ranked.to_vec();
    };
    let deep = RERANK_DEPTH.min(ranked.len());
    let grams = (ct.len() + 1).saturating_sub(sharper.order()).max(1);
    let cost = (PLUGBOARD_PAIRS as f64).ln() / grams as f64;
    let mut out: Vec<(f64, usize)> = ranked[..deep]
        .par_iter()
        .map(|&(_, i)| {
            let hit = found[i];
            let settings = Settings {
                rotors: orders[hit.order],
                reflector: 0,
                rings: [Ring::new(0), hit.middle, hit.ring],
                positions: hit.positions,
            };
            let board = Plugboard::from_mapping(boards[i].1);
            let plain = Enigma::with_reflector(settings, wirings[hit.reflector], board).run(ct);
            (sharper.score(&plain) - cost * board.pairs().len() as f64, i)
        })
        .collect();
    out.sort_unstable_by(|a, b| b.0.total_cmp(&a.0));
    out
}

#[cfg(feature = "gpu")]
impl Attack for GpuEnigmaNaval {
    fn name(&self) -> String {
        let rings = if self.rings <= 1 {
            "ring A"
        } else {
            "all rings"
        };
        format!("enigma M4 naval ({}, {rings}) (gpu)", self.focus)
    }

    fn family(&self) -> &'static str {
        "rotor"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Searched(
            enigma::rotor_orders(enigma::ROTOR_COUNT).len() as u64
                * enigma::NAVAL_REFLECTOR_COUNT as u64
                * self.rings as u64
                * (ALPHABET as u64).pow(3),
        )
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let Some(model) = ctx.judge.model_named(&self.focus) else {
            return Vec::new();
        };
        let orders = enigma::rotor_orders(enigma::ROTOR_COUNT);
        let named = enigma::naval_reflectors();
        let wirings: Vec<[u8; ALPHABET]> = named.iter().map(|(_, r)| *r).collect();
        let job = crate::gpu::EnigmaJob {
            ct,
            logp: model.log_table(),
            order: model.order(),
            orders: &orders,
            reflectors: &wirings,
            rings: self.rings,
            middles: self.middles,
            keep: self.shortlist,
        };
        let found = self.gpu.sweep_enigma(&job);

        let boards = self
            .gpu
            .climb_plugboards(&job, &found, self.leads, LEAD_MARGIN as f32);
        let grams = (ct.len() + 1).saturating_sub(model.order()).max(1);
        let lead_cost = (PLUGBOARD_PAIRS as f64).ln() / grams as f64;
        ctx.trace.note("naval/sweep", || {
            let head = describe_hits(&orders, &named, found.iter().take(8).map(|h| (h, h.score)));
            format!("kept {}, best: {head}", found.len())
        });

        let mut ranked: Vec<(f64, usize)> = boards
            .iter()
            .enumerate()
            .map(|(i, &(score, mapping))| {
                let used = Plugboard::from_mapping(mapping).pairs().len();
                (score - lead_cost * used as f64, i)
            })
            .collect();
        ranked.sort_unstable_by(|a, b| b.0.total_cmp(&a.0));

        ranked = rerank_on(ctx, ct, &ranked, &found, &boards, &orders, &wirings);

        ctx.trace.note("naval/climb", || {
            let head = describe_hits(
                &orders,
                &named,
                ranked
                    .iter()
                    .take(8)
                    .map(|&(penalty, i)| (&found[i], penalty)),
            );
            format!("climbed {}, best: {head}", ranked.len())
        });
        ranked.truncate(self.finish.max(1));

        let out: Vec<(Candidate, usize)> = ranked
            .par_iter()
            .map(|&(_, i)| {
                let hit = found[i];
                let settings = Settings {
                    rotors: orders[hit.order],
                    reflector: 0,
                    rings: [Ring::new(0), hit.middle, hit.ring],
                    positions: hit.positions,
                };
                let (tuned, board, score, plain) =
                    finish_enigma(settings, wirings[hit.reflector], self.leads, ct, ctx);
                (
                    Candidate {
                        score,
                        key: format!(
                            "rotors {:?} {} rings {} start {} plugs {}",
                            tuned.rotors.map(|r| r + 1),
                            named[hit.reflector].0,
                            from_letters(&tuned.ring_letters()),
                            from_letters(&tuned.position_letters()),
                            describe_leads(&board)
                        ),
                        plain,
                    },
                    board.pairs().len(),
                )
            })
            .collect();
        let ranked = rank_enigma(out, grams, ctx.keep);
        ctx.trace.note("naval/finish", || {
            ranked
                .iter()
                .take(4)
                .map(|c| format!("{:+.2}s {}", c.score, c.key))
                .collect::<Vec<_>>()
                .join(" | ")
        });
        ranked
    }
}

pub struct BombeAttack {
    #[cfg(feature = "gpu")]
    pub gpu: Option<std::sync::Arc<crate::gpu::Gpu>>,
    pub stops: std::sync::atomic::AtomicU64,
    pub finished: std::sync::atomic::AtomicU64,
    pub shapes: std::sync::Mutex<Vec<(Plugboard, u32)>>,
    pub crib: Vec<Letter>,
    pub label: String,
    pub rotors_available: usize,
    pub naval: bool,
    pub rings: bool,
    pub middles: bool,
    pub at: Option<usize>,
    pub finish: usize,
}

fn reflectors_for(naval: bool) -> Vec<(String, [u8; ALPHABET])> {
    if naval {
        enigma::naval_reflectors()
    } else {
        (0..enigma::REFLECTOR_COUNT)
            .map(|i| {
                let name = if i == 0 { "B" } else { "C" };
                (name.to_string(), enigma::reflector_wiring(i))
            })
            .collect()
    }
}

const STOPS_BEFORE_SIFTING: usize = 64;

fn sift(stops: &mut Vec<Pending>, keep: usize) {
    stops.sort_unstable_by(|a, b| b.partial.total_cmp(&a.partial));
    stops.truncate(keep);
}

#[must_use]
pub fn score_outside_the_crib(plain: &[Letter], ctx: &Context, offset: usize, len: usize) -> f64 {
    let end = (offset + len).min(plain.len());
    if offset >= plain.len() || end <= offset {
        return ctx.score(plain);
    }
    let mut rest: Vec<Letter> = Vec::with_capacity(plain.len() - (end - offset));
    rest.extend_from_slice(&plain[..offset]);
    rest.extend_from_slice(&plain[end..]);
    if rest.is_empty() {
        return f64::NEG_INFINITY;
    }
    ctx.score(&rest)
}

pub const BOMBE_FINISH: usize = 200_000;

const SHAPES_KEPT: usize = 1_024;

#[derive(Clone, Copy, Debug)]
struct Pending {
    partial: f64,
    settings: Settings,
    reflector: usize,
    menu: usize,
}

fn climb_free(
    settings: Settings,
    reflector: [u8; ALPHABET],
    (forced, known): (Plugboard, u32),
    leads: usize,
    margin: f64,
    ct: &[Letter],
    ctx: &Context,
) -> Plugboard {
    let open = |board: &Plugboard, l: u8| (known >> l) & 1 == 0 && board.map(l) == l;
    let mut board = forced;
    let mut machine = Enigma::with_reflector(settings, reflector, board);
    let mut buf = vec![0u8; ct.len()];
    machine.run_into(ct, &mut buf);
    let mut best = ctx.refine(&buf);
    let mut grown: Vec<(Letter, Letter)> = Vec::new();
    while board.pairs().len() < leads {
        let mut improved = None;
        for a in 0..ALPHABET as u8 {
            if !open(&board, a) {
                continue;
            }
            for b in (a + 1)..ALPHABET as u8 {
                if !open(&board, b) {
                    continue;
                }
                let mut trial = board;
                trial.connect(a, b);
                machine.aim(settings, reflector);
                machine.replug(trial);
                machine.run_into(ct, &mut buf);
                let s = ctx.refine(&buf);
                if s > best + margin {
                    best = s;
                    improved = Some((a, b));
                }
            }
        }
        let Some((a, b)) = improved else { break };
        board.connect(a, b);
        grown.push((a, b));
    }
    loop {
        let mut improved: Option<(usize, Plugboard, (Letter, Letter))> = None;
        for (i, &(x, _)) in grown.iter().enumerate() {
            let mut without = board;
            without.disconnect(x);
            for a in 0..ALPHABET as u8 {
                if !open(&without, a) {
                    continue;
                }
                for b in (a + 1)..ALPHABET as u8 {
                    if !open(&without, b) {
                        continue;
                    }
                    let mut trial = without;
                    trial.connect(a, b);
                    machine.aim(settings, reflector);
                    machine.replug(trial);
                    machine.run_into(ct, &mut buf);
                    let s = ctx.refine(&buf);
                    if s > best + margin {
                        best = s;
                        improved = Some((i, trial, (a, b)));
                    }
                }
            }
        }
        let Some((i, better, lead)) = improved else {
            break;
        };
        board = better;
        grown[i] = lead;
    }
    board
}

fn best_rings(
    settings: Settings,
    reflector: [u8; ALPHABET],
    board: Plugboard,
    reach: usize,
    ct: &[Letter],
    ctx: &Context,
) -> Settings {
    let traced =
        |s: Settings| Enigma::with_reflector(s, reflector, Plugboard::empty()).offset_trace(reach);
    let over_the_crib = traced(settings);
    let held = [
        settings.positions[1].against(settings.rings[1]),
        settings.positions[2].against(settings.rings[2]),
    ];
    let mut machine = Enigma::with_reflector(settings, reflector, board);
    let mut buf = vec![0u8; ct.len()];
    let mut best = (settings, f64::NEG_INFINITY);
    for m in 0..ALPHABET as u8 {
        for r in 0..ALPHABET as u8 {
            let (middle, right) = (Ring::new(m), Ring::new(r));
            let trial = Settings {
                rings: [settings.rings[0], middle, right],
                positions: [
                    settings.positions[0],
                    held[0].with_ring(middle),
                    held[1].with_ring(right),
                ],
                ..settings
            };
            if trial != settings && traced(trial) != over_the_crib {
                continue;
            }
            machine.aim(trial, reflector);
            machine.replug(board);
            machine.run_into(ct, &mut buf);
            let s = ctx.refine(&buf);
            if s > best.1 {
                best = (trial, s);
            }
        }
    }
    best.0
}

#[must_use]
pub fn complete_board(
    settings: Settings,
    reflector: [u8; ALPHABET],
    (forced, known): (Plugboard, u32),
    leads: usize,
    reach: usize,
    ct: &[Letter],
    ctx: &Context,
) -> (Settings, Plugboard, Vec<Letter>) {
    let board = climb_free(
        settings,
        reflector,
        (forced, known),
        leads,
        LEAD_MARGIN,
        ct,
        ctx,
    );
    let settings = best_rings(settings, reflector, board, reach, ct, ctx);
    let board = climb_free(settings, reflector, (forced, known), leads, 0.0, ct, ctx);
    let plain = Enigma::with_reflector(settings, reflector, board).run(ct);
    (settings, board, plain)
}

fn partial_score(
    ct: &[Letter],
    ctx: &Context,
    settings: Settings,
    reflector: [u8; ALPHABET],
    board: Plugboard,
    offset: usize,
    crib: usize,
) -> f64 {
    let plain = Enigma::with_reflector(settings, reflector, board).run(ct);
    score_outside_the_crib(&plain, ctx, offset, crib)
}

fn finish_stop(
    ct: &[Letter],
    ctx: &Context,
    stop: &Pending,
    menu: &Menu,
    reflector: &(String, [u8; ALPHABET]),
    reach: usize,
    crib: usize,
) -> Option<((Candidate, usize), (Plugboard, u32))> {
    let positions = Positions::of(stop.settings, reflector.1, reach);
    let mut scratch = Scratch::new();
    scan_all_with(menu, &positions, &mut scratch)
        .into_iter()
        .filter_map(|found| match found {
            Stop::Survived { board, known, .. } => Some((board, known)),
            Stop::Refuted => None,
        })
        .filter_map(|(forced, known)| {
            let (settings, board, plain) = complete_board(
                stop.settings,
                reflector.1,
                (forced, known),
                ENIGMA_LEADS,
                menu.offset + crib,
                ct,
                ctx,
            );
            if menu.edges.iter().any(|&(i, p, _)| plain[i] != p) {
                return None;
            }
            let found = (
                Candidate {
                    score: score_outside_the_crib(&plain, ctx, menu.offset, crib),
                    key: format!(
                        "rotors {:?} {} rings {} start {} crib at {} plugs {}",
                        settings.rotors.map(|r| r + 1),
                        reflector.0,
                        from_letters(&settings.ring_letters()),
                        from_letters(&settings.position_letters()),
                        menu.offset,
                        describe_leads(&board)
                    ),
                    plain,
                },
                board.pairs().len(),
            );
            Some((found, (forced, known)))
        })
        .max_by(|a, b| a.0.0.score.total_cmp(&b.0.0.score))
}

#[must_use]
pub fn finished_noise(
    ct: &[Letter],
    ctx: &Context,
    naval: bool,
    offset: usize,
    crib: usize,
    shapes: &[(Plugboard, u32)],
    samples: usize,
) -> Vec<f64> {
    if shapes.is_empty() {
        return Vec::new();
    }
    let orders = enigma::rotor_orders(enigma::ROTOR_COUNT);
    let reflectors = reflectors_for(naval);
    (0..samples as u64)
        .into_par_iter()
        .map(|i| {
            let mut rng = Rng::new(ctx.seed ^ 0xF1_415E ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let rotors = orders[rng.below(orders.len())];
            let reflector = reflectors[rng.below(reflectors.len())].1;
            let letter = |r: &mut Rng| r.below(ALPHABET) as u8;
            let rings = [0, letter(&mut rng), letter(&mut rng)];
            let starts = [letter(&mut rng), letter(&mut rng), letter(&mut rng)];
            let (forced, known) = shapes[i as usize % shapes.len()];
            let (_, _, plain) = complete_board(
                Settings::at(rotors, 0, rings, starts),
                reflector,
                (forced, known),
                ENIGMA_LEADS,
                offset + crib,
                ct,
                ctx,
            );
            score_outside_the_crib(&plain, ctx, offset, crib)
        })
        .collect()
}

impl BombeAttack {
    fn ring_count(&self) -> usize {
        if self.rings { ALPHABET } else { 1 }
    }

    fn middle_count(&self) -> usize {
        if self.middles { ALPHABET } else { 1 }
    }

    fn finish_all(
        &self,
        ct: &[Letter],
        ctx: &Context,
        mut pending: Vec<Pending>,
        menus: &[Menu],
        named: &[(String, [u8; ALPHABET])],
        reach: usize,
    ) -> Vec<Candidate> {
        pending.sort_unstable_by(|a, b| b.partial.total_cmp(&a.partial));
        pending.truncate(self.finish.max(1));
        self.finished
            .store(pending.len() as u64, std::sync::atomic::Ordering::Relaxed);
        let finished: Vec<((Candidate, usize), (Plugboard, u32))> = pending
            .par_iter()
            .filter_map(|stop| {
                finish_stop(
                    ct,
                    ctx,
                    stop,
                    &menus[stop.menu],
                    &named[stop.reflector],
                    reach,
                    self.crib.len(),
                )
            })
            .collect();
        if let Ok(mut shapes) = self.shapes.lock() {
            *shapes = finished.iter().take(SHAPES_KEPT).map(|f| f.1).collect();
        }
        let found = finished.into_iter().map(|f| f.0).collect();
        rank_enigma(found, ct.len().saturating_sub(2).max(1), ctx.keep)
    }

    fn sweep_on_processor(
        &self,
        ct: &[Letter],
        ctx: &Context,
        (rotors, reflector, wiring): ([usize; 3], usize, [u8; ALPHABET]),
        menus: &[Menu],
        reach: usize,
    ) -> Vec<Pending> {
        let span = (ALPHABET as u64).pow(3);
        let ring_count = self.ring_count() as u64;
        let middle_count = self.middle_count() as u64;
        let keep = self.finish.max(ctx.keep);
        let mut stops: Vec<Pending> = Vec::new();
        let mut positions = Positions::of(Settings::at(rotors, 0, [0; 3], [0; 3]), wiring, reach);
        let mut scratch = Scratch::new();
        let mut survived = 0u64;
        let mut aimed = (0u8, 0u8);
        for index in 0..span * ring_count * middle_count {
            let p = index % span;
            let middle = (index / span / ring_count) as u8;
            let ring = ((index / span) % ring_count) as u8;
            let start = [
                (p / (ALPHABET as u64 * ALPHABET as u64)) as u8,
                ((p / ALPHABET as u64) % ALPHABET as u64) as u8,
                (p % ALPHABET as u64) as u8,
            ];
            if enigma::rings_repeat(rotors, start[1], start[2], (middle, ring), reach) {
                continue;
            }
            let settings = Settings::at(rotors, 0, [0, middle, ring], start);
            if aimed != (middle, ring) {
                positions.aim(settings, wiring, reach);
                aimed = (middle, ring);
            }
            positions.restart(settings, reach);
            for (m, menu) in menus.iter().enumerate() {
                let Stop::Survived { board, .. } = scan_with(menu, &positions, &mut scratch) else {
                    continue;
                };
                survived += 1;
                stops.push(Pending {
                    partial: partial_score(
                        ct,
                        ctx,
                        settings,
                        wiring,
                        board,
                        menu.offset,
                        self.crib.len(),
                    ),
                    settings,
                    reflector,
                    menu: m,
                });
            }
            if stops.len() > keep * STOPS_BEFORE_SIFTING {
                sift(&mut stops, keep);
            }
        }
        sift(&mut stops, keep);
        self.stops
            .fetch_add(survived, std::sync::atomic::Ordering::Relaxed);
        stops
    }

    fn placements(&self, ct: &[Letter]) -> Vec<usize> {
        let mut all = crate::crib::placements(ct, &self.crib);
        if let Some(at) = self.at {
            all.retain(|&o| o == at);
        }
        all
    }

    #[cfg(feature = "gpu")]
    fn on_device(&self, ct: &[Letter], ctx: &Context) -> Option<Vec<Candidate>> {
        let gpu = self.gpu.as_ref()?;
        let model = ctx.focus?;
        if self.crib.len() > crate::gpu::BOMBE_MAX_CRIB {
            return None;
        }
        let placements = self.placements(ct);
        let menus: Vec<Menu> = placements
            .iter()
            .filter_map(|&offset| Menu::place(ct, &self.crib, offset))
            .filter(|menu| menu.closures() > 0)
            .collect();
        if menus.is_empty() {
            return Some(Vec::new());
        }
        let packed: Vec<crate::gpu::PlacedMenu> = menus
            .iter()
            .map(|m| {
                let pairs = (0..self.crib.len())
                    .map(|i| (self.crib[i], ct[m.offset + i]))
                    .collect();
                (m.offset, pairs, m.hub())
            })
            .collect();
        let orders = enigma::rotor_orders(self.rotors_available);
        let named = reflectors_for(self.naval);
        let wirings: Vec<[u8; ALPHABET]> = named.iter().map(|(_, w)| *w).collect();

        let found = gpu.sweep_bombe(&crate::gpu::BombeJob {
            ct,
            logp: model.log_table(),
            order: model.order(),
            orders: &orders,
            reflectors: &wirings,
            menus: &packed,
            rings: self.ring_count(),
            middles: self.middle_count(),
            keep: self.finish.max(ctx.keep),
        });
        self.stops
            .store(found.stops, std::sync::atomic::Ordering::Relaxed);
        ctx.trace.note("bombe/device", || {
            format!("{} stops over {} menus", found.stops, menus.len())
        });

        let reach = menus
            .iter()
            .map(|m| m.offset + self.crib.len())
            .max()
            .unwrap_or(ct.len());
        let pending: Vec<Pending> = found
            .best
            .iter()
            .map(|hit| Pending {
                partial: hit.score,
                settings: Settings::at(
                    orders[hit.order],
                    0,
                    [0, hit.middle.value(), hit.ring.value()],
                    hit.positions.map(Indicator::value),
                ),
                reflector: hit.reflector,
                menu: hit.menu,
            })
            .collect();
        Some(self.finish_all(ct, ctx, pending, &menus, &named, reach))
    }
}

impl Attack for BombeAttack {
    fn name(&self) -> String {
        format!("bombe on {}", self.label)
    }

    fn family(&self) -> &'static str {
        "rotor"
    }

    fn coverage(&self, ct: &[Letter]) -> Coverage {
        let placements = self.placements(ct).len() as u64;
        if placements == 0 {
            return Coverage::Impossible("the crib meets its own image at every offset");
        }
        let orders = enigma::rotor_orders(self.rotors_available).len() as u64;
        let reflectors = if self.naval {
            enigma::NAVAL_REFLECTOR_COUNT as u64
        } else {
            enigma::REFLECTOR_COUNT as u64
        };
        let rings = self.ring_count() as u64 * self.middle_count() as u64;
        // The rotor sweep is exhaustive, but completing the surviving plugboards uses a shortlist and hill climbing.
        Coverage::Searched(placements * orders * reflectors * rings * (ALPHABET as u64).pow(3))
    }

    fn own_null(&self) -> Option<Vec<f64>> {
        Some(Vec::new())
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        self.stops.store(0, std::sync::atomic::Ordering::Relaxed);
        #[cfg(feature = "gpu")]
        if let Some(found) = self.on_device(ct, ctx) {
            return found;
        }
        let placements = self.placements(ct);
        if placements.is_empty() {
            return Vec::new();
        }
        let orders = enigma::rotor_orders(self.rotors_available);
        let reflectors = reflectors_for(self.naval);
        let reflector_count = reflectors.len();
        let order_count = orders.len();

        let span = (ALPHABET as u64).pow(3);
        let settings = span
            * self.ring_count() as u64
            * self.middle_count() as u64
            * orders.len() as u64
            * reflectors.len() as u64;

        let menus: Vec<Menu> = placements
            .iter()
            .filter_map(|&offset| Menu::place(ct, &self.crib, offset))
            .filter(|menu| menu.closures() > 0)
            .collect();
        if menus.is_empty() {
            return Vec::new();
        }
        let decisive = menus.iter().filter(|m| m.decisive_over(settings)).count();
        ctx.trace.note("bombe/menus", || {
            format!(
                "{} placements, {} closing a loop, {decisive} of those decisive over {settings} settings",
                placements.len(),
                menus.len()
            )
        });
        let reach = menus
            .iter()
            .map(|menu| menu.offset + self.crib.len())
            .max()
            .unwrap_or(ct.len());

        let jobs: Vec<(usize, usize)> = (0..order_count)
            .flat_map(|o| (0..reflector_count).map(move |r| (o, r)))
            .collect();

        let found: Vec<Pending> = jobs
            .par_iter()
            .flat_map(|&(order, reflector)| {
                self.sweep_on_processor(
                    ct,
                    ctx,
                    (orders[order], reflector, reflectors[reflector].1),
                    &menus,
                    reach,
                )
            })
            .collect();
        self.finish_all(ct, ctx, found, &menus, &reflectors, reach)
    }
}

#[must_use]
pub fn registry(depth: usize) -> Vec<Box<dyn Attack>> {
    let mut out: Vec<Box<dyn Attack>> = vec![
        Box::new(AffineSweep),
        Box::new(SubstitutionAnneal),
        Box::new(RailFenceSweep),
        Box::new(SelectionSweep),
        Box::new(HillSweep),
        Box::new(PlayfairAnneal),
        Box::new(FourSquareAnneal),
        Box::new(BifidPlain),
    ];
    for width in COLUMNAR_WIDTHS {
        out.push(Box::new(ColumnarSweep { width }));
    }
    for period in 1..=depth.min(MAX_KEY) {
        out.push(Box::new(PeriodicSweep { period }));
    }
    out.push(Box::new(PeriodicClimb {
        max_period: CLIMB_MAX_PERIOD,
        restarts: CLIMB_RESTARTS,
    }));
    for period in 1..=(depth + 2).min(MAX_KEY) {
        out.push(Box::new(PortaSweep { period }));
    }
    for length in 1..=depth.saturating_sub(1).clamp(1, MAX_KEY) {
        out.push(Box::new(AutokeySweep { length }));
    }
    for period in KEYED_BIFID_PERIODS {
        out.push(Box::new(BifidAnneal { period }));
    }
    out.push(Box::new(EnigmaAttack {
        rotors_available: 5,
        shortlist: CPU_ENIGMA_SHORTLIST,
        leads: ENIGMA_LEADS,
    }));
    if depth >= 5 {
        out.push(Box::new(EnigmaAttack {
            rotors_available: enigma::ROTOR_COUNT,
            shortlist: CPU_ENIGMA_SHORTLIST,
            leads: ENIGMA_LEADS,
        }));
        out.push(Box::new(EnigmaNaval {
            shortlist: CPU_ENIGMA_SHORTLIST,
            leads: ENIGMA_LEADS,
            focus: Some("de".to_string()),
        }));
    }
    out
}

#[must_use]
pub fn candidate_ic(c: &Candidate) -> f64 {
    index_of_coincidence(&c.plain)
}

#[cfg(test)]
mod bombe_recovery_tests {
    use super::*;

    #[test]
    fn finishing_checks_the_whole_menu_including_disconnected_edges() {
        let plain = crate::to_letters(
            "TTTFFFZWOVIERVVVFXDXUUUXAUSBXXTRAVEMUENDEBLEIBENXWEITEREBEFEHLEATWARTKNX",
        );
        let ct = crate::to_letters(
            "VIDTGYBSPAXVEDJFKONPMXHTCNAAFKXIOWVCZXUTDGFSEWGFAIDHPKQVARAGUAUPWVRBFOWO",
        );
        let bank = Polyglot::from_bundle(include_str!("../data/models.bundle"));
        let focus = crate::ngram::Model::parse(include_str!("../data/german-quadgrams.txt"))
            .expect("German model");
        let scale = Scale::build(&bank, ct.len(), 128, &mut Rng::new(1));
        let focus_scale = Scale::for_model(&focus, ct.len(), 128, &mut Rng::new(2));
        let ctx = Context {
            judge: &bank,
            scale: &scale,
            plan: Schedule::default(),
            seed: 1,
            keep: 5,
            trace: &crate::trace::QUIET,
            focus: Some(&focus),
            focus_scale: Some(&focus_scale),
        };
        let settings = Settings::at([3, 2, 7], 0, [0, 2, 20], [16, 24, 17]);
        let reflector = (
            "gamma/W B-thin".to_string(),
            enigma::composite_reflector(1, 22, 0),
        );
        let pending = Pending {
            partial: 0.0,
            settings,
            reflector: 0,
            menu: 0,
        };
        for (length, recoverable) in [(16, false), (24, true)] {
            let menu = Menu::place(&ct, &plain[..length], 0).expect("true crib");
            let found = finish_stop(&ct, &ctx, &pending, &menu, &reflector, length, length);
            if recoverable {
                assert_eq!(
                    found
                        .expect("the longer crib recovers the message")
                        .0
                        .0
                        .plain,
                    plain
                );
            } else {
                assert!(
                    found.is_none(),
                    "a completion that changes a disconnected crib edge must be rejected"
                );
            }
        }
    }
}
