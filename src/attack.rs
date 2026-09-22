// SPDX-License-Identifier: MIT OR Apache-2.0

//! The attacks, and the catalogue of them.
//!
//! An [`Attack`] is a named key space plus a way of searching it.
//! That is the only abstraction the tool needs: adding a cipher means adding one of these and nothing else, and every piece of machinery around it — the nulls, the ranking, the report — works on the new one the day it arrives.
//!
//! Each attack declares its [`Coverage`], which is what separates "no key works" from "no key I tried works".
//! Both are useful answers and they are not the same answer, so the report never conflates them.

use crate::alphabet::{ALPHABET, Letter, from_letters};
use crate::anneal::{Schedule, anneal};
use crate::bombe::{Menu, Positions, Stop, scan};
use crate::ciphers::enigma::{self, Enigma, Plugboard, Settings};
use crate::ciphers::{
    autokey, bifid, hill, periodic, playfair, porta, substitution, transposition,
};
use crate::enigma_types::{Indicator, Ring};
use crate::polyglot::{Polyglot, Scale};
use crate::rng::Rng;
use crate::square::{self, Square};
use crate::stats::index_of_coincidence;
use rayon::prelude::*;

/// What an attack needs from outside itself.
pub struct Context<'a> {
    /// The judge that decides whether a candidate is a language.
    pub judge: &'a Polyglot,
    /// What random letters score, length by length.
    pub scale: &'a Scale,
    /// How much effort an annealing attack may spend.
    pub plan: Schedule,
    /// The seed every random choice descends from.
    pub seed: u64,
    /// How many candidates to return.
    pub keep: usize,
    /// Where an attack says what it is doing, for when it does it wrongly.
    pub trace: &'a crate::trace::Trace,
    /// What random letters score under [`Context::focus`], length by length.
    pub focus_scale: Option<&'a Scale>,
    /// A higher-order model of the one language a message is known to be in.
    ///
    /// The tool refuses to guess a language, but sometimes provenance settles it, and then a sharper judge is available.
    /// A plugboard is grown one lead at a time and each lead is accepted on a small improvement in score; a trigram model is not fine-grained enough to tell a real lead from a flattering one, and will invent leads that corrupt an otherwise exact decipherment.
    /// A quadgram model of the right language will not.
    pub focus: Option<&'a crate::ngram::Model>,
}

impl Context<'_> {
    /// Score a candidate plaintext, in deviations above random letters of the same length.
    ///
    /// Every attack scores through here, so no attack has to know that a short candidate and a long one are not comparable on the raw number.
    /// When the caller has said what language a message is in, that is the
    /// judge. Ranking a German plaintext by the best of twenty-six languages
    /// lets a text that is not German at all win for fitting something else,
    /// and on a short message it does: a true Enigma decipherment came fourth
    /// behind three that fitted nothing in particular rather well.
    #[inline]
    #[must_use]
    pub fn score(&self, plain: &[Letter]) -> f64 {
        match (self.focus, self.focus_scale) {
            (Some(model), Some(scale)) => scale.standardise(plain.len(), model.score(plain)),
            _ => self.scale.standardise(plain.len(), self.judge.score(plain)),
        }
    }

    /// Score with the sharpest judge available, for choosing between candidates that are already close to each other.
    ///
    /// Only ever used to compare texts of the same length, so the raw number is enough and no standardising is needed.
    #[inline]
    #[must_use]
    pub fn refine(&self, plain: &[Letter]) -> f64 {
        match self.focus {
            Some(model) => model.score(plain),
            None => self.score(plain),
        }
    }
}

/// How thoroughly an attack covers its key space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// Every key was tried; a negative result is final for this cipher.
    Exhaustive(u64),
    /// The space was searched, not enumerated; a negative result is weaker.
    Searched(u64),
    /// The cipher cannot have produced this ciphertext, for a structural reason that needs no key at all.
    Impossible(&'static str),
}

impl Coverage {
    /// How many keys the attack will look at.
    #[must_use]
    pub fn keys(self) -> u64 {
        match self {
            Coverage::Exhaustive(n) | Coverage::Searched(n) => n,
            Coverage::Impossible(_) => 0,
        }
    }
}

/// One reading of the ciphertext.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// How well the plaintext fits the best language on hand.
    pub score: f64,
    /// The key, rendered for a human.
    pub key: String,
    /// The plaintext it produced.
    pub plain: Vec<Letter>,
}

/// A named key space and a way of searching it.
pub trait Attack: Sync + Send {
    /// How the attack is named in reports and on the command line.
    fn name(&self) -> String;

    /// The family it belongs to, for grouping.
    fn family(&self) -> &'static str;

    /// How much of the space this ciphertext will see.
    fn coverage(&self, ct: &[Letter]) -> Coverage;

    /// The best candidates the attack finds.
    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate>;
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

/// A bounded collection of the highest scores seen, by key index.
///
/// Sweeps run to tens of millions of keys, so nothing may be kept per key.
/// Scores and indices are kept while the search runs and the winning keys are rebuilt at the end, which costs one extra decipherment each and no memory at all.
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

/// Run a scoring function over an index range in parallel, keeping the best.
fn sweep_indices<F>(total: u64, keep: usize, width: usize, score: F) -> Vec<(f64, u64)>
where
    F: Fn(u64, &mut [Letter]) -> f64 + Sync,
{
    sweep_indices_with(total, keep, || vec![0u8; width], |i, buf| score(i, buf))
}

/// The same, with a scratch state each thread builds once and keeps.
///
/// An Enigma sweep needs a machine as well as a buffer, and building one per key costs more than running it does.
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

/// How much a plugboard lead has to improve the score before it is believed.
///
/// Zero is the obvious choice and the wrong one.
/// A lead that is not there will often improve a score by a hair — enough to be accepted, and enough to corrupt an otherwise exact decipherment.
/// Demanding a real improvement costs nothing when the lead is real.
pub const LEAD_MARGIN: f64 = 0.02;

/// How many distinct leads a plugboard could take: every unordered pair of letters.
pub const PLUGBOARD_PAIRS: usize = ALPHABET * (ALPHABET - 1) / 2;

/// How many invertible two-by-two matrices there are over the alphabet.
///
/// Stated rather than counted so that [`Attack::coverage`] costs nothing;
/// a test builds the list and checks the number.
pub const HILL_KEYS: u64 = 157_248;

/// The widths a columnar transposition is exhausted at.
///
/// Every column order is tried, so the work is the factorial of the width; at nine this passes a third of a million keys for one width alone.
pub const COLUMNAR_WIDTHS: std::ops::RangeInclusive<usize> = 2..=8;

/// The strides a null cipher is looked for at.
pub const SELECTION_STRIDES: std::ops::RangeInclusive<usize> = 2..=12;

/// The periods an unkeyed bifid square is tried at.
pub const BIFID_PERIODS: std::ops::RangeInclusive<usize> = 1..=24;

/// The periods a keyed bifid square is searched at.
///
/// Below three the cipher barely fractionates; above sixteen a block is longer than most of the messages this tool is handed.
pub const KEYED_BIFID_PERIODS: std::ops::RangeInclusive<usize> = 3..=16;

/// How far the hill-climbing attack on a repeating key reaches.
pub const CLIMB_MAX_PERIOD: usize = 16;

/// How many random starting keys each hill climb gets.
pub const CLIMB_RESTARTS: usize = 12;

/// How many rotor settings a processor-side Enigma attack keeps.
pub const CPU_ENIGMA_SHORTLIST: usize = 400;

/// How many plugboard leads an Enigma attack looks for.
///
/// Ten is what the Kriegsmarine used.
pub const ENIGMA_LEADS: usize = 10;

/// The longest key a stack-allocated sweep buffer holds.
///
/// Sweeps run to tens of millions of keys and a heap allocation per key is the difference between using the machine and waiting for it.
/// Every exhaustive attack here spells its key into a fixed array instead.
pub const MAX_KEY: usize = 16;

/// Spell an index as a key of the given length over the alphabet.
#[inline]
fn spell_key(mut index: u64, length: usize, out: &mut [Letter; MAX_KEY]) {
    for slot in out[..length].iter_mut().rev() {
        *slot = (index % ALPHABET as u64) as u8;
        index /= ALPHABET as u64;
    }
}

/// Spell an index as a list of digits in an arbitrary base.
#[inline]
fn spell_digits(mut index: u64, length: usize, base: u64, out: &mut [usize; MAX_KEY]) {
    for slot in out[..length].iter_mut().rev() {
        *slot = (index % base) as usize;
        index /= base;
    }
}

// --------------------------------------------------------------------------
// The Vigenere family, exhausted
// --------------------------------------------------------------------------

/// Every key of a fixed length, under all three members of the family.
pub struct PeriodicSweep {
    /// The key length to exhaust.
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

/// Coordinate ascent on the key, for periods too long to exhaust.
pub struct PeriodicClimb {
    /// The longest period to try.
    pub max_period: usize,
    /// How many random starting keys each period gets.
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

// --------------------------------------------------------------------------
// Porta
// --------------------------------------------------------------------------

/// Every Porta key of a fixed period.
pub struct PortaSweep {
    /// The period to exhaust.
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

// --------------------------------------------------------------------------
// Autokey
// --------------------------------------------------------------------------

/// Every autokey primer of a fixed length, under both primings and all three families.
pub struct AutokeySweep {
    /// The primer length to exhaust.
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

// --------------------------------------------------------------------------
// Hill
// --------------------------------------------------------------------------

/// Every invertible two-by-two Hill key.
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

// --------------------------------------------------------------------------
// Monoalphabetic
// --------------------------------------------------------------------------

/// Every affine key, plus the shifts and Atbash inside them.
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

/// The general substitution cipher, searched by annealing.
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

// --------------------------------------------------------------------------
// Transposition
// --------------------------------------------------------------------------

/// Every column order for a fixed grid width.
pub struct ColumnarSweep {
    /// The grid width to exhaust.
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

/// Every rail fence height that could apply.
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

/// Reading only every nth letter, which is what a null cipher hides behind.
///
/// This is the one attack here that does not decipher anything.
/// It is included because the statistics that rule out transposition and substitution say nothing about it: a message hidden as every fourth letter of random padding leaves a ciphertext that is random, because most of it is.
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

// --------------------------------------------------------------------------
// Keyed squares
// --------------------------------------------------------------------------

/// Bifid with the unkeyed square, over every period and every letter the ciphertext leaves room to omit.
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

/// Bifid with a keyed square, searched by annealing.
pub struct BifidAnneal {
    /// The period to search at.
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

/// Playfair with a keyed square, searched by annealing.
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

/// Four-square with two keyed squares, searched by annealing.
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

/// The same exhaustive periodic sweep, run on a device.
///
/// The device chooses by the raw fit while the processor chooses by the fit standardised for length.
/// Within one sweep every candidate is the same length, and standardising is an increasing function of the raw score at a fixed length, so the two orderings are the same one — which is why the winning keys can come back from the device and be scored again here,
/// without the two backends ever needing to agree on a number.
#[cfg(feature = "gpu")]
pub struct GpuPeriodicSweep {
    /// The key length to exhaust.
    pub period: usize,
    /// The device to run on.
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

// --------------------------------------------------------------------------
// Enigma
// --------------------------------------------------------------------------

/// Enigma, attacked the only way a ciphertext alone allows.
///
/// The key has two halves of wildly different size.
/// The rotor order, the reflector and the three starting positions come to about twelve million combinations; the plugboard comes to a hundred and fifty trillion.
/// Nothing can enumerate the second, but it barely needs to be: a plugboard swaps ten pairs of letters and leaves the other six alone, so a decipherment with the rotors right and the board wrong still reads as a mangled version of the language underneath — enough for a score to notice.
///
/// So the rotors are exhausted, and the board is then grown one lead at a time, each lead chosen as the single swap that most improves the score.
/// This is Gillogly's attack, and it is known to need a few hundred letters to be reliable.
/// On a short message it will still return its best answer; what says whether that answer means anything is, as everywhere here, the same search run on shuffled text.
pub struct EnigmaAttack {
    /// How many of the eight historical rotors to draw from.
    pub rotors_available: usize,
    /// How many rotor settings survive into the plugboard search.
    pub shortlist: usize,
    /// How many leads to try to find.
    pub leads: usize,
}

/// Grow a plugboard one lead at a time, keeping each lead that helps.
///
/// The plugboard is far too large to enumerate and barely needs to be.
/// A decipherment with the rotors right and the board empty still reads as a mangled version of the language underneath, so each lead can be found by asking which single swap most improves the score — and the leads that are really there improve it, one after another, until none is left.
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

    // Growing a board one lead at a time can commit early to a lead that only looked good before the others were there.
    // Each lead is now pulled out in turn and the best replacement for it sought, which costs another few hundred runs and routinely recovers a lead the greedy pass missed.
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

/// Search the ring settings, holding the wiring path the rotors already found.
///
/// A rotor sweep runs with the rings at zero, which is not a restriction on the wiring — moving a ring and its rotor together leaves the path through the machine exactly as it was — but it is a restriction on the notches.
/// A notch fires at an indicator letter, so where the ring sits decides *when* the rotor to its left moves, and on a short message that is two or three moments in seventy letters.
///
/// So this varies the rings and compensates the positions, which changes only the notch timing and leaves everything the sweep established alone.
/// The leftmost ring is not searched: there is no rotor to its left for its notch to turn, so it is redundant with the position the sweep already has.
fn refine_rings(
    settings: Settings,
    reflector: [u8; ALPHABET],
    ct: &[Letter],
    ctx: &Context,
    board: Plugboard,
) -> (Settings, f64) {
    let side = ALPHABET as u8;
    // Hold the wiring exactly where the sweep put it.
    // Moving a ring and its indicator together is the one change that leaves the path through the machine alone and alters only when the notches fire.
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

/// Everything after the rotor sweep: the board, the rings, then the board again.
///
/// The three steps are not independent and the order matters.
/// A board cannot be found until the rotors are right, the rings cannot be judged until the board is roughly right, and the board can be improved once the rings are.
/// Two passes over the board with the rings between them is where that settles.
fn finish_enigma(
    settings: Settings,
    reflector: [u8; ALPHABET],
    leads: usize,
    ct: &[Letter],
    ctx: &Context,
) -> (Settings, Plugboard, f64, Vec<Letter>) {
    // The first climb only has to get close enough for the rings to be worth judging, so it is held to the margin that stops a broad search inventing leads.
    // The last one is the opposite case: the rotors and rings are settled, the text is nearly right, and a lead that helps at all is a lead that is there.
    // Holding it to the same margin is what left a real plugboard lead behind on a short message.
    let (board, _, _) = climb_plugboard(settings, reflector, leads, LEAD_MARGIN, ct, ctx);
    let (tuned, _) = refine_rings(settings, reflector, ct, ctx, board);
    let (board, score, plain) = climb_plugboard(tuned, reflector, leads, 0.0, ct, ctx);
    (tuned, board, score, plain)
}

/// What a plugboard lead costs when candidates are ranked against each other.
///
/// Ten leads chosen from 325 possibilities will fit any rotor setting tolerably, so the best climbed score belongs to whichever setting was given the most room.
/// That is the same overfitting the nulls catch elsewhere in this tool, arriving one stage earlier and needing the same answer: charge for the freedom.
/// A lead costs log(325) nats, spread over the grams the score is a mean of, which is the standard price for a parameter.
///
/// The price is paid only when ordering candidates inside an attack.
/// The score an attack reports is left alone, because the null it is reported against was produced by a search with exactly the same freedom and has already paid.
#[must_use]
pub fn penalised(score: f64, leads: usize, grams: usize) -> f64 {
    score - (PLUGBOARD_PAIRS as f64).ln() / grams.max(1) as f64 * leads as f64
}

/// Rotor settings written out for a trace, best first.
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

/// Order candidates with their plugboards' freedom charged for, and keep the best.
///
/// The score each candidate reports is untouched; only the order is decided this way.
/// The reported score is what a null will be compared against, and that null was produced by a search with the same freedom.
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

/// How the leads a climb found are written out.
fn describe_leads(board: &Plugboard) -> String {
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
        // Exhaustive in the rotors, searched in the plugboard, so the honest label is the weaker of the two.
        Coverage::Searched(orders * 2 * (ALPHABET as u64).pow(3))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let orders = enigma::rotor_orders(self.rotors_available);
        let positions = (ALPHABET as u64).pow(3);
        let total = orders.len() as u64 * 2 * positions;

        // The rotors, exhausted with no plugboard and the rings at zero.
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

        // The plugboard, grown on the settings that survived.
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

/// The Naval four-rotor Enigma, as the U-boats carried it.
///
/// The fourth rotor never turns.
/// That is the whole of what makes this machine reachable: a rotor that never turns, together with the thin reflector behind it, is one fixed permutation for the length of a message, and still an involution.
/// So an M4 is an M3 with one of `2 × 26 × 2` reflectors, and the rotor half of its key is 336 orders times 104 reflectors times 17,576 starting positions — six hundred million, which is a sweep rather than a dream.
///
/// The plugboard is then grown one lead at a time, as in the three-rotor attack.
/// Where the provenance of a message fixes its language, the rotor sweep is steered by that one model: a Kriegsmarine signal is in German, and searching six hundred million settings under eighteen languages when seventeen of them are known to be wrong is eighteen times the work for a worse answer.
pub struct EnigmaNaval {
    /// How many rotor settings survive into the plugboard search.
    pub shortlist: usize,
    /// How many leads to try to find.
    pub leads: usize,
    /// The language the rotor sweep is steered by, when one is known.
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

/// The naval rotor sweep, run on a device.
///
/// Only the rotor half moves to the GPU.
/// The plugboard is grown afterwards on the processor, on a few hundred settings rather than six hundred million, and it is not where the time goes.
#[cfg(feature = "gpu")]
pub struct GpuEnigmaNaval {
    /// How many rotor settings survive into the plugboard search.
    pub shortlist: usize,
    /// How many leads to try to find.
    pub leads: usize,
    /// The language the rotor sweep is steered by.
    pub focus: String,
    /// How many right-rotor ring settings the sweep tries.
    pub rings: usize,
    /// How many of the device's boards are finished here.
    pub finish: usize,
    /// The device to run on.
    pub gpu: std::sync::Arc<crate::gpu::Gpu>,
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
        // Steer by the sharpest model of the language available.
        // Sixteen billion settings is enough that the best of the wrong ones beats the right one under a trigram model; a quadgram model of the same language separates them again.
        // This is the same lesson the nulls teach everywhere else in the tool, arriving from the other side:
        // the more you search, the better your judge has to be.
        // Steered by the trigram model, not the quadgram one.
        // German quadgrams fill only an eighth of their table even after four million letters, so most of what a seventy-letter candidate lands on is the floor, and a judge that answers "unseen" to most of its questions is a blunt judge.
        // Measured on a planted key, the trigram model puts the true setting 146th of six hundred million and the quadgram model 1380th.
        // The quadgram model earns its place later,
        // where the text is already nearly right and the question is whether one more plugboard lead helps.
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
            keep: self.shortlist,
        };
        let found = self.gpu.sweep_enigma(&job);

        // Grow a board for every one of them, on the device.
        // A short message rarely puts the true setting first under an empty board, so the shortlist is long and this is what makes a long one affordable.
        let boards = self
            .gpu
            .climb_plugboards(&job, &found, self.leads, LEAD_MARGIN as f32);
        // Rank with the plugboard's freedom charged for.
        // Ten leads chosen from 325 possibilities will fit any setting tolerably, so the best climbed score belongs to whichever setting was given the most room —
        // which is the same overfitting the nulls catch everywhere else in this tool, arriving one stage earlier.
        // Each lead costs log(325) nats, spread over the grams the score is a mean of, which is the standard price for a parameter and is what puts the true setting back in front of the settings that merely had room.
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

        // Finish the survivors here: the rings, then the board once more.
        let out: Vec<(Candidate, usize)> = ranked
            .par_iter()
            .map(|&(_, i)| {
                let hit = found[i];
                let settings = Settings {
                    rotors: orders[hit.order],
                    reflector: 0,
                    rings: [Ring::new(0), Ring::new(0), hit.ring],
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

/// Enigma attacked through a crib, with a bombe rather than a judge.
///
/// Every other Enigma attack here needs the decipherment to look like a language, and with a full plugboard on a short message it never does: the board sends twenty of twenty-six letters somewhere else, and what comes out is not German in any form a model recognises.
///
/// A bombe does not look at the decipherment.
/// It asks whether any plugboard at all could turn this ciphertext into the crib under this rotor setting, and answers by contradiction — which is exact, and which does not weaken as the board grows.
/// That is the only tool that reaches a message like this, and it is the one the war used.
///
/// It needs a crib that is actually there, and a crib whose letters repeat enough to close loops.
/// A menu with no closures forces nothing twice, so nothing can ever disagree, and the attack accepts every setting it is shown; [`crate::bombe::Menu::closures`] is what says whether a crib is worth running.
pub struct BombeAttack {
    /// The guessed plaintext.
    pub crib: Vec<Letter>,
    /// What to call it in the report.
    pub label: String,
    /// How many of the eight rotors to draw from.
    pub rotors_available: usize,
    /// Whether to fold in the Greek rotor and thin reflectors.
    pub naval: bool,
}

impl Attack for BombeAttack {
    fn name(&self) -> String {
        format!("bombe on {}", self.label)
    }

    fn family(&self) -> &'static str {
        "rotor"
    }

    fn coverage(&self, ct: &[Letter]) -> Coverage {
        let placements = crate::crib::placements(ct, &self.crib).len() as u64;
        if placements == 0 {
            return Coverage::Impossible("the crib meets its own image at every offset");
        }
        let orders = enigma::rotor_orders(self.rotors_available).len() as u64;
        let reflectors = if self.naval {
            enigma::NAVAL_REFLECTOR_COUNT as u64
        } else {
            enigma::REFLECTOR_COUNT as u64
        };
        Coverage::Exhaustive(placements * orders * reflectors * (ALPHABET as u64).pow(3))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let placements = crate::crib::placements(ct, &self.crib);
        if placements.is_empty() {
            return Vec::new();
        }
        let orders = enigma::rotor_orders(self.rotors_available);
        let reflectors: Vec<(String, [u8; ALPHABET])> = if self.naval {
            enigma::naval_reflectors()
        } else {
            (0..enigma::REFLECTOR_COUNT)
                .map(|i| {
                    (
                        if i == 0 {
                            "B".to_string()
                        } else {
                            "C".to_string()
                        },
                        enigma::reflector_wiring(i),
                    )
                })
                .collect()
        };
        let span = (ALPHABET as u64).pow(3);

        let reflector_count = reflectors.len();
        let order_count = orders.len();
        let jobs: Vec<(usize, usize, usize)> = placements
            .iter()
            .flat_map(|&offset| {
                (0..order_count)
                    .flat_map(move |o| (0..reflector_count).map(move |r| (offset, o, r)))
            })
            .collect();

        let mut found: Vec<(Candidate, usize)> = jobs
            .par_iter()
            .flat_map(|&(offset, order, reflector)| {
                let Some(menu) = Menu::place(ct, &self.crib, offset) else {
                    return Vec::new();
                };
                let reach = offset + self.crib.len();
                let mut stops: Vec<(Candidate, usize)> = Vec::new();
                let base = Settings::at(orders[order], 0, [0; 3], [0; 3]);
                let mut positions = Positions::of(base, reflectors[reflector].1, reach);
                for index in 0..span {
                    let settings = Settings::at(
                        orders[order],
                        0,
                        [0; 3],
                        [
                            (index / (ALPHABET as u64 * ALPHABET as u64)) as u8,
                            ((index / ALPHABET as u64) % ALPHABET as u64) as u8,
                            (index % ALPHABET as u64) as u8,
                        ],
                    );
                    positions.aim(settings, reflectors[reflector].1, reach);
                    let Stop::Survived { board, .. } = scan(&menu, &positions) else {
                        continue;
                    };
                    let plain =
                        Enigma::with_reflector(settings, reflectors[reflector].1, board).run(ct);
                    stops.push((
                        Candidate {
                            score: ctx.score(&plain),
                            key: format!(
                                "rotors {:?} {} start {} crib at {offset} plugs {}",
                                settings.rotors.map(|r| r + 1),
                                reflectors[reflector].0,
                                from_letters(&settings.position_letters()),
                                describe_leads(&board)
                            ),
                            plain,
                        },
                        board.pairs().len(),
                    ));
                }
                stops.sort_unstable_by(|a, b| b.0.score.total_cmp(&a.0.score));
                stops.truncate(ctx.keep.max(1));
                stops
            })
            .collect();
        found.sort_unstable_by(|a, b| b.0.score.total_cmp(&a.0.score));
        rank_enigma(found, ct.len().saturating_sub(2).max(1), ctx.keep)
    }
}

/// The catalogue, in the order a report reads best.
///
/// `depth` decides how far the exhaustive sweeps run: the cost of the periodic and autokey sweeps is 26 to the power of the key length, so each step up is 26 times the work, and where to stop is the one thing worth choosing.
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
    // Each step up multiplies the work by the alphabet, so the caps are set by how far each cipher's space grows: Porta counts in thirteens rather than twenty-sixes and reaches two digits further for the same cost,
    // while autokey carries six variants and reaches one less.
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

/// The index of coincidence of a candidate, used as a cheap cross-check in reports.
#[must_use]
pub fn candidate_ic(c: &Candidate) -> f64 {
    index_of_coincidence(&c.plain)
}
