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
use crate::ciphers::enigma::{self, Enigma, Plugboard, Settings};
use crate::ciphers::{
    autokey, bifid, hill, periodic, playfair, porta, substitution, transposition,
};
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
    #[inline]
    #[must_use]
    pub fn score(&self, plain: &[Letter]) -> f64 {
        self.scale.standardise(plain.len(), self.judge.score(plain))
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
        Coverage::Exhaustive(157_248)
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
        Coverage::Exhaustive(2 * (2..=12u64).sum::<u64>())
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = (2..=12usize)
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
        Coverage::Exhaustive(square::omissions_for(ct).len() as u64 * 24)
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let jobs: Vec<(Letter, usize)> = square::omissions_for(ct)
            .into_iter()
            .flat_map(|m| (1..=24usize).map(move |p| (m, p)))
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
fn climb_plugboard(
    settings: Settings,
    reflector: [u8; ALPHABET],
    leads: usize,
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
                if s > best + LEAD_MARGIN {
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
    (board, ctx.score(&best_plain), best_plain)
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
            Settings {
                rotors: order,
                reflector,
                rings: [0; 3],
                positions: [
                    (p / (ALPHABET as u64 * ALPHABET as u64)) as u8,
                    ((p / ALPHABET as u64) % ALPHABET as u64) as u8,
                    (p % ALPHABET as u64) as u8,
                ],
            }
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
        let mut out: Vec<Candidate> = found
            .par_iter()
            .map(|&(_, index)| {
                let settings = decode(index);
                let reflector = enigma::reflector_wiring(settings.reflector);
                let (board, score, plain) =
                    climb_plugboard(settings, reflector, self.leads, ct, ctx);
                Candidate {
                    score,
                    key: format!(
                        "rotors {:?} reflector {} start {} plugs {}",
                        settings.rotors.map(|r| r + 1),
                        if settings.reflector == 0 { "B" } else { "C" },
                        from_letters(&settings.positions),
                        describe_leads(&board)
                    ),
                    plain,
                }
            })
            .collect();
        out.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        out.truncate(ctx.keep);
        out
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
        let orders = enigma::rotor_orders(8).len() as u64;
        Coverage::Searched(orders * 104 * (ALPHABET as u64).pow(3))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let orders = enigma::rotor_orders(8);
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
                Settings {
                    rotors: order,
                    reflector: 0,
                    rings: [0; 3],
                    positions: [
                        (p / (ALPHABET as u64 * ALPHABET as u64)) as u8,
                        ((p / ALPHABET as u64) % ALPHABET as u64) as u8,
                        (p % ALPHABET as u64) as u8,
                    ],
                },
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

        let mut out: Vec<Candidate> = found
            .par_iter()
            .map(|&(_, index)| {
                let (reflector, settings) = decode(index);
                let (board, score, plain) =
                    climb_plugboard(settings, reflectors[reflector].1, self.leads, ct, ctx);
                Candidate {
                    score,
                    key: format!(
                        "rotors {:?} {} start {} plugs {}",
                        settings.rotors.map(|r| r + 1),
                        reflectors[reflector].0,
                        from_letters(&settings.positions),
                        describe_leads(&board)
                    ),
                    plain,
                }
            })
            .collect();
        out.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        out.truncate(ctx.keep);
        out
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
    /// The device to run on.
    pub gpu: std::sync::Arc<crate::gpu::Gpu>,
}

#[cfg(feature = "gpu")]
impl Attack for GpuEnigmaNaval {
    fn name(&self) -> String {
        format!("enigma M4 naval ({}) (gpu)", self.focus)
    }

    fn family(&self) -> &'static str {
        "rotor"
    }

    fn coverage(&self, _ct: &[Letter]) -> Coverage {
        Coverage::Searched(enigma::rotor_orders(8).len() as u64 * 104 * (ALPHABET as u64).pow(3))
    }

    fn best(&self, ct: &[Letter], ctx: &Context) -> Vec<Candidate> {
        let Some(model) = ctx.judge.model_named(&self.focus) else {
            return Vec::new();
        };
        let orders = enigma::rotor_orders(8);
        let named = enigma::naval_reflectors();
        let wirings: Vec<[u8; ALPHABET]> = named.iter().map(|(_, r)| *r).collect();
        let found = self.gpu.sweep_enigma(
            ct,
            model.log_table(),
            model.order(),
            &orders,
            &wirings,
            self.shortlist,
        );
        let positions = (ALPHABET as u64).pow(3);
        let per_order = wirings.len() as u64 * positions;
        let mut out: Vec<Candidate> = found
            .par_iter()
            .map(|&(_, index)| {
                let order = orders[(index / per_order) as usize];
                let reflector = ((index % per_order) / positions) as usize;
                let p = index % positions;
                let settings = Settings {
                    rotors: order,
                    reflector: 0,
                    rings: [0; 3],
                    positions: [
                        (p / (ALPHABET as u64 * ALPHABET as u64)) as u8,
                        ((p / ALPHABET as u64) % ALPHABET as u64) as u8,
                        (p % ALPHABET as u64) as u8,
                    ],
                };
                let (board, score, plain) =
                    climb_plugboard(settings, wirings[reflector], self.leads, ct, ctx);
                Candidate {
                    score,
                    key: format!(
                        "rotors {:?} {} start {} plugs {}",
                        settings.rotors.map(|r| r + 1),
                        named[reflector].0,
                        from_letters(&settings.positions),
                        describe_leads(&board)
                    ),
                    plain,
                }
            })
            .collect();
        out.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        out.truncate(ctx.keep);
        out
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
    for width in 2..=8 {
        out.push(Box::new(ColumnarSweep { width }));
    }
    // Each step up multiplies the work by the alphabet, so the caps are set by how far each cipher's space grows: Porta counts in thirteens rather than twenty-sixes and reaches two digits further for the same cost,
    // while autokey carries six variants and reaches one less.
    for period in 1..=depth.min(MAX_KEY) {
        out.push(Box::new(PeriodicSweep { period }));
    }
    out.push(Box::new(PeriodicClimb {
        max_period: 16,
        restarts: 12,
    }));
    for period in 1..=(depth + 2).min(MAX_KEY) {
        out.push(Box::new(PortaSweep { period }));
    }
    for length in 1..=depth.saturating_sub(1).clamp(1, MAX_KEY) {
        out.push(Box::new(AutokeySweep { length }));
    }
    for period in 3..=16 {
        out.push(Box::new(BifidAnneal { period }));
    }
    out.push(Box::new(EnigmaAttack {
        rotors_available: 5,
        shortlist: 200,
        leads: 10,
    }));
    if depth >= 5 {
        out.push(Box::new(EnigmaAttack {
            rotors_available: 8,
            shortlist: 400,
            leads: 10,
        }));
        out.push(Box::new(EnigmaNaval {
            shortlist: 400,
            leads: 10,
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
