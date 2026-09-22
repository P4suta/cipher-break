// SPDX-License-Identifier: MIT OR Apache-2.0

//! Judging a candidate plaintext without being told the language.
//!
//! The index of coincidence is the only wholly language-free measure there is,
//! and it is weak: it counts letters and ignores their order, so it cannot tell a plaintext from an anagram of one.
//! Swapping the rows of a Hill deciphering matrix swaps the letters inside every digraph and leaves it untouched, which is exactly how a true key can fail to come first in a sweep that trusts it.
//!
//! The cure is not to guess the language but to carry all of them.
//! A bank of models scores a candidate under each in turn and keeps the best fit: a text that is a language fits its own, and a text that is not fits none.
//!
//! On the models shipped in `data/models`, the separation is not subtle:
//!
//! | text | fit |
//! | --- | --- |
//! | real prose, 72 letters, any of the 18 languages | −6.4 to −7.8 |
//! | uniform random letters | −14.0 |

use crate::alphabet::Letter;
use crate::ngram::{Grams, Model};
use crate::rng::Rng;
use std::fs;
use std::io;
use std::path::Path;

/// Texts up to this length are scored without allocating.
const INLINE: usize = 512;

/// The most languages the interleaved accumulator holds.
const MAX_LANGS: usize = 32;

/// One n-gram model per language, laid out for the loop that matters.
///
/// The models are kept twice: once as models, for training and sampling, and once interleaved — every language's log probability for a gram sitting together, `table[gram * langs + language]`.
/// Scoring walks the grams of a candidate and touches all eighteen languages at each one, so interleaving turns eighteen scattered cache lines per gram into two adjacent ones, and hands the compiler an inner loop it can vectorise.
/// It is the single change that most affects how long a sweep takes.
#[derive(Clone, Debug, Default)]
pub struct Polyglot {
    models: Vec<(String, Model)>,
    order: usize,
    langs: usize,
    table: Vec<f32>,
}

impl Polyglot {
    /// A bank from named models.
    #[must_use]
    pub fn new(models: Vec<(String, Model)>) -> Self {
        let langs = models.len();
        let order = models.first().map_or(0, |(_, m)| m.order());
        let uniform =
            langs > 0 && langs <= MAX_LANGS && models.iter().all(|(_, m)| m.order() == order);
        let table = if uniform {
            let slots = crate::alphabet::ALPHABET.pow(order as u32);
            let mut table = vec![0f32; slots * langs];
            for (l, (_, model)) in models.iter().enumerate() {
                for g in 0..slots {
                    table[g * langs + l] = model.logp_at(g);
                }
            }
            table
        } else {
            Vec::new()
        };
        Polyglot {
            models,
            order,
            langs,
            table,
        }
    }

    /// Read every `.txt` model in a directory, named by its file stem.
    ///
    /// # Errors
    ///
    /// Fails if the directory cannot be listed.
    pub fn load(dir: &Path) -> io::Result<Self> {
        let mut names: Vec<_> = fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "txt"))
            .collect();
        names.sort();
        let mut models = Vec::new();
        for path in names {
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let Some(model) = Model::parse(&text) else {
                continue;
            };
            let name = path
                .file_stem()
                .map_or_else(String::new, |s| s.to_string_lossy().into());
            models.push((name, model));
        }
        Ok(Polyglot::new(models))
    }

    /// Whether the bank holds anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// How many languages are carried.
    #[must_use]
    pub fn len(&self) -> usize {
        self.models.len()
    }

    /// The names of the languages carried.
    #[must_use]
    pub fn languages(&self) -> Vec<&str> {
        self.models.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// The language that fits best, and how well it fits.
    ///
    /// The gram indices depend only on the text, so they are computed once and reused across every model: with eighteen languages that is eighteen times less index arithmetic in the hottest loop the tool has.
    #[must_use]
    pub fn identify(&self, ls: &[Letter]) -> (&str, f64) {
        if self.models.is_empty() {
            return ("none", f64::NEG_INFINITY);
        }
        if self.table.is_empty() || ls.len() > INLINE {
            return self
                .models
                .iter()
                .map(|(n, m)| (n.as_str(), m.score(ls)))
                .fold(
                    ("none", f64::NEG_INFINITY),
                    |a, b| if b.1 > a.1 { b } else { a },
                );
        }

        let langs = self.langs;
        let mut acc = [0f32; MAX_LANGS];
        let mut n = 0usize;
        for g in Grams::new(self.order, ls) {
            let row = &self.table[g * langs..g * langs + langs];
            for (slot, &v) in acc[..langs].iter_mut().zip(row) {
                *slot += v;
            }
            n += 1;
        }
        if n == 0 {
            return (self.models[0].0.as_str(), 0.0);
        }
        let inverse = 1.0 / n as f32;
        let mut best_index = 0usize;
        let mut best_value = f32::NEG_INFINITY;
        for (i, &v) in acc[..langs].iter().enumerate() {
            if v > best_value {
                best_value = v;
                best_index = i;
            }
        }
        (
            self.models[best_index].0.as_str(),
            f64::from(best_value * inverse),
        )
    }

    /// The interleaved log-probability table, `gram * langs + language`.
    ///
    /// Exposed so the GPU backend can upload exactly what the CPU reads,
    /// rather than a second layout that could drift from it.
    #[must_use]
    pub fn table(&self) -> &[f32] {
        &self.table
    }

    /// How many languages the interleaved table carries.
    #[must_use]
    pub fn langs(&self) -> usize {
        self.langs
    }

    /// The order every model in the bank shares.
    #[must_use]
    pub fn order(&self) -> usize {
        self.order
    }

    /// The best fit alone, without identifying which language it was.
    ///
    /// Sweeps call this tens of millions of times and never look at the name,
    /// so skipping the search for which language won is worth its own method.
    #[inline]
    #[must_use]
    pub fn fit(&self, ls: &[Letter]) -> f64 {
        if self.table.is_empty() || ls.len() > INLINE {
            return self.identify(ls).1;
        }
        let langs = self.langs;
        let mut acc = [0f32; MAX_LANGS];
        let mut n = 0usize;
        for g in Grams::new(self.order, ls) {
            let row = &self.table[g * langs..g * langs + langs];
            for (slot, &v) in acc[..langs].iter_mut().zip(row) {
                *slot += v;
            }
            n += 1;
        }
        if n == 0 {
            return 0.0;
        }
        let mut best = f32::NEG_INFINITY;
        for &v in &acc[..langs] {
            if v > best {
                best = v;
            }
        }
        f64::from(best) / n as f64
    }

    /// What a real text of a given length scores, and what noise scores.
    ///
    /// Both are drawn from the models themselves — language text by sampling each model, noise by drawing letters uniformly — so the tool arrives at its own decision threshold with no corpus to be pointed at and no constant to go stale.
    #[must_use]
    pub fn calibrate(
        &self,
        scale: &Scale,
        len: usize,
        per_language: usize,
        rng: &mut Rng,
    ) -> Calibration {
        let mut language = Vec::new();
        for (_, model) in &self.models {
            for _ in 0..per_language {
                let text = model.sample(len, rng);
                language.push(scale.standardise(len, self.score(&text)));
            }
        }
        language.sort_by(f64::total_cmp);
        let floor = if language.is_empty() {
            f64::NEG_INFINITY
        } else {
            language[language.len() / 20]
        };
        let (language_mean, language_sd) = crate::stats::moments(&language);
        Calibration {
            language_mean,
            language_sd,
            language_floor: floor,
            noise_mean: 0.0,
            noise_sd: 1.0,
        }
    }

    /// How well a text fits the best language on hand.
    #[inline]
    #[must_use]
    pub fn score(&self, ls: &[Letter]) -> f64 {
        self.fit(ls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;

    fn bank() -> Polyglot {
        let english = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGTHETHETHEANDANDANDTHATTHATTHERETHERE";
        let other = "AKAKAKAKIKIKIKIKUKUKUKUKEKEKEKEKOKOKOKOKASASASASISISISIS";
        Polyglot::new(vec![
            ("en".into(), Model::train(3, &to_letters(english))),
            ("xx".into(), Model::train(3, &to_letters(other))),
        ])
    }

    #[test]
    fn it_picks_the_language_a_text_belongs_to() {
        assert_eq!(bank().identify(&to_letters("THETHETHEAND")).0, "en");
        assert_eq!(bank().identify(&to_letters("KAKAKIKIKUKU")).0, "xx");
    }

    #[test]
    fn an_empty_bank_answers_without_panicking() {
        let empty = Polyglot::default();
        let (name, score) = empty.identify(&to_letters("ABC"));
        assert_eq!(name, "none");
        assert!(score.is_infinite());
    }

    #[test]
    fn long_texts_take_the_allocating_path_and_agree() {
        let bank = bank();
        let long = to_letters(&"THEQUICKBROWNFOX".repeat(60));
        let inline = to_letters("THEQUICKBROWNFOX");
        assert!(bank.score(&long) > f64::NEG_INFINITY);
        assert!(bank.score(&inline) > f64::NEG_INFINITY);
    }
}

/// What random letters score, length by length.
///
/// A model's score is a mean log probability per gram, and that mean is much noisier over twelve letters than over seventy.
/// Comparing a twelve-letter candidate with a seventy-letter one on the raw number therefore rewards the short one for being short: the best of many short fragments is high because short fragments vary, not because any of them says anything.
///
/// This tool missed a message hidden as every third letter for exactly that reason — the null it was measured against was full of twelve-letter fragments scoring better than the real forty-nine-letter message.
/// The fix is to stop comparing raw scores at all.
/// Every score in the tool is expressed in deviations above what random letters *of that same length* achieve, which is a number that means the same thing everywhere.
#[derive(Clone, Debug)]
pub struct Scale {
    mean: Vec<f64>,
    sd: Vec<f64>,
}

impl Scale {
    /// Measure random letters at every length up to `max_len`.
    #[must_use]
    pub fn build(bank: &Polyglot, max_len: usize, samples: usize, rng: &mut Rng) -> Self {
        let mut mean = vec![0.0; max_len + 1];
        let mut sd = vec![1.0; max_len + 1];
        for len in 1..=max_len {
            let values: Vec<f64> = (0..samples)
                .map(|_| {
                    let text: Vec<Letter> = (0..len)
                        .map(|_| rng.below(crate::alphabet::ALPHABET) as u8)
                        .collect();
                    bank.score(&text)
                })
                .collect();
            let (m, s) = crate::stats::moments(&values);
            mean[len] = m;
            sd[len] = s.max(1e-6);
        }
        Scale { mean, sd }
    }

    /// The longest length the scale covers.
    #[must_use]
    pub fn reach(&self) -> usize {
        self.mean.len().saturating_sub(1)
    }

    /// A raw score, in deviations above random letters of the same length.
    #[inline]
    #[must_use]
    pub fn standardise(&self, len: usize, raw: f64) -> f64 {
        let i = len.min(self.reach());
        if i == 0 {
            0.0
        } else {
            (raw - self.mean[i]) / self.sd[i]
        }
    }
}

/// What language and noise score at a given length, under a given bank.
#[derive(Clone, Copy, Debug)]
pub struct Calibration {
    /// Mean score of text drawn from the models.
    pub language_mean: f64,
    /// Deviation of that score.
    pub language_sd: f64,
    /// The fifth percentile, used as the bar a candidate has to clear.
    pub language_floor: f64,
    /// Mean score of uniform random letters.
    pub noise_mean: f64,
    /// Deviation of that score.
    pub noise_sd: f64,
}

impl Calibration {
    /// The bar a candidate has to clear to be called a reading.
    ///
    /// Text drawn from a model scores higher under that model than real prose does — it is generated from exactly the distribution it is judged by,
    /// and real writing never is.
    /// Calibrating on sampled text alone therefore sets the bar above real plaintexts, and this tool failed to read a plain Caesar cipher until that was noticed.
    ///
    /// The fix is to let the noise end of the scale carry half the decision.
    /// The bar is the lower of "three deviations below sampled text" and "most of the way from noise to language", so it tracks the models where they are tight and the gap where they are not.
    #[must_use]
    pub fn floor(&self) -> f64 {
        let optimistic = self.language_mean - 3.0 * self.language_sd;
        let spanning = self.noise_mean + 0.6 * (self.language_mean - self.noise_mean);
        optimistic.min(spanning)
    }

    /// Whether a score is high enough to be a plaintext rather than noise.
    #[must_use]
    pub fn reads_as_language(&self, score: f64) -> bool {
        score >= self.floor()
    }

    /// How far a score sits between noise and language, as a fraction.
    #[must_use]
    pub fn position(&self, score: f64) -> f64 {
        let span = self.language_mean - self.noise_mean;
        if span.abs() < 1e-9 {
            0.0
        } else {
            (score - self.noise_mean) / span
        }
    }
}

#[cfg(test)]
mod calibration_tests {
    use super::*;
    use crate::alphabet::to_letters;

    fn small_bank() -> Polyglot {
        let corpus =
            to_letters("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGTHETHETHEANDANDANDTHATTHATTHERETHERE");
        Polyglot::new(vec![("en".into(), Model::train(3, &corpus))])
    }

    #[test]
    fn language_calibrates_above_noise() {
        let bank = small_bank();
        let scale = Scale::build(&bank, 72, 60, &mut Rng::new(1));
        let cal = bank.calibrate(&scale, 72, 40, &mut Rng::new(2));
        assert!(cal.language_mean > cal.noise_mean);
        assert!(cal.reads_as_language(cal.language_mean));
        assert!(!cal.reads_as_language(cal.noise_mean));
        assert!(cal.floor() > cal.noise_mean);
        assert!(cal.floor() < cal.language_mean);
    }

    #[test]
    fn the_scale_puts_random_letters_at_zero() {
        let bank = small_bank();
        let mut rng = Rng::new(3);
        let scale = Scale::build(&bank, 40, 200, &mut rng);
        let noise: Vec<Letter> = (0..40).map(|_| rng.below(26) as u8).collect();
        let z = scale.standardise(40, bank.score(&noise));
        assert!(z.abs() < 4.0, "random letters landed at {z}");
    }

    #[test]
    fn the_scale_makes_lengths_comparable() {
        // A short fragment of noise and a long one both sit near zero, which is the whole point: the raw scores do not.
        let bank = small_bank();
        let mut rng = Rng::new(4);
        let scale = Scale::build(&bank, 60, 200, &mut rng);
        let short: Vec<Letter> = (0..12).map(|_| rng.below(26) as u8).collect();
        let long: Vec<Letter> = (0..60).map(|_| rng.below(26) as u8).collect();
        let a = scale.standardise(12, bank.score(&short));
        let b = scale.standardise(60, bank.score(&long));
        assert!((a - b).abs() < 8.0, "{a} vs {b}");
    }
}
