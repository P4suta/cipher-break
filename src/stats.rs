// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frequency statistics: the numbers every classical attack rests on.

use crate::alphabet::{ALPHABET, Letter};

/// How often each of the 26 letters occurs.
#[must_use]
pub fn counts(ls: &[Letter]) -> [u32; ALPHABET] {
    let mut out = [0u32; ALPHABET];
    for &l in ls {
        out[(l as usize) % ALPHABET] += 1;
    }
    out
}

/// The probability that two letters drawn without replacement match.
///
/// Random text sits near `0.0385`, which is `1/26`, and English near `0.0667`.
/// A text enciphered with a long key looks random by this measure, which is what makes the statistic a period detector rather than a language detector.
#[must_use]
pub fn index_of_coincidence(ls: &[Letter]) -> f64 {
    let n = ls.len();
    if n < 2 {
        return 0.0;
    }
    let c = counts(ls);
    let total: u64 = c
        .iter()
        .map(|&x| u64::from(x) * u64::from(x.saturating_sub(1)))
        .sum();
    total as f64 / (n * (n - 1)) as f64
}

/// Letter frequencies of English prose, as fractions summing to one.
pub const ENGLISH: [f64; ALPHABET] = [
    0.081_67, 0.014_92, 0.027_82, 0.042_53, 0.127_02, 0.022_28, 0.020_15, 0.060_94, 0.069_66,
    0.001_53, 0.007_72, 0.040_25, 0.024_06, 0.067_49, 0.075_07, 0.019_29, 0.000_95, 0.059_87,
    0.063_27, 0.090_56, 0.027_58, 0.009_78, 0.023_60, 0.001_50, 0.019_74, 0.000_74,
];

/// Pearson's statistic against [`ENGLISH`]; smaller is more English.
#[must_use]
pub fn chi_squared(ls: &[Letter]) -> f64 {
    let n = ls.len();
    if n == 0 {
        return 0.0;
    }
    let c = counts(ls);
    (0..ALPHABET)
        .map(|i| {
            let expected = ENGLISH[i] * n as f64;
            let diff = f64::from(c[i]) - expected;
            diff * diff / expected
        })
        .sum()
}

/// Split a text into the `n` positions a single key letter enciphered.
///
/// Each column is a monoalphabetic cipher, which is the whole reason a period is worth finding.
#[must_use]
pub fn columns(n: usize, ls: &[Letter]) -> Vec<Vec<Letter>> {
    if n <= 1 {
        return vec![ls.to_vec()];
    }
    let mut out = vec![Vec::with_capacity(ls.len() / n + 1); n];
    for (i, &l) in ls.iter().enumerate() {
        out[i % n].push(l);
    }
    out
}

/// Mean index of coincidence across the columns a period would create.
///
/// At the true period every column is a monoalphabetic substitution of the plaintext and the mean rises towards the language's own value; at a wrong period the columns stay mixed and it sits near `1/26`.
/// This sees any periodic cipher at all, not only the ones built from shifts.
#[must_use]
pub fn ic_by_period(ls: &[Letter], n: usize) -> f64 {
    let cols = columns(n, ls);
    let usable: Vec<f64> = cols
        .iter()
        .filter(|c| c.len() >= 2)
        .map(|c| index_of_coincidence(c))
        .collect();
    if usable.is_empty() {
        0.0
    } else {
        usable.iter().sum::<f64>() / usable.len() as f64
    }
}

/// Mean and standard deviation of a sample.
#[must_use]
pub fn moments(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n;
    (mean, var.max(1e-15).sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;

    #[test]
    fn counts_sum_to_the_length() {
        let ls = to_letters("THEQUICKBROWNFOX");
        assert_eq!(counts(&ls).iter().sum::<u32>() as usize, ls.len());
    }

    #[test]
    fn one_repeated_letter_has_ic_one() {
        assert!((index_of_coincidence(&to_letters("AAAAAA")) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn ic_of_a_short_text_is_zero() {
        assert_eq!(index_of_coincidence(&to_letters("A")), 0.0);
        assert_eq!(index_of_coincidence(&[]), 0.0);
    }

    #[test]
    fn two_letters_are_enough_to_have_an_index() {
        // The boundary itself: a pair is the shortest text with a pair in it,
        // and treating it as too short reports nothing where the answer is one.
        assert_eq!(index_of_coincidence(&to_letters("AA")), 1.0);
        assert_eq!(index_of_coincidence(&to_letters("AB")), 0.0);
    }

    #[test]
    fn chi_squared_is_not_zero_on_text_that_is_not_english() {
        assert!(chi_squared(&to_letters("ZZZZZZZZ")) > 0.0);
    }

    #[test]
    fn moments_are_the_mean_and_the_deviation() {
        let (mean, sd) = moments(&[1.0, 3.0]);
        assert!((mean - 2.0).abs() < 1e-12, "mean was {mean}");
        assert!((sd - 1.0).abs() < 1e-12, "deviation was {sd}");
    }

    #[test]
    fn moments_of_a_constant_sample_have_no_spread() {
        let (mean, sd) = moments(&[5.0, 5.0, 5.0]);
        assert!((mean - 5.0).abs() < 1e-12);
        assert!(sd < 1e-6, "deviation was {sd}");
    }

    #[test]
    fn moments_of_nothing_are_nothing() {
        assert_eq!(moments(&[]), (0.0, 0.0));
    }

    #[test]
    fn the_english_table_is_a_distribution() {
        let total: f64 = ENGLISH.iter().sum();
        assert!((total - 1.0).abs() < 1e-3, "it summed to {total}");
        assert!(ENGLISH.iter().all(|&p| p > 0.0));
    }

    #[test]
    fn ic_by_period_falls_back_to_zero_when_no_column_is_usable() {
        assert_eq!(ic_by_period(&to_letters("ABC"), 10), 0.0);
    }

    #[test]
    fn columns_partition_the_text() {
        let ls: Vec<u8> = (0..23).collect();
        let mut flat: Vec<u8> = columns(5, &ls).concat();
        flat.sort_unstable();
        assert_eq!(flat, ls);
    }

    #[test]
    fn chi_squared_is_zero_on_empty_input() {
        assert_eq!(chi_squared(&[]), 0.0);
    }
}
