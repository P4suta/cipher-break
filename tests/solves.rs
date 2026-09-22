// SPDX-License-Identifier: MIT OR Apache-2.0

//! The tool has to break ciphers it is handed before its silence means anything.
//!
//! Each test plants a key in real text, hands the ciphertext to the same catalogue a user would get, and requires the plaintext back.
//! A negative result on an unknown message is worth exactly what this file is worth.

use cipher_break::alphabet::{Letter, from_letters, to_letters};
use cipher_break::anneal::Schedule;
use cipher_break::attack::{Context, registry};
use cipher_break::ciphers::{autokey, hill, periodic, porta, substitution, transposition};
use cipher_break::ngram::Model;
use cipher_break::polyglot::{Polyglot, Scale};
use cipher_break::report::{self, Conclusion};
use cipher_break::rng::Rng;
use cipher_break::sweep;

const PLAIN: &str = "ITISACAPITALMISTAKETOTHEORIZEBEFOREONEHASDATAINSENSIBLYONEBEGINS\
                     TOTWISTFACTSTOSUITTHEORIESINSTEADOFTHEORIESTOSUITFACTS";

/// The models the shipped binary carries.
fn bank() -> Polyglot {
    let bundle = include_str!("../data/models.bundle");
    let mut out = Vec::new();
    let mut name = String::new();
    let mut body = String::new();
    for line in bundle.lines() {
        if let Some(rest) = line.strip_prefix("### ") {
            if !name.is_empty()
                && let Some(m) = Model::parse(&body)
            {
                out.push((name.clone(), m));
            }
            name = rest.trim().to_string();
            body.clear();
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(m) = Model::parse(&body) {
        out.push((name, m));
    }
    Polyglot::new(out)
}

/// Run the catalogue the way `cb` does and return what it concluded.
fn solve(ct: &[Letter]) -> Conclusion {
    let bank = bank();
    let scale = Scale::build(&bank, ct.len(), 128, &mut Rng::new(0x5CA1E));
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default().scaled(0.5),
        seed: 1,
        keep: 1,
    };
    let outcomes: Vec<_> = registry(4)
        .iter()
        .map(|a| sweep::run(a.as_ref(), ct, &ctx, 8))
        .collect();
    let mut calibrator = report::Calibrator::new(&bank, &scale, 0xCA11);
    report::conclude(&outcomes, &mut calibrator, |p| {
        bank.identify(p).0.to_string()
    })
}

#[track_caller]
fn assert_reads(ct: &[Letter], expected: &str) {
    match solve(ct) {
        Conclusion::Read {
            plain, attack, key, ..
        } => {
            assert_eq!(
                from_letters(&plain),
                expected,
                "read as {attack} with key {key}: {}",
                from_letters(&plain)
            );
        }
        Conclusion::Unread { best, noise, .. } => {
            panic!("did not read it at all (best {best:+.1}s, noise {noise:+.1}s)")
        }
    }
}

#[test]
fn it_breaks_a_caesar_shift() {
    let plain = to_letters(PLAIN);
    let ct = substitution::apply(&substitution::shift(7), &plain);
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_an_affine_cipher() {
    let plain = to_letters(PLAIN);
    let ct = substitution::apply(&substitution::affine(5, 8), &plain);
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_atbash() {
    let plain = to_letters(PLAIN);
    let ct = substitution::apply(&substitution::atbash(), &plain);
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_a_vigenere_key() {
    let plain = to_letters(PLAIN);
    let ct = periodic::encipher(periodic::Family::Vigenere, &to_letters("LEMON"), &plain);
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_a_beaufort_key() {
    let plain = to_letters(PLAIN);
    let ct = periodic::encipher(periodic::Family::Beaufort, &to_letters("CRYPT"), &plain);
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_a_long_vigenere_key_by_climbing() {
    let plain = to_letters(PLAIN);
    let ct = periodic::encipher(
        periodic::Family::Vigenere,
        &to_letters("CRYPTOGRAPHY"),
        &plain,
    );
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_a_porta_key() {
    let plain = to_letters(PLAIN);
    let ct = porta::apply(&[3, 7, 1], &plain);
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_an_autokey_primer() {
    let plain = to_letters(PLAIN);
    let ct = autokey::encipher(
        autokey::Priming::Plaintext,
        periodic::Family::Vigenere,
        &to_letters("QX"),
        &plain,
    );
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_a_hill_matrix() {
    let plain = to_letters(PLAIN);
    let ct = hill::Matrix(3, 3, 2, 5).apply(&plain);
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_a_rail_fence() {
    let plain = to_letters(PLAIN);
    let rails = 4;
    let mut pattern: Vec<usize> = (0..rails).collect();
    pattern.extend((1..rails - 1).rev());
    let mut order: Vec<usize> = (0..plain.len()).collect();
    order.sort_by_key(|&i| (pattern[i % pattern.len()], i));
    let ct: Vec<Letter> = order.into_iter().map(|i| plain[i]).collect();
    assert_eq!(
        transposition::rail_fence(rails, &ct),
        plain,
        "fixture is wrong"
    );
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_breaks_a_columnar_transposition() {
    let plain = to_letters(PLAIN);
    let key = [2usize, 0, 3, 1, 4];
    let mut ct = Vec::new();
    for &position in &key {
        let mut i = position;
        while i < plain.len() {
            ct.push(plain[i]);
            i += key.len();
        }
    }
    assert_eq!(
        transposition::columnar(&key, &ct),
        plain,
        "fixture is wrong"
    );
    assert_reads(&ct, PLAIN);
}

#[test]
fn it_finds_a_message_hidden_as_every_third_letter() {
    let hidden = to_letters("MEETMEATTHEOLDMILLATMIDNIGHTANDBRINGTHEMAPWITHYOU");
    let mut rng = Rng::new(9);
    let mut ct = Vec::new();
    for &l in &hidden {
        ct.push(l);
        ct.push(rng.below(26) as u8);
        ct.push(rng.below(26) as u8);
    }
    assert_reads(&ct, &from_letters(&hidden));
}

#[test]
fn it_says_nothing_about_random_letters() {
    let mut rng = Rng::new(4242);
    let ct: Vec<Letter> = (0..120).map(|_| rng.below(26) as u8).collect();
    match solve(&ct) {
        Conclusion::Unread { .. } => {}
        Conclusion::Read {
            attack, key, plain, ..
        } => {
            panic!("read noise as {attack} / {key}: {}", from_letters(&plain))
        }
    }
}
