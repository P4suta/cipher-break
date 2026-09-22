// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Enigma attacks, shown working on messages this file enciphered.
//!
//! These are slow — a naval sweep is six hundred million settings — so they are marked `#[ignore]` and run on purpose with `cargo test -- --ignored`.
//! They are the reason a negative result on a real message is worth anything.

use cipher_break::alphabet::{Letter, from_letters, to_letters};
use cipher_break::anneal::Schedule;
use cipher_break::attack::{Attack, Context, EnigmaAttack, EnigmaNaval};
use cipher_break::ciphers::enigma::{Enigma, Plugboard, Settings, composite_reflector};
use cipher_break::ngram::Model;

/// The German quadgram model the binary carries.
fn german() -> Option<Model> {
    Model::parse(include_str!("../data/german-quadgrams.txt"))
}
use cipher_break::polyglot::{Polyglot, Scale};
use cipher_break::rng::Rng;

/// A Kriegsmarine signal in the shape they were actually sent in.
const SIGNAL: &str = "VONVONJAWEGENDERSITUATIONXXMELDEICHXXFEINDKONVOIINSICHTXXMARQUADRATBE";

fn bank() -> Polyglot {
    let bundle = include_str!("../data/models.bundle");
    Polyglot::from_bundle(bundle)
}

#[test]
fn the_machine_never_sends_a_letter_to_itself() {
    let settings = Settings {
        rotors: [0, 1, 2],
        reflector: 0,
        rings: [0; 3],
        positions: [0; 3],
    };
    let plain = to_letters(SIGNAL);
    let ct = Enigma::new(settings, Plugboard::empty()).run(&plain);
    assert!(cipher_break::ciphers::enigma::compatible(&ct, &plain));
}

/// Run the three-rotor attack against a message this function enciphered.
fn three_rotor_case(plugs: &[(u8, u8)], shortlist: usize, text: &str) -> (bool, String) {
    let settings = Settings {
        rotors: [2, 0, 4],
        reflector: 0,
        rings: [0; 3],
        positions: [7, 19, 3],
    };
    let mut board = Plugboard::empty();
    for &(a, b) in plugs {
        board.connect(a, b);
    }
    let plain = to_letters(text);
    let ct = Enigma::new(settings, board).run(&plain);

    let bank = bank();
    let scale = Scale::build(&bank, ct.len(), 128, &mut Rng::new(1));
    let focus = german();
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default(),
        seed: 1,
        keep: 5,
        focus: focus.as_ref(),
    };
    let attack = EnigmaAttack {
        rotors_available: 5,
        shortlist,
        leads: plugs.len().max(1),
    };
    let found = attack.best(&ct, &ctx);
    let read = found.iter().any(|c| c.plain == plain);
    (
        read,
        format!(
            "best {:+.1} {} -> {}",
            found[0].score,
            found[0].key,
            from_letters(&found[0].plain)
        ),
    )
}

#[test]
#[ignore = "a full rotor sweep; run with --ignored"]
fn it_breaks_a_three_rotor_message_with_no_plugboard() {
    let (read, detail) = three_rotor_case(&[], 2000, SIGNAL);
    assert!(read, "{detail}");
}

#[test]
#[ignore = "a full rotor sweep; run with --ignored"]
fn it_breaks_a_three_rotor_message_with_a_plugboard() {
    let (read, detail) = three_rotor_case(
        &[(0, 20), (4, 12), (8, 15), (17, 2), (24, 9)],
        20_000,
        SIGNAL,
    );
    assert!(read, "{detail}");
}

#[test]
#[ignore = "six hundred million settings; run with --ignored"]
fn it_breaks_a_naval_four_rotor_message() {
    let settings = Settings {
        rotors: [3, 1, 6],
        reflector: 0,
        rings: [0; 3],
        positions: [11, 4, 22],
    };
    let reflector = composite_reflector(0, 9, 0);
    let mut board = Plugboard::empty();
    for (a, b) in [(1u8, 20u8), (8, 15), (17, 2)] {
        board.connect(a, b);
    }
    let plain: Vec<Letter> = to_letters(SIGNAL);
    let ct = Enigma::with_reflector(settings, reflector, board).run(&plain);

    let bank = bank();
    let scale = Scale::build(&bank, ct.len(), 128, &mut Rng::new(1));
    let focus = german();
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default(),
        seed: 1,
        keep: 5,
        focus: focus.as_ref(),
    };
    let attack = EnigmaNaval {
        shortlist: 400,
        leads: 5,
        focus: Some("de".to_string()),
    };
    let found = attack.best(&ct, &ctx);
    let read = found.iter().any(|c| c.plain == plain);
    assert!(
        read,
        "best was {:+.1} {} -> {}",
        found[0].score,
        found[0].key,
        from_letters(&found[0].plain)
    );
}

/// The device backend has to find what the processor finds.
///
/// Two implementations of the same sweep are only worth having while they agree, and a rotor sweep is exactly the kind of thing where a shader and a loop can quietly differ — one modulo out of place changes every letter.
#[cfg(feature = "gpu")]
#[test]
#[ignore = "needs a GPU; run with --ignored"]
fn the_device_finds_the_same_naval_key() {
    use cipher_break::attack::GpuEnigmaNaval;

    let settings = Settings {
        rotors: [3, 1, 6],
        reflector: 0,
        rings: [0; 3],
        positions: [11, 4, 22],
    };
    let reflector = composite_reflector(0, 9, 0);
    let mut board = Plugboard::empty();
    for (a, b) in [(1u8, 20u8), (8, 15), (17, 2)] {
        board.connect(a, b);
    }
    let plain: Vec<Letter> = to_letters(SIGNAL);
    let ct = Enigma::with_reflector(settings, reflector, board).run(&plain);

    let bank = bank();
    let scale = Scale::build(&bank, ct.len(), 128, &mut Rng::new(1));
    let focus = german();
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default(),
        seed: 1,
        keep: 5,
        focus: focus.as_ref(),
    };
    let gpu = std::sync::Arc::new(cipher_break::gpu::Gpu::open().expect("a device"));
    let attack = GpuEnigmaNaval {
        shortlist: 400,
        leads: 5,
        focus: "de".to_string(),
        gpu,
    };
    let found = attack.best(&ct, &ctx);
    let key = &found[0].key;
    assert!(
        key.contains("rotors [4, 2, 7]") && key.contains("beta/J") && key.contains("start LEW"),
        "the device found {key} -> {}",
        from_letters(&found[0].plain)
    );
}
