// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Enigma attacks, shown working on messages this file enciphered.
//!
//! Every planted case is declared once, in [`CASES`], and both the attacks and
//! the diagnostic run from that one table. They used to be written out
//! separately, and a diagnostic that planted `start HEW` while the test it was
//! meant to explain planted `start LLP` cost an hour of looking in the wrong
//! place. A fact measured about one message says nothing about another.
//!
//! The sweeps are slow — a naval one is six hundred million settings, or
//! sixteen billion with the ring — so the heavy tests are `#[ignore]` and run
//! on purpose with `cargo test -- --ignored`.

use cipher_break::alphabet::{Letter, from_letters, to_letters};
use cipher_break::anneal::Schedule;
use cipher_break::attack::{Attack, Context};
use cipher_break::ciphers::enigma::{
    Enigma, Plugboard, Settings, compatible, composite_reflector, naval_reflectors, rotor_orders,
};
use cipher_break::enigma_types::{Indicator, Ring};
use cipher_break::ngram::Model;
use cipher_break::polyglot::{Polyglot, Scale};
use cipher_break::rng::Rng;
use cipher_break::trace::Trace;

/// A Kriegsmarine signal in the shape they were actually sent in.
const SIGNAL: &str = "VONVONJAWEGENDERSITUATIONXXMELDEICHXXFEINDKONVOIINSICHTXXMARQUADRATBE";

/// A longer one, for the searches that need more evidence than a short signal carries.
const LONG_SIGNAL: &str = "VONVONJAWEGENDERSITUATIONXXMELDEICHXXFEINDKONVOIINSICHTXXMARQUADRATBE\
                           XXDREISCHIFFEUNDZWEIZERSTOERERXXKURSNORDOSTXXGESCHWINDIGKEITACHTXX\
                           GREIFEBEIMORGENGRAUENANXXERBITTEUNTERSTUETZUNGDURCHZWEIBOOTEXXENDE";

/// The right ring setting one planted case uses, as a letter index.
const RIGHT_RING_T: u8 = 19;

/// A sweep that holds the right ring at A.
const RINGS_HELD: usize = 1;

/// A sweep that tries every right-ring setting.
const RINGS_SWEPT: usize = cipher_break::alphabet::ALPHABET;

/// How deep the rank diagnostic looks before reporting "not found".
const RANK_DEPTH: usize = 200_000;

/// How many settings a cross-check between the two backends needs.
const CROSS_CHECK_KEEP: usize = 4;

/// How long a shortlist the planted-case attacks are given.
const PLANTED_SHORTLIST: usize = 60_000;

/// How many of the device's boards each planted case finishes here.
const PLANTED_FINISH: usize = 64;

/// How many candidates a planted case is allowed to return.
const PLANTED_KEEP: usize = 5;

/// How many random texts the planted cases calibrate against.
const PLANTED_SAMPLES: usize = 128;

/// A message this file enciphered, with everything needed to attack it again.
pub struct Planted {
    /// How the case is named in output.
    pub label: &'static str,
    /// The plaintext.
    pub text: &'static str,
    /// Which rotors, right to left as the machine holds them.
    pub rotors: [usize; 3],
    /// Ring settings, left to right.
    pub rings: [u8; 3],
    /// Starting positions, left to right.
    pub positions: [u8; 3],
    /// The Greek rotor, its setting and the thin reflector.
    pub greek: (usize, u8, usize),
    /// The plugboard leads.
    pub plugs: &'static [(u8, u8)],
    /// How many right-rotor ring settings an attack must sweep to contain it.
    pub sweep_rings: usize,
}

/// Every planted case, declared once.
///
/// The `sweep_rings` column is not a preference; it is what the case requires.
/// A rotor sweep runs with the rings at zero, which reproduces any wiring but only one notch timing, so a case whose right ring is not `A` is outside a one-ring sweep by construction and no amount of searching will find it.
pub const CASES: &[Planted] = &[
    Planted {
        label: "naval, short, ring A",
        text: SIGNAL,
        rotors: [3, 1, 6],
        rings: [0, 0, 0],
        positions: [11, 4, 22],
        greek: (0, 9, 0),
        plugs: &[(1, 20), (8, 15), (17, 2)],
        sweep_rings: 1,
    },
    Planted {
        label: "naval, long, ring A",
        text: LONG_SIGNAL,
        rotors: [3, 1, 6],
        rings: [0, 0, 0],
        positions: [11, 4, 22],
        greek: (0, 9, 0),
        plugs: &[(1, 20), (8, 15), (17, 2)],
        sweep_rings: 1,
    },
    Planted {
        label: "naval, long, right ring T",
        text: LONG_SIGNAL,
        rotors: [3, 1, 6],
        rings: [0, 0, RIGHT_RING_T],
        positions: [11, 4, 22],
        greek: (0, 9, 0),
        plugs: &[(1, 20), (8, 15), (17, 2)],
        sweep_rings: 26,
    },
];

impl Planted {
    /// The settings the machine was set to.
    #[must_use]
    pub fn settings(&self) -> Settings {
        Settings {
            rotors: self.rotors,
            reflector: 0,
            rings: self.rings.map(Ring::new),
            positions: self.positions.map(Indicator::new),
        }
    }

    /// The composite reflector the Greek rotor and thin reflector make.
    #[must_use]
    pub fn reflector(&self) -> [u8; cipher_break::alphabet::ALPHABET] {
        composite_reflector(self.greek.0, self.greek.1, self.greek.2)
    }

    /// Which of the 104 naval reflectors that is.
    #[must_use]
    pub fn reflector_index(&self) -> usize {
        self.greek.0 * 52 + self.greek.2 * 26 + self.greek.1 as usize
    }

    /// The board that was fitted.
    #[must_use]
    pub fn board(&self) -> Plugboard {
        let mut board = Plugboard::empty();
        for &(a, b) in self.plugs {
            board.connect(a, b);
        }
        board
    }

    /// The plaintext, as letters.
    #[must_use]
    pub fn plain(&self) -> Vec<Letter> {
        to_letters(self.text)
    }

    /// What the machine produced.
    #[must_use]
    pub fn ciphertext(&self) -> Vec<Letter> {
        Enigma::with_reflector(self.settings(), self.reflector(), self.board()).run(&self.plain())
    }
}

/// A message a bombe is known to break, and the plaintext it should come back with.
///
/// Shared so that a test about the bombe's answer and a test about the bombe's null are asking about the same sweep; the last time two bombe tests planted different settings, the disagreement between them cost an hour to find.
fn planted_bombe_message() -> (Vec<u8>, Vec<u8>) {
    let settings = Settings::at([2, 0, 4], 0, [0; 3], [7, 19, 3]);
    let mut board = Plugboard::empty();
    for (a, b) in [(0u8, 20u8), (4, 12), (8, 15), (17, 2), (24, 9)] {
        board.connect(a, b);
    }
    let plain = to_letters(SIGNAL);
    let ct = Enigma::new(settings, board).run(&plain);
    (plain, ct)
}

/// The models the shipped binary carries.
fn bank() -> Polyglot {
    Polyglot::from_bundle(include_str!("../data/models.bundle"))
}

/// The German quadgram model the binary carries.
fn german() -> Option<Model> {
    Model::parse(include_str!("../data/german-quadgrams.txt"))
}

#[test]
fn the_reflector_index_agrees_with_the_list() {
    let named = naval_reflectors();
    for case in CASES {
        assert_eq!(
            named[case.reflector_index()].1,
            case.reflector(),
            "{}: the index and the wiring disagree",
            case.label
        );
    }
}

#[test]
fn the_machine_never_sends_a_letter_to_itself() {
    for case in CASES {
        assert!(
            compatible(&case.ciphertext(), &case.plain()),
            "{}: a letter was enciphered as itself",
            case.label
        );
    }
}

#[test]
fn every_planted_case_deciphers_back() {
    for case in CASES {
        let back = Enigma::with_reflector(case.settings(), case.reflector(), case.board())
            .run(&case.ciphertext());
        assert_eq!(back, case.plain(), "{}", case.label);
    }
}

#[cfg(feature = "gpu")]
mod device {
    use super::*;
    use cipher_break::attack::{GpuEnigmaNaval, LEAD_MARGIN, climb_plugboard};
    use cipher_break::gpu::{EnigmaHit, EnigmaJob, Gpu};

    fn context<'a>(
        bank: &'a Polyglot,
        scale: &'a Scale,
        focus: Option<&'a Model>,
        focus_scale: Option<&'a Scale>,
        trace: &'a Trace,
        keep: usize,
    ) -> Context<'a> {
        Context {
            judge: bank,
            scale,
            plan: Schedule::default(),
            seed: 1,
            keep,
            focus,
            focus_scale,
            trace,
        }
    }

    /// Where the true setting lands in the rotor sweep, case by case.
    ///
    /// This is the diagnostic that decides which half of an attack to look at when it fails: a true setting near the front means the sweep is fine and the stage after it is losing the answer; a true setting nowhere means no downstream work will help.
    #[test]
    #[ignore = "a full rotor sweep per case; run with --ignored"]
    fn where_the_true_setting_ranks() {
        let bank = bank();
        let model = bank.model_named("de").expect("german");
        let orders = rotor_orders(8);
        let named = naval_reflectors();
        let wirings: Vec<[u8; cipher_break::alphabet::ALPHABET]> =
            named.iter().map(|(_, r)| *r).collect();
        let gpu = Gpu::open().expect("a device");

        for case in CASES {
            let ct = case.ciphertext();
            let settings = case.settings();
            let order = orders
                .iter()
                .position(|&o| o == case.rotors)
                .expect("order");
            // The sweep holds the rings at zero and moves the indicator with the right ring, so this is the setting it could return.
            let wanted = [
                settings.positions[0],
                settings.positions[1]
                    .against(settings.rings[1])
                    .with_ring(Ring::new(0)),
                settings.positions[2],
            ];
            let hits = gpu.sweep_enigma(&EnigmaJob {
                ct: &ct,
                logp: model.log_table(),
                order: model.order(),
                orders: &orders,
                reflectors: &wirings,
                rings: case.sweep_rings,
                keep: RANK_DEPTH,
            });
            let rank = hits.iter().position(|h| {
                h.order == order
                    && h.reflector == case.reflector_index()
                    && h.ring == settings.rings[2]
                    && h.positions == wanted
            });
            let truth = model.score(
                &Enigma::with_reflector(settings, case.reflector(), Plugboard::empty()).run(&ct),
            );
            println!(
                "{:<28} {:>4} letters, {:>2} rings: best {:.4}, true {:.4}, rank {:?}",
                case.label,
                ct.len(),
                case.sweep_rings,
                hits[0].score,
                truth,
                rank
            );
        }
    }

    /// The device and the processor have to agree on the very same setting.
    ///
    /// Comparing only the answers a search returns hides a shader that is subtly wrong: it will confidently return the best of the wrong things.
    #[test]
    #[ignore = "needs a GPU; run with --ignored"]
    fn scores_a_setting_exactly_as_the_processor_does() {
        let case = &CASES[0];
        let ct = case.ciphertext();
        let bank = bank();
        let model = bank.model_named("de").expect("german");
        let orders = rotor_orders(8);
        let wirings: Vec<[u8; cipher_break::alphabet::ALPHABET]> =
            naval_reflectors().iter().map(|(_, r)| *r).collect();
        let gpu = Gpu::open().expect("a device");

        for rings in [RINGS_HELD, RINGS_SWEPT] {
            let hits = gpu.sweep_enigma(&EnigmaJob {
                ct: &ct,
                logp: model.log_table(),
                order: model.order(),
                orders: &orders,
                reflectors: &wirings,
                rings,
                keep: CROSS_CHECK_KEEP,
            });
            let hit = hits[0];
            let rebuilt = Settings {
                rotors: orders[hit.order],
                reflector: 0,
                rings: [Ring::new(0), Ring::new(0), hit.ring],
                positions: hit.positions,
            };
            let here = model.score(
                &Enigma::with_reflector(rebuilt, wirings[hit.reflector], Plugboard::empty())
                    .run(&ct),
            );
            assert!(
                (here - hit.score).abs() < 1e-4,
                "rings {rings}: device said {:.6}, processor says {here:.6}",
                hit.score
            );
        }
    }

    /// The device's plugboard climb has to reach what the processor's reaches.
    #[test]
    #[ignore = "needs a GPU; run with --ignored"]
    fn climbs_a_plugboard_exactly_as_the_processor_does() {
        let case = &CASES[0];
        let ct = case.ciphertext();
        let bank = bank();
        let model = bank.model_named("de").expect("german");
        let orders = rotor_orders(8);
        let wirings: Vec<[u8; cipher_break::alphabet::ALPHABET]> =
            naval_reflectors().iter().map(|(_, r)| *r).collect();
        let order = orders
            .iter()
            .position(|&o| o == case.rotors)
            .expect("order");
        let gpu = Gpu::open().expect("a device");

        let hit = EnigmaHit {
            score: 0.0,
            order,
            reflector: case.reflector_index(),
            ring: Ring::new(0),
            positions: case.positions.map(Indicator::new),
        };
        let device = gpu.climb_plugboards(
            &EnigmaJob {
                ct: &ct,
                logp: model.log_table(),
                order: model.order(),
                orders: &orders,
                reflectors: &wirings,
                rings: 1,
                keep: CROSS_CHECK_KEEP,
            },
            &[hit],
            case.plugs.len(),
            LEAD_MARGIN as f32,
        );

        let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
        let trace = Trace::new(false);
        let ctx = context(&bank, &scale, None, None, &trace, 1);
        let (_, _, cpu_plain) = climb_plugboard(
            case.settings(),
            wirings[case.reflector_index()],
            case.plugs.len(),
            LEAD_MARGIN,
            &ct,
            &ctx,
        );
        let here = model.score(&cpu_plain);
        assert!(
            (device[0].0 - here).abs() < 0.05,
            "device reached {:.4}, processor {here:.4}",
            device[0].0
        );
    }

    /// Break every planted case, each swept to the depth it needs.
    #[test]
    #[ignore = "a full attack per case; run with --ignored"]
    fn breaks_every_planted_case() {
        let bank = bank();
        let focus = german();
        let gpu = std::sync::Arc::new(Gpu::open().expect("a device"));
        let mut failures = Vec::new();

        for case in CASES {
            let ct = case.ciphertext();
            let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
            let trace = Trace::new(true);
            let focus_scale = focus
                .as_ref()
                .map(|m| Scale::for_model(m, ct.len(), PLANTED_SAMPLES, &mut Rng::new(2)));
            let ctx = context(
                &bank,
                &scale,
                focus.as_ref(),
                focus_scale.as_ref(),
                &trace,
                PLANTED_KEEP,
            );
            let attack = GpuEnigmaNaval {
                shortlist: PLANTED_SHORTLIST,
                leads: case.plugs.len(),
                focus: "de".to_string(),
                rings: case.sweep_rings,
                finish: PLANTED_FINISH,
                gpu: gpu.clone(),
            };
            let found = attack.best(&ct, &ctx);
            let read = found.iter().any(|c| c.plain == case.plain());
            println!("{}\n{}", case.label, trace.render());
            if !read {
                failures.push(format!(
                    "{}: best {:+.2}s {} -> {}",
                    case.label,
                    found[0].score,
                    found[0].key,
                    from_letters(&found[0].plain)
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}

/// The bombe, shown breaking a message it was given the words to.
///
/// A three-rotor machine with five plugboard leads and a thirty-seven letter crib, carrying a plugboard no amount of n-gram scoring would see through on this length.
///
/// The crib is long on purpose.
/// A menu contradicts only where it forces a letter twice, which needs a cycle in its graph, and a graph of sixteen edges over twenty-odd letters is a forest.
/// Bletchley's cribs ran to twenty and thirty letters for this reason and not for want of shorter guesses.
#[test]
#[ignore = "a rotor sweep per crib placement; run with --ignored"]
fn the_bombe_breaks_a_message_it_has_a_crib_for() {
    use cipher_break::attack::BombeAttack;
    use cipher_break::bombe::Menu;

    let (plain, ct) = planted_bombe_message();
    let crib = to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXX");
    let menu = Menu::place(&ct, &crib, 0).expect("the true placement is never refuted");
    assert!(
        menu.closures() > 0,
        "the crib closes no loops and would refute nothing"
    );

    let bank = bank();
    let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
    let focus = german();
    let focus_scale = focus
        .as_ref()
        .map(|m| Scale::for_model(m, ct.len(), PLANTED_SAMPLES, &mut Rng::new(2)));
    let trace = Trace::new(false);
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default(),
        seed: 1,
        keep: PLANTED_KEEP,
        focus: focus.as_ref(),
        focus_scale: focus_scale.as_ref(),
        trace: &trace,
    };
    let attack = BombeAttack {
        slices: std::sync::Mutex::new(Vec::new()),
        stops: std::sync::atomic::AtomicU64::new(0),
        crib,
        label: "VONVONJAWEGENDERSITUATIONXXMELDEICHXX".to_string(),
        rotors_available: 5,
        naval: false,
    };
    let found = attack.best(&ct, &ctx);
    assert!(
        found.iter().any(|c| c.plain == plain),
        "best {:+.1}s {} -> {}",
        found[0].score,
        found[0].key,
        from_letters(&found[0].plain)
    );
}

/// Where a bombe sweep's time actually goes.
///
/// Three guesses at this were wrong in a row — the allocation, the repeated trace, the per-hypothesis clearing — and each cost a rebuild to disprove.
/// Measuring the parts separately is faster than guessing at them.
#[cfg(feature = "gpu")]
#[test]
#[ignore = "a measurement, not an assertion; run with --ignored --nocapture"]
fn where_the_bombe_spends_its_time() {
    use cipher_break::bombe::{Menu, Positions, Scratch, scan_with};
    use cipher_break::crib::placements;
    use std::time::Instant;

    /// Enough settings that a timing is a timing and not a cache miss.
    const N: usize = 200_000;

    let case = &CASES[0];
    let ct = case.ciphertext();
    let crib = to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXX");
    let offsets = placements(&ct, &crib);
    let menus: Vec<Menu> = offsets
        .iter()
        .filter_map(|&o| Menu::place(&ct, &crib, o))
        .collect();
    let reach = offsets
        .iter()
        .map(|&o| o + crib.len())
        .max()
        .expect("a placement");
    let settings = case.settings();
    let reflector = case.reflector();
    let mut positions = Positions::of(settings, reflector, reach);
    let mut scratch = Scratch::new();

    let start = Instant::now();
    for i in 0..N {
        let s = Settings::at(case.rotors, 0, [0; 3], [0, 0, (i % 26) as u8]);
        positions.restart(s, reach);
        std::hint::black_box(&positions);
    }
    let tracing = start.elapsed();

    let start = Instant::now();
    for i in 0..N {
        let s = Settings::at(case.rotors, 0, [0; 3], [0, 0, (i % 26) as u8]);
        positions.restart(s, reach);
        let r = scan_with(&menus[0], &positions, &mut scratch);
        std::hint::black_box(&r);
    }
    let one_menu = start.elapsed();

    let start = Instant::now();
    for i in 0..N {
        let s = Settings::at(case.rotors, 0, [0; 3], [0, 0, (i % 26) as u8]);
        positions.restart(s, reach);
        for menu in &menus {
            let r = scan_with(menu, &positions, &mut scratch);
            std::hint::black_box(&r);
        }
    }
    let all_menus = start.elapsed();

    let per = |d: std::time::Duration| d.as_secs_f64() / N as f64 * 1e9;
    println!(
        "menus {}, reach {reach}, {N} settings each:\n  \
         trace only        {:>8.0} ns/setting\n  \
         + one menu        {:>8.0} ns/setting  ({:>6.0} ns/scan)\n  \
         + all {:>2} menus    {:>8.0} ns/setting  ({:>6.0} ns/scan)",
        menus.len(),
        per(tracing),
        per(one_menu),
        per(one_menu) - per(tracing),
        menus.len(),
        per(all_menus),
        (per(all_menus) - per(tracing)) / menus.len() as f64
    );
}

/// What a stop costs to judge, which is what decides how many of them a sweep can afford to produce.
///
/// A bombe narrows and a score chooses; the second only works if the first hands it a pile it can get through.
#[test]
#[ignore = "a measurement, not a check"]
fn what_it_costs_to_judge_a_stop() {
    use cipher_break::ciphers::enigma::{Enigma, Plugboard, Settings};

    let ct = cipher_break::to_letters(
        "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
    );
    let bank = bank();
    let rounds = 20_000;

    let start = std::time::Instant::now();
    let mut sink = 0f64;
    for i in 0..rounds {
        let settings = Settings::at([0, 1, 2], 0, [0; 3], [(i % 26) as u8, 0, 0]);
        let plain = Enigma::new(settings, Plugboard::empty()).run(&ct);
        sink += bank.fit(&plain);
    }
    let each = start.elapsed().as_nanos() as f64 / f64::from(rounds);
    println!(
        "  judging one stop   {each:>8.0} ns   (decrypt {} letters and score it)",
        ct.len()
    );
    println!(
        "  so a menu leaving   1,000,000 stops costs {:>6.1} s to judge",
        each * 1e6 / 1e9
    );
    println!(
        "                     23,622,144 stops costs {:>6.1} s to judge",
        each * 23_622_144.0 / 1e9
    );
    assert!(sink.is_finite());
}

/// The null a bombe measures on itself must be the same statistic as the best it reports.
///
/// A null made of individual stops against a best that is the largest of millions would call any sweep a reading, which is the shape of mistake this tool has already made once.
#[test]
fn a_bombe_calibrates_itself_against_its_own_accidents() {
    use cipher_break::attack::{Attack, BombeAttack, NULL_GROUPS};

    // The same machine and message the planted bombe test breaks, so that a sweep here is a sweep that is known to find something.
    let (plain, ct) = planted_bombe_message();
    let crib = to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXX");

    let bank = bank();
    let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
    let focus = german();
    let focus_scale = focus
        .as_ref()
        .map(|m| Scale::for_model(m, ct.len(), PLANTED_SAMPLES, &mut Rng::new(2)));
    let trace = Trace::new(false);
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default(),
        seed: 1,
        keep: PLANTED_KEEP,
        focus: focus.as_ref(),
        focus_scale: focus_scale.as_ref(),
        trace: &trace,
    };

    let attack = BombeAttack {
        slices: std::sync::Mutex::new(Vec::new()),
        stops: std::sync::atomic::AtomicU64::new(0),
        crib,
        label: "self-calibration".to_string(),
        rotors_available: 5,
        naval: false,
    };
    let _ = &plain;

    assert_eq!(
        attack.own_null(),
        Some(Vec::new()),
        "before a sweep there is nothing measured and so nothing to compare against"
    );

    let best = attack.best(&ct, &ctx);
    let null = attack.own_null().expect("a bombe always answers for itself");

    assert!(
        null.len() < NULL_GROUPS,
        "one slice produces the reported best and cannot also be its own null: {} of {NULL_GROUPS}",
        null.len()
    );
    if let Some(top) = best.first() {
        for &n in &null {
            assert!(
                n <= top.score,
                "a null point {n} above the reported best {} means the best was not the best",
                top.score
            );
        }
    }
    // Every slice that saw a stop contributes, and a sweep that saw stops in more than one slice can say something about its own spread.
    let stops = attack.stops.load(std::sync::atomic::Ordering::Relaxed);
    println!("  {stops} stops over {NULL_GROUPS} slices gave {} null points", null.len());
}

/// Whether a menu that closes one loop refutes anything, which decides whether it is worth sweeping.
///
/// Counting closures says it refutes nothing: one closure is what makes a stop possible and leaves a sweep exactly as it found it.
/// Counting closures leaves out Turing's diagonal board, which forces the other end of every lead it sets and so contradicts far more often than the loops alone can account for — the whole point of the thing.
#[test]
fn a_weak_menu_still_refutes_most_of_what_it_is_shown() {
    use cipher_break::bombe::{Menu, Positions, Scratch, Stop, scan_with};
    use cipher_break::ciphers::enigma::{Settings, rotor_orders};

    let ct = cipher_break::to_letters(
        "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
    );
    // A menu for each of the two counts the loop arithmetic writes off entirely.
    let weak: Vec<Menu> = [0usize, 1]
        .iter()
        .filter_map(|&want| {
            let crib = to_letters(if want == 0 {
                "ABCDEFGH"
            } else {
                "MELDEICHXXSTANDORTXX"
            });
            (0..=ct.len() - crib.len())
                .filter_map(|o| Menu::place(&ct, &crib, o))
                .find(|m| m.closures() == want)
        })
        .collect();
    assert!(!weak.is_empty(), "no weak menu to measure");

    for menu in &weak {

    // One rotor order and one reflector: enough settings that a rate is a rate.
    let crib_len = menu.edges.len();
    let orders = rotor_orders(5);
    let reflector = cipher_break::ciphers::enigma::reflector_wiring(0);
    let reach = menu.offset + crib_len;
    let mut positions = Positions::of(
        Settings::at(orders[0], 0, [0; 3], [0; 3]),
        reflector,
        reach,
    );
    let mut scratch = Scratch::new();

    let mut shown = 0u32;
    let mut survived = 0u32;
    for index in 0..26u32 * 26 * 26 {
        let settings = Settings::at(
            orders[0],
            0,
            [0; 3],
            [
                (index / (26 * 26)) as u8,
                ((index / 26) % 26) as u8,
                (index % 26) as u8,
            ],
        );
        positions.restart(settings, reach);
        shown += 1;
        if matches!(scan_with(menu, &positions, &mut scratch), Stop::Survived { .. }) {
            survived += 1;
        }
    }

    let rate = f64::from(survived) / f64::from(shown);
    println!(
        "  {} closures: {survived} of {shown} settings survived ({:.1}%), where counting loops predicts 100%",
        menu.closures(),
        100.0 * rate
    );
    if menu.closures() >= 1 {
        assert!(
            rate < 1.0,
            "a one-closure menu refuted nothing at all, so dropping it from a sweep would cost nothing"
        );
    }
    }
}

/// How much of the search space each crib in the shipped lists actually refutes.
///
/// The one number that decides whether a crib is worth an hour, measured rather than reasoned: the loop arithmetic that used to answer this was wrong by five orders of magnitude and wrong in both directions.
/// Short cribs matter because they are the ones that might really be in the message — a guess at twenty-eight letters of German has to be right twenty-eight times over — and the question is whether they still bite.
#[test]
#[ignore = "a measurement, not a check"]
fn how_much_each_shipped_crib_refutes() {
    use cipher_break::bombe::{Menu, Positions, Scratch, Stop, scan_with};
    use cipher_break::ciphers::enigma::{Settings, reflector_wiring, rotor_orders};
    use cipher_break::alphabet::ALPHABET;
    use cipher_break::crib::{KRIEGSMARINE, KRIEGSMARINE_LONG};

    let ct = cipher_break::to_letters(
        "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
    );
    let orders = rotor_orders(8);
    let reflector = reflector_wiring(0);
    let span = (ALPHABET as u32).pow(3);

    println!(
        "  {:<18} {:>4} {:>6} {:>8} {:>12} {:>9}",
        "crib", "len", "places", "closures", "survive", "naval cost"
    );
    for word in KRIEGSMARINE.iter().chain(KRIEGSMARINE_LONG) {
        let crib = to_letters(word);
        if crib.len() > ct.len() {
            continue;
        }
        let menus: Vec<Menu> = (0..=ct.len() - crib.len())
            .filter_map(|o| Menu::place(&ct, &crib, o))
            .filter(|m| m.closures() > 0)
            .collect();
        if menus.is_empty() {
            println!("  {word:<18} {:>4} {:>6}", crib.len(), 0);
            continue;
        }
        let reach = menus.iter().map(|m| m.offset + crib.len()).max().unwrap_or(0);
        let mut positions =
            Positions::of(Settings::at(orders[0], 0, [0; 3], [0; 3]), reflector, reach);
        let mut scratch = Scratch::new();

        let mut survived = 0u64;
        for index in 0..span {
            let settings = Settings::at(
                orders[0],
                0,
                [0; 3],
                [
                    (index / (ALPHABET as u32 * ALPHABET as u32)) as u8,
                    ((index / ALPHABET as u32) % ALPHABET as u32) as u8,
                    (index % ALPHABET as u32) as u8,
                ],
            );
            positions.restart(settings, reach);
            for menu in &menus {
                if matches!(scan_with(menu, &positions, &mut scratch), Stop::Survived { .. }) {
                    survived += 1;
                }
            }
        }
        let shown = u64::from(span) * menus.len() as u64;
        let rate = survived as f64 / shown as f64;
        // What a naval sweep of this crib would leave to decipher and score, at 1.9 microseconds each.
        let naval = rate * (336.0 * 104.0 * f64::from(span)) * menus.len() as f64;
        let closures: Vec<usize> = menus.iter().map(Menu::closures).collect();
        println!(
            "  {word:<18} {:>4} {:>6} {:>8} {:>11.4}% {:>8.0}s",
            crib.len(),
            menus.len(),
            format!(
                "{}-{}",
                closures.iter().min().copied().unwrap_or(0),
                closures.iter().max().copied().unwrap_or(0)
            ),
            100.0 * rate,
            naval * 1.893e-6 / 18.0
        );
    }
}

/// What a stop costs to judge along the path a sweep actually takes.
///
/// The first measurement of this timed deciphering and scoring and left out the candidate's key, which is a formatted string built for every stop whether or not the report will ever show it.
/// A weak crib stops billions of times, so anything paid per stop is paid billions of times.
#[test]
#[ignore = "a measurement, not a check"]
fn what_a_stop_costs_along_the_path_the_sweep_takes() {
    use cipher_break::ciphers::enigma::{Enigma, Plugboard, Settings};

    let ct = cipher_break::to_letters(
        "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
    );
    let bank = bank();
    let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
    let trace = Trace::new(false);
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default(),
        seed: 1,
        keep: 5,
        focus: None,
        focus_scale: None,
        trace: &trace,
    };
    let mut board = Plugboard::empty();
    for (a, b) in [(0u8, 20u8), (4, 12), (8, 15), (17, 2), (24, 9)] {
        board.connect(a, b);
    }
    let rounds = 20_000u32;

    // Warmed first, because the language tables are cold on the first pass and the first loop timed would otherwise be charged for filling the cache the second one reads.
    let mut sink = 0f64;
    for i in 0..rounds {
        let settings = Settings::at([0, 1, 2], 0, [0; 3], [(i % 26) as u8, 0, 0]);
        sink += ctx.score(&Enigma::new(settings, board).run(&ct));
    }

    let start = std::time::Instant::now();
    for i in 0..rounds {
        let settings = Settings::at([0, 1, 2], 0, [0; 3], [(i % 26) as u8, 0, 0]);
        let plain = Enigma::new(settings, board).run(&ct);
        sink += ctx.score(&plain);
    }
    let scoring = start.elapsed().as_nanos() as f64 / f64::from(rounds);

    let mut length = 0usize;
    let start = std::time::Instant::now();
    for i in 0..rounds {
        let settings = Settings::at([0, 1, 2], 0, [0; 3], [(i % 26) as u8, 0, 0]);
        let plain = Enigma::new(settings, board).run(&ct);
        let key = format!(
            "rotors {:?} {} start {} crib at {} plugs {}",
            settings.rotors.map(|r| r + 1),
            "B",
            cipher_break::from_letters(&settings.position_letters()),
            7,
            cipher_break::attack::describe_leads(&board)
        );
        length += key.len();
        sink += ctx.score(&plain);
    }
    let both = start.elapsed().as_nanos() as f64 / f64::from(rounds);

    println!("  decipher and score        {scoring:>8.0} ns");
    println!("  and build the key too     {both:>8.0} ns   ({:+.0} ns, {:.0}% more)", both - scoring, 100.0 * (both - scoring) / scoring);
    println!("  a crib stopping 2.7e9 times pays {:.0} s of that key, over 18 threads", 2.7e9 * (both - scoring) / 1e9 / 18.0);
    assert!(sink.is_finite() && length > 0);
}
