// SPDX-License-Identifier: MIT OR Apache-2.0

use cipher_break::alphabet::{Letter, from_letters, to_letters};
use cipher_break::anneal::Schedule;
use cipher_break::attack::{Attack, Context};
#[cfg(feature = "gpu")]
use cipher_break::ciphers::enigma::rotor_orders;
use cipher_break::ciphers::enigma::{
    Enigma, Plugboard, Settings, compatible, composite_reflector, naval_reflectors,
};
use cipher_break::enigma_types::{Indicator, Ring};
use cipher_break::ngram::Model;
use cipher_break::polyglot::{Polyglot, Scale};
use cipher_break::rng::Rng;
use cipher_break::trace::Trace;

const SIGNAL: &str = "VONVONJAWEGENDERSITUATIONXXMELDEICHXXFEINDKONVOIINSICHTXXMARQUADRATBE";

const LONG_SIGNAL: &str = "VONVONJAWEGENDERSITUATIONXXMELDEICHXXFEINDKONVOIINSICHTXXMARQUADRATBE\
                           XXDREISCHIFFEUNDZWEIZERSTOERERXXKURSNORDOSTXXGESCHWINDIGKEITACHTXX\
                           GREIFEBEIMORGENGRAUENANXXERBITTEUNTERSTUETZUNGDURCHZWEIBOOTEXXENDE";

const MIDDLE_RING_F: u8 = 5;

const RIGHT_RING_T: u8 = 19;

#[cfg(feature = "gpu")]
const RINGS_HELD: usize = 1;

#[cfg(feature = "gpu")]
const RINGS_SWEPT: usize = cipher_break::alphabet::ALPHABET;

#[cfg(feature = "gpu")]
const RANK_DEPTH: usize = 200_000;

#[cfg(feature = "gpu")]
const CROSS_CHECK_KEEP: usize = 4;

#[cfg(feature = "gpu")]
const PLANTED_SHORTLIST: usize = 60_000;

#[cfg(feature = "gpu")]
const PLANTED_FINISH: usize = 64;

const PLANTED_KEEP: usize = 5;

const PLANTED_SAMPLES: usize = 128;

pub struct Planted {
    pub label: &'static str,
    pub text: &'static str,
    pub rotors: [usize; 3],
    pub rings: [u8; 3],
    pub positions: [u8; 3],
    pub greek: (usize, u8, usize),
    pub plugs: &'static [(u8, u8)],
    pub sweep_rings: usize,
}

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
        label: "naval, short, right ring T",
        text: SIGNAL,
        rotors: [3, 1, 6],
        rings: [0, 0, RIGHT_RING_T],
        positions: [11, 4, 22],
        greek: (0, 9, 0),
        plugs: &[(1, 20), (8, 15), (17, 2)],
        sweep_rings: 26,
    },
    Planted {
        label: "naval, short, middle ring F",
        text: SIGNAL,
        rotors: [3, 1, 6],
        rings: [0, MIDDLE_RING_F, RIGHT_RING_T],
        positions: [11, 4, 22],
        greek: (0, 9, 0),
        plugs: &[(1, 20), (8, 15), (17, 2)],
        sweep_rings: 26,
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
    #[must_use]
    pub fn settings(&self) -> Settings {
        Settings {
            rotors: self.rotors,
            reflector: 0,
            rings: self.rings.map(Ring::new),
            positions: self.positions.map(Indicator::new),
        }
    }

    #[must_use]
    pub fn reflector(&self) -> [u8; cipher_break::alphabet::ALPHABET] {
        composite_reflector(self.greek.0, self.greek.1, self.greek.2)
    }

    #[must_use]
    pub fn reflector_index(&self) -> usize {
        self.greek.0 * 52 + self.greek.2 * 26 + self.greek.1 as usize
    }

    #[must_use]
    pub fn board(&self) -> Plugboard {
        let mut board = Plugboard::empty();
        for &(a, b) in self.plugs {
            board.connect(a, b);
        }
        board
    }

    #[must_use]
    pub fn plain(&self) -> Vec<Letter> {
        to_letters(self.text)
    }

    #[must_use]
    pub fn ciphertext(&self) -> Vec<Letter> {
        Enigma::with_reflector(self.settings(), self.reflector(), self.board()).run(&self.plain())
    }
}

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

fn bank() -> Polyglot {
    Polyglot::from_bundle(include_str!("../data/models.bundle"))
}

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

    #[test]
    #[ignore = "a measurement, not a check"]
    fn what_a_naval_bombe_costs_on_the_device() {
        use cipher_break::bombe::Menu;
        use cipher_break::ciphers::enigma::{ROTOR_COUNT, naval_reflectors, rotor_orders};

        let gpu = Gpu::open().expect("the requested GPU check requires a hardware device");
        let ct = cipher_break::to_letters(
            "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
        );
        let crib = to_letters("KEINEBESONDEREN");
        let menus: Vec<Menu> = (0..=ct.len() - crib.len())
            .filter_map(|o| Menu::place(&ct, &crib, o))
            .filter(|m| m.closures() > 0)
            .collect();
        let packed: Vec<cipher_break::gpu::PlacedMenu> = menus
            .iter()
            .map(|m| {
                let pairs = (0..crib.len())
                    .map(|i| (crib[i], ct[m.offset + i]))
                    .collect();
                (m.offset, pairs, m.hub())
            })
            .collect();
        let german = german().expect("the German model");
        let reflectors: Vec<[u8; 26]> = naval_reflectors().into_iter().map(|(_, w)| w).collect();
        let orders = rotor_orders(ROTOR_COUNT);

        let start = std::time::Instant::now();
        let found = gpu.sweep_bombe(&BombeJob {
            ct: &ct,
            logp: german.log_table(),
            order: german.order(),
            orders: &orders[..1],
            reflectors: &reflectors,
            menus: &packed,
            rings: 1,
            middles: 1,
            keep: 5,
        });
        let one = start.elapsed().as_secs_f64();

        println!("  crib {} letters, {} placements", crib.len(), menus.len());
        println!(
            "  one rotor order          {one:>8.2} s   {} stops",
            found.stops
        );
        println!(
            "  all {} orders         {:>8.1} min",
            orders.len(),
            one * orders.len() as f64 / 60.0
        );
        println!("  the processor took about 22 min for a crib of this size");
        if let Some(top) = found.best.first() {
            println!(
                "  best {:+.3} at menu {} guess {}",
                top.score, top.menu, top.guess
            );
        }
    }

    use cipher_break::attack::{GpuEnigmaNaval, LEAD_MARGIN, climb_plugboard};
    use cipher_break::gpu::{BombeJob, EnigmaHit, EnigmaJob, Gpu};

    #[test]
    #[ignore = "a rotor sweep, and it needs a device"]
    fn the_device_refutes_exactly_what_the_processor_refutes() {
        use cipher_break::bombe::{Menu, Positions, Scratch, Stop, scan_with};
        use cipher_break::ciphers::enigma::{Settings, reflector_wiring};

        let gpu = Gpu::open().expect("the requested GPU check requires a hardware device");
        let (plain, ct) = planted_bombe_message();
        let crib = to_letters("VONVONJAWE");
        let menus: Vec<Menu> = (0..=ct.len() - crib.len())
            .filter_map(|o| Menu::place(&ct, &crib, o))
            .filter(|m| m.closures() > 0)
            .collect();
        assert!(!menus.is_empty(), "the crib has to sit somewhere");

        let orders = vec![[2usize, 0, 4]];
        let reflector = reflector_wiring(0);
        let bank = bank();
        let german = german().expect("the German model");

        let packed: Vec<cipher_break::gpu::PlacedMenu> = menus
            .iter()
            .map(|m| {
                let pairs: Vec<(u8, u8)> = (0..crib.len())
                    .map(|i| (crib[i], ct[m.offset + i]))
                    .collect();
                (m.offset, pairs, m.hub())
            })
            .collect();

        let found = gpu.sweep_bombe(&BombeJob {
            ct: &ct,
            logp: german.log_table(),
            order: german.order(),
            orders: &orders,
            reflectors: &[reflector],
            menus: &packed,
            rings: 1,
            middles: 1,
            keep: 8,
        });

        let mut expected: u64 = 0;
        let reach = menus
            .iter()
            .map(|m| m.offset + crib.len())
            .max()
            .expect("a menu");
        let mut positions =
            Positions::of(Settings::at(orders[0], 0, [0; 3], [0; 3]), reflector, reach);
        let mut scratch = Scratch::new();
        for index in 0..26u32 * 26 * 26 {
            let settings = Settings::at(
                orders[0],
                0,
                [0; 3],
                [
                    (index / 676) as u8,
                    ((index / 26) % 26) as u8,
                    (index % 26) as u8,
                ],
            );
            positions.restart(settings, reach);
            for menu in &menus {
                if matches!(
                    scan_with(menu, &positions, &mut scratch),
                    Stop::Survived { .. }
                ) {
                    expected += 1;
                }
            }
        }

        println!("  processor {expected} stops, device {} stops", found.stops);
        assert!(expected > 0, "a comparison of two zeroes proves nothing");
        assert_eq!(
            found.stops, expected,
            "the two bombes disagree about which settings survive"
        );

        let truth = [7u8, 19, 3];
        let mut kept = false;
        for menu in &menus {
            positions.restart(Settings::at(orders[0], 0, [0; 3], truth), reach);
            if matches!(
                scan_with(menu, &positions, &mut scratch),
                Stop::Survived { .. }
            ) {
                kept = true;
            }
        }
        assert!(kept, "a bombe that refutes the true setting is broken");
        let _ = (&plain, &bank);
    }

    #[test]
    #[ignore = "a rotor sweep with the rings in it, and it needs a device"]
    fn a_bombe_with_the_rings_swept_keeps_a_ring_away_from_a() {
        use cipher_break::bombe::{Menu, Positions, Scratch, Stop, scan_with};
        use cipher_break::ciphers::enigma::{Settings, reflector_wiring};

        let gpu = Gpu::open().expect("the requested GPU check requires a hardware device");
        for (rotors, ring) in [([2usize, 0, 4], 13u8), ([2, 6, 5], 10)] {
            let truth = Settings::at(rotors, 0, [0, 0, ring], [7, 19, 3 + ring]);
            let mut board = Plugboard::empty();
            for (a, b) in [(0u8, 20u8), (4, 12), (8, 15), (17, 2), (24, 9)] {
                board.connect(a, b);
            }
            let plain = to_letters(SIGNAL);
            let ct = Enigma::new(truth, board).run(&plain);
            let crib = to_letters("VONVONJAWEGENDERSITUATION");
            let menus: Vec<Menu> = (0..=ct.len() - crib.len())
                .filter_map(|o| Menu::place(&ct, &crib, o))
                .filter(|m| m.closures() > 0)
                .collect();
            let at_start = menus
                .iter()
                .position(|m| m.offset == 0)
                .expect("the crib sits at the start and closes a loop there");
            let reach = menus
                .iter()
                .map(|m| m.offset + crib.len())
                .max()
                .expect("a menu");
            let reflector = reflector_wiring(0);
            let mut scratch = Scratch::new();
            let survives = |settings: Settings, scratch: &mut Scratch| {
                let positions = Positions::of(settings, reflector, reach);
                matches!(
                    scan_with(&menus[at_start], &positions, scratch),
                    Stop::Survived { .. }
                )
            };

            let held = Settings::at(rotors, 0, [0; 3], [7, 19, 3]);
            assert!(
                !survives(held, &mut scratch),
                "the rings-at-A copy of the truth should be refuted, or this test is not testing the rings"
            );
            assert!(
                survives(truth, &mut scratch),
                "the true setting has to survive its own crib"
            );

            let packed: Vec<cipher_break::gpu::PlacedMenu> = menus
                .iter()
                .map(|m| {
                    let pairs: Vec<(u8, u8)> = (0..crib.len())
                        .map(|i| (crib[i], ct[m.offset + i]))
                        .collect();
                    (m.offset, pairs, m.hub())
                })
                .collect();
            let german = german().expect("the German model");
            let found = gpu.sweep_bombe(&BombeJob {
                ct: &ct,
                logp: german.log_table(),
                order: german.order(),
                orders: &[rotors],
                reflectors: &[reflector],
                menus: &packed,
                rings: 26,
                middles: 26,
                keep: 64,
            });

            let expected = processor_stops_with_rings(rotors, reflector, &menus, reach);
            println!("  processor {expected} stops, device {} stops", found.stops);
            assert_eq!(
                found.stops, expected,
                "the two bombes disagree about which settings survive"
            );
            let read = found.best.iter().any(|h| {
                let settings = Settings::at(
                    rotors,
                    0,
                    [0, h.middle.value(), h.ring.value()],
                    h.positions.map(Indicator::value),
                );
                Enigma::new(settings, Plugboard::empty()).run(&ct)
                    == Enigma::new(truth, Plugboard::empty()).run(&ct)
            });
            assert!(
                read,
                "the device's best stops do not include the setting the message was enciphered on"
            );
        }
    }

    #[test]
    #[ignore = "a diagnostic, not a check"]
    fn where_each_stage_leaves_the_truth_on_one_order() {
        let bank = bank();
        let model = bank.model_named("de").expect("german");
        let quad = german().expect("the German quadgram model");
        let named = naval_reflectors();
        let wirings: Vec<[u8; cipher_break::alphabet::ALPHABET]> =
            named.iter().map(|(_, r)| *r).collect();
        let gpu = Gpu::open().expect("a device");
        for case in CASES
            .iter()
            .filter(|c| c.sweep_rings == 26 && c.text == SIGNAL)
        {
            let ct = case.ciphertext();
            let orders = vec![case.rotors];
            let truth =
                Enigma::with_reflector(case.settings(), case.reflector(), Plugboard::empty())
                    .run(&ct);
            let settings_of = |h: &EnigmaHit| Settings {
                rotors: orders[h.order],
                reflector: 0,
                rings: [Ring::new(0), h.middle, h.ring],
                positions: h.positions,
            };
            let is_truth = |h: &EnigmaHit| {
                Enigma::with_reflector(settings_of(h), wirings[h.reflector], Plugboard::empty())
                    .run(&ct)
                    == truth
            };
            let job = EnigmaJob {
                ct: &ct,
                logp: model.log_table(),
                order: model.order(),
                orders: &orders,
                reflectors: &wirings,
                rings: 26,
                middles: 26,
                keep: 1_000_000,
            };
            let found = gpu.sweep_enigma(&job);
            println!(
                "  {:<28} truth scores {:.4} with no board; kept run {:.4} down to {:.4}",
                case.label,
                model.score(&truth),
                found[0].score,
                found[found.len() - 1].score
            );
            let swept = found.iter().position(is_truth);
            let copies = found.iter().filter(|h| is_truth(h)).count();
            let boards = gpu.climb_plugboards(&job, &found, case.plugs.len(), LEAD_MARGIN as f32);
            let grams = ct.len() + 1 - model.order();
            let cost = (cipher_break::attack::PLUGBOARD_PAIRS as f64).ln() / grams as f64;
            let mut ranked: Vec<(f64, usize)> = boards
                .iter()
                .enumerate()
                .map(|(i, &(score, mapping))| {
                    (
                        score - cost * Plugboard::from_mapping(mapping).pairs().len() as f64,
                        i,
                    )
                })
                .collect();
            ranked.sort_unstable_by(|a, b| b.0.total_cmp(&a.0));
            let climbed = ranked.iter().position(|&(_, i)| is_truth(&found[i]));
            let qgrams = ct.len() + 1 - quad.order();
            let qcost = (cipher_break::attack::PLUGBOARD_PAIRS as f64).ln() / qgrams as f64;
            let mut requad: Vec<(f64, usize)> = ranked
                .iter()
                .take(60_000)
                .map(|&(_, i)| {
                    let board = Plugboard::from_mapping(boards[i].1);
                    let plain = Enigma::with_reflector(
                        settings_of(&found[i]),
                        wirings[found[i].reflector],
                        board,
                    )
                    .run(&ct);
                    (quad.score(&plain) - qcost * board.pairs().len() as f64, i)
                })
                .collect();
            requad.sort_unstable_by(|a, b| b.0.total_cmp(&a.0));
            let reranked = requad.iter().position(|&(_, i)| is_truth(&found[i]));
            println!(
                "  {:<28} kept {}, truth swept {swept:?} ({copies} copies), climbed {climbed:?}, reranked {reranked:?}",
                case.label,
                found.len()
            );
        }
    }

    fn processor_stops_with_rings(
        rotors: [usize; 3],
        reflector: [u8; cipher_break::alphabet::ALPHABET],
        menus: &[cipher_break::bombe::Menu],
        reach: usize,
    ) -> u64 {
        use cipher_break::bombe::{Positions, Scratch, Stop, scan_with};

        let mut scratch = Scratch::new();
        let mut expected: u64 = 0;
        let mut positions =
            Positions::of(Settings::at(rotors, 0, [0; 3], [0; 3]), reflector, reach);
        for middle in 0..26u8 {
            for ring in 0..26u8 {
                positions.aim(
                    Settings::at(rotors, 0, [0, middle, ring], [0; 3]),
                    reflector,
                    reach,
                );
                for p in 0..26u32 * 26 * 26 {
                    let start = [(p / 676) as u8, ((p / 26) % 26) as u8, (p % 26) as u8];
                    if cipher_break::ciphers::enigma::rings_repeat(
                        rotors,
                        start[1],
                        start[2],
                        (middle, ring),
                        reach,
                    ) {
                        continue;
                    }
                    positions.restart(Settings::at(rotors, 0, [0, middle, ring], start), reach);
                    for menu in menus {
                        if matches!(
                            scan_with(menu, &positions, &mut scratch),
                            Stop::Survived { .. }
                        ) {
                            expected += 1;
                        }
                    }
                }
            }
        }
        expected
    }

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
                middles: case.sweep_rings,
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
                middles: rings,
                keep: CROSS_CHECK_KEEP,
            });
            let hit = hits[0];
            let rebuilt = Settings {
                rotors: orders[hit.order],
                reflector: 0,
                rings: [Ring::new(0), hit.middle, hit.ring],
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

    #[test]
    #[ignore = "needs a GPU; run with --ignored"]
    fn climbs_a_plugboard_exactly_as_the_processor_does() {
        let bank = bank();
        let model = bank.model_named("de").expect("german");
        let orders = rotor_orders(8);
        let wirings: Vec<[u8; cipher_break::alphabet::ALPHABET]> =
            naval_reflectors().iter().map(|(_, r)| *r).collect();
        let gpu = Gpu::open().expect("a device");

        for case in CASES {
            let ct = case.ciphertext();
            let order = orders
                .iter()
                .position(|&o| o == case.rotors)
                .expect("order");
            assert_eq!(case.rings[0], 0, "the sweep holds the left ring at A");
            let hit = EnigmaHit {
                score: 0.0,
                order,
                reflector: case.reflector_index(),
                middle: Ring::new(case.rings[1]),
                ring: Ring::new(case.rings[2]),
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
                    middles: 1,
                    keep: CROSS_CHECK_KEEP,
                },
                &[hit],
                case.plugs.len(),
                LEAD_MARGIN as f32,
            );

            let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
            let trace = Trace::new(false);
            let ctx = context(&bank, &scale, Some(model), None, &trace, 1);
            let (cpu_board, _, cpu_plain) = climb_plugboard(
                case.settings(),
                wirings[case.reflector_index()],
                case.plugs.len(),
                LEAD_MARGIN,
                &ct,
                &ctx,
            );
            let here = model.score(&cpu_plain);
            let board = Plugboard::from_mapping(device[0].1);
            assert_eq!(
                board, cpu_board,
                "{}: CPU and GPU must climb with the same judge",
                case.label
            );
            let device_board_here = model
                .score(&Enigma::with_reflector(case.settings(), case.reflector(), board).run(&ct));
            println!(
                "  {:<28} device {:.4} ({device_board_here:.4} here, {} leads), processor {here:.4}",
                case.label,
                device[0].0,
                board.pairs().len()
            );
            assert!(
                (device[0].0 - device_board_here).abs() < 1e-4,
                "{}: device scored its board {:.4}, the processor scores that board {device_board_here:.4}",
                case.label,
                device[0].0
            );
        }
    }

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
                middles: case.sweep_rings,
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

fn short_board() -> Plugboard {
    let mut board = Plugboard::empty();
    for (a, b) in [
        (1u8, 20u8),
        (8, 15),
        (17, 2),
        (0, 12),
        (3, 24),
        (5, 19),
        (6, 14),
        (7, 22),
        (9, 16),
        (10, 25),
    ] {
        board.connect(a, b);
    }
    board
}

#[cfg(feature = "gpu")]
fn short_signal_with_ten_leads(plain: &[Letter], starts: [u8; 3]) -> Vec<Letter> {
    let settings = Settings::at([2, 0, 1], 0, [0, MIDDLE_RING_F, RIGHT_RING_T], starts);
    Enigma::with_reflector(settings, composite_reflector(0, 9, 0), short_board()).run(plain)
}

#[test]
fn completing_the_board_preserves_the_short_signals_full_plaintext() {
    use cipher_break::attack::{complete_boards, score_outside_the_crib};
    let plain =
        to_letters("TTTFFFZWOVIERVVVFXDXUUUXAUSBXXTRAVEMUENDEBLEIBENXWEITEREBEFEHLEATWARTKNX");
    let settings = Settings::at([2, 0, 1], 0, [0, MIDDLE_RING_F, RIGHT_RING_T], [11, 4, 10]);
    let reflector = composite_reflector(0, 9, 0);
    let board = short_board();
    let ct = Enigma::with_reflector(settings, reflector, board).run(&plain);
    let bank = bank();
    let model = german()
        .expect("German model")
        .supplemented(&to_letters(include_str!(
            "../data/p1030680/model-corpus.txt"
        )));
    let scale = Scale::build(&bank, ct.len(), 128, &mut Rng::new(1));
    let focus_scale = Scale::for_model(&model, ct.len(), 128, &mut Rng::new(2));
    let trace = Trace::new(false);
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default(),
        seed: 1,
        keep: 5,
        trace: &trace,
        focus: Some(&model),
        focus_scale: Some(&focus_scale),
    };
    let found = complete_boards(
        settings,
        reflector,
        (board, (1 << 26) - 1),
        10,
        16,
        &ct,
        &ctx,
    );
    assert!(found.iter().any(|(_, _, read)| *read == plain));
    assert!(
        found.iter().any(|(_, _, read)| {
            *read != plain
                && score_outside_the_crib(read, &ctx, 0, 16)
                    > score_outside_the_crib(&plain, &ctx, 0, 16)
        }),
        "language ranking must not erase a compatible key"
    );
    for (key, plugs, read) in found {
        assert_eq!(read[..16], plain[..16]);
        assert_eq!(Enigma::with_reflector(key, reflector, plugs).run(&read), ct);
    }
}

#[test]
fn a_short_true_crib_without_a_loop_requires_a_longer_menu() {
    let plain =
        to_letters("TTTFFFZWOVIERVVVFXDXUUUXAUSBXXTRAVEMUENDEBLEIBENXWEITEREBEFEHLEATWARTKNX");
    let settings = Settings::at([2, 0, 1], 0, [0, MIDDLE_RING_F, RIGHT_RING_T], [11, 4, 10]);
    let ct =
        Enigma::with_reflector(settings, composite_reflector(0, 9, 0), short_board()).run(&plain);
    let menu = |length| cipher_break::bombe::Menu::place(&ct, &plain[..length], 0).unwrap();
    assert_eq!(menu(14).closures(), 0);
    assert!(menu(24).closures() > 0);
}

#[cfg(feature = "gpu")]
fn verify_short_key(candidate: &cipher_break::attack::Candidate, ciphertext: &[Letter]) {
    assert!(
        candidate
            .key
            .starts_with("rotors [3, 1, 2] beta/J B-thin rings ")
    );
    assert!(
        candidate
            .key
            .ends_with(&cipher_break::attack::describe_leads(&short_board()))
    );
    let letters_after = |marker: &str| -> [u8; 3] {
        to_letters(
            candidate
                .key
                .split_once(marker)
                .unwrap()
                .1
                .split_whitespace()
                .next()
                .unwrap(),
        )
        .try_into()
        .unwrap()
    };
    let key = Settings::at(
        [2, 0, 1],
        0,
        letters_after(" rings "),
        letters_after(" start "),
    );
    assert_eq!(
        Enigma::with_reflector(key, composite_reflector(0, 9, 0), short_board())
            .run(&candidate.plain),
        ciphertext
    );
}

#[cfg(feature = "gpu")]
fn check_wide_shuffles(
    attack: &cipher_break::attack::BombeAttack,
    ct: &[Letter],
    plain: &[Letter],
    ctx: &Context,
    truth_score: f64,
) {
    let mut rng = Rng::new(20_261_002);
    let mut exceeds = 0;
    for i in 0..8 {
        let shuffled = rng.shuffled(ct);
        let controls = attack.best(&shuffled, ctx);
        assert!(controls.iter().all(|c| c.plain != plain));
        let score = controls.first().map_or(f64::NEG_INFINITY, |c| c.score);
        println!("identical six-order/104-reflector shuffle search {i}: {score:.6}");
        exceeds += usize::from(score >= truth_score);
    }
    println!(
        "pilot empirical p: {}/9; eight controls do not establish p < 0.001",
        exceeds + 1
    );
    assert_eq!(
        exceeds, 0,
        "the matched null must not outrank the known reading"
    );
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "a bombe with the rings swept over six rotor orders; needs a device"]
fn a_ring_swept_bombe_reads_a_short_signal_with_ten_leads() {
    use cipher_break::attack::BombeAttack;
    use cipher_break::gpu::Gpu;

    let gpu = Gpu::open().expect("the requested GPU check requires a hardware device");
    let gpu = std::sync::Arc::new(gpu);
    let text = "TTTFFFZWOVIERVVVFXDXUUUXAUSBXXTRAVEMUENDEBLEIBENXWEITEREBEFEHLEATWARTKNX";
    let plain = to_letters(text);
    for (starts, lengths) in [([11u8, 4, 22], [16usize, 14]), ([11, 4, 10], [16, 24])] {
        let ct = short_signal_with_ten_leads(&plain, starts);
        let bank = bank();
        let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
        let quad = german()
            .expect("German model")
            .supplemented(&to_letters(include_str!(
                "../data/p1030680/model-corpus.txt"
            )));
        let quad_scale = Scale::for_model(&quad, ct.len(), PLANTED_SAMPLES, &mut Rng::new(2));
        let trace = Trace::new(false);
        let ctx = Context {
            judge: &bank,
            scale: &scale,
            plan: Schedule::default(),
            seed: 1,
            keep: 5,
            focus: Some(&quad),
            focus_scale: Some(&quad_scale),
            trace: &trace,
        };
        for length in lengths {
            let crib = to_letters(&text[..length]);
            assert!(
                cipher_break::bombe::Menu::place(&ct, &crib, 0).is_some_and(|m| m.closures() > 0),
                "the planted recovery check must exercise a closing menu"
            );
            let attack = BombeAttack {
                gpu: Some(gpu.clone()),
                stops: std::sync::atomic::AtomicU64::new(0),
                finished: std::sync::atomic::AtomicU64::new(0),
                shapes: std::sync::Mutex::new(Vec::new()),
                crib: crib.clone(),
                label: "a short signal".to_string(),
                rotors_available: 3,
                naval: true,
                rings: true,

                middles: true,
                at: Some(0),
                finish: 64,
            };
            let start = std::time::Instant::now();
            let found = attack.best(&ct, &ctx);
            let standing = attack.stops.load(std::sync::atomic::Ordering::Relaxed);
            let rank = found
                .iter()
                .position(|c| c.plain == plain)
                .expect("the full key must survive the actual 64-stop, five-reading limits");
            let truth = &found[rank];
            verify_short_key(truth, &ct);
            println!(
                "  starts {starts:?}, crib {length}: {standing} stops, {} finished, {:.0}s; exact plaintext at rank {rank}, held-out score {:+.6}",
                attack.finished.load(std::sync::atomic::Ordering::Relaxed),
                start.elapsed().as_secs_f64(),
                truth.score
            );
            println!(
                "         {}\n         {}",
                truth.key,
                from_letters(&truth.plain)
            );
            if starts == [11, 4, 10] && length == 16 {
                check_wide_shuffles(&attack, &ct, &plain, &ctx, truth.score);
            }
        }
    }
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "a bombe with the right ring swept over six rotor orders; needs a device"]
fn a_right_ring_sweep_reads_the_short_signal_too() {
    use cipher_break::attack::BombeAttack;
    use cipher_break::gpu::Gpu;

    let gpu = Gpu::open().expect("the requested GPU check requires a hardware device");
    let text = "TTTFFFZWOVIERVVVFXDXUUUXAUSBXXTRAVEMUENDEBLEIBENXWEITEREBEFEHLEATWARTKNX";
    let plain = to_letters(text);
    let ct = short_signal_with_ten_leads(&plain, [11, 4, 22]);
    let bank = bank();
    let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
    let quad = german().expect("the German quadgram model");
    let quad_scale = Scale::for_model(&quad, ct.len(), PLANTED_SAMPLES, &mut Rng::new(2));
    let trace = Trace::new(false);
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default(),
        seed: 1,
        keep: 5,
        focus: Some(&quad),
        focus_scale: Some(&quad_scale),
        trace: &trace,
    };
    let attack = BombeAttack {
        gpu: Some(std::sync::Arc::new(gpu)),
        stops: std::sync::atomic::AtomicU64::new(0),
        finished: std::sync::atomic::AtomicU64::new(0),
        shapes: std::sync::Mutex::new(Vec::new()),
        crib: to_letters(&text[..16]),
        label: "a short signal".to_string(),
        rotors_available: 3,
        naval: true,
        rings: true,
        middles: false,
        at: Some(0),
        finish: cipher_break::attack::BOMBE_FINISH,
    };
    let found = attack.best(&ct, &ctx);
    let top = found
        .first()
        .expect("the true setting's copy is never refuted");
    println!(
        "  {:+.2}s {}\n         {}",
        top.score,
        top.key,
        from_letters(&top.plain)
    );
    assert_eq!(
        top.plain, plain,
        "the finish has to find the middle ring the sweep held at A"
    );
}

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
        #[cfg(feature = "gpu")]
        gpu: None,
        stops: std::sync::atomic::AtomicU64::new(0),
        finished: std::sync::atomic::AtomicU64::new(0),
        shapes: std::sync::Mutex::new(Vec::new()),
        crib,
        label: "VONVONJAWEGENDERSITUATIONXXMELDEICHXX".to_string(),
        rotors_available: 5,
        naval: false,
        rings: false,

        middles: false,
        at: None,
        finish: cipher_break::attack::BOMBE_FINISH,
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

#[cfg(feature = "gpu")]
#[test]
#[ignore = "a measurement, not an assertion; run with --ignored --nocapture"]
fn where_the_bombe_spends_its_time() {
    use cipher_break::bombe::{Menu, Positions, Scratch, scan_with};
    use cipher_break::crib::placements;
    use std::time::Instant;

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

#[test]
fn a_bombe_offers_no_null_of_its_own() {
    use cipher_break::attack::{Attack, BombeAttack};

    let (_, ct) = planted_bombe_message();
    let attack = BombeAttack {
        #[cfg(feature = "gpu")]
        gpu: None,
        stops: std::sync::atomic::AtomicU64::new(0),
        finished: std::sync::atomic::AtomicU64::new(0),
        shapes: std::sync::Mutex::new(Vec::new()),
        crib: to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXX"),
        label: "no self-calibration".to_string(),
        rotors_available: 5,
        naval: false,
        rings: false,

        middles: false,
        at: None,
        finish: cipher_break::attack::BOMBE_FINISH,
    };
    assert_eq!(
        attack.own_null(),
        Some(Vec::new()),
        "a null of no points, so no margin can be computed and no reading declared from one"
    );
    let _ = ct;
}

#[test]
fn a_weak_menu_still_refutes_most_of_what_it_is_shown() {
    use cipher_break::bombe::{Menu, Positions, Scratch, Stop, scan_with};
    use cipher_break::ciphers::enigma::{Settings, rotor_orders};

    let ct = cipher_break::to_letters(
        "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
    );
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
        let crib_len = menu.edges.len();
        let orders = rotor_orders(5);
        let reflector = cipher_break::ciphers::enigma::reflector_wiring(0);
        let reach = menu.offset + crib_len;
        let mut positions =
            Positions::of(Settings::at(orders[0], 0, [0; 3], [0; 3]), reflector, reach);
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
            if matches!(
                scan_with(menu, &positions, &mut scratch),
                Stop::Survived { .. }
            ) {
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

#[test]
#[ignore = "a measurement, not a check"]
fn how_much_each_shipped_crib_refutes() {
    use cipher_break::alphabet::ALPHABET;
    use cipher_break::bombe::{Menu, Positions, Scratch, Stop, scan_with};
    use cipher_break::ciphers::enigma::{Settings, reflector_wiring, rotor_orders};
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
        let reach = menus
            .iter()
            .map(|m| m.offset + crib.len())
            .max()
            .unwrap_or(0);
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
                if matches!(
                    scan_with(menu, &positions, &mut scratch),
                    Stop::Survived { .. }
                ) {
                    survived += 1;
                }
            }
        }
        let shown = u64::from(span) * menus.len() as u64;
        let rate = survived as f64 / shown as f64;
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
    println!(
        "  and build the key too     {both:>8.0} ns   ({:+.0} ns, {:.0}% more)",
        both - scoring,
        100.0 * (both - scoring) / scoring
    );
    println!(
        "  a crib stopping 2.7e9 times pays {:.0} s of that key, over 18 threads",
        2.7e9 * (both - scoring) / 1e9 / 18.0
    );
    assert!(sink.is_finite() && length > 0);
}

#[test]
fn a_bombe_is_not_credited_with_the_crib_it_planted() {
    use cipher_break::attack::score_outside_the_crib;

    let bank = bank();
    let ct = cipher_break::to_letters(
        "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
    );
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

    let noise = cipher_break::to_letters(
        "DRWIBTARUAXRMGLDIRBEINSSTANDORTSZIIRNAMTIMULTRECEMMTAMMKMAEIURFFFNGOEOJO",
    );
    let whole = ctx.score(&noise);
    let outside = score_outside_the_crib(&noise, &ctx, 23, 8);
    println!("  whole {whole:+.2}s, without the planted crib {outside:+.2}s");
    assert!(
        outside < whole,
        "cutting out eight letters of fluent German should lower the score, not raise it"
    );

    let german = cipher_break::to_letters(
        "KEINEBESONDERENVORKOMMNISSEXXSTANDORTMARQUADRATSIEBENXXWETTERBERICHTXXAB",
    );
    let both = (
        ctx.score(&german),
        score_outside_the_crib(&german, &ctx, 23, 8),
    );
    println!(
        "  real German {:+.2}s, without eight of its letters {:+.2}s",
        both.0, both.1
    );
    assert!(
        both.1 > whole,
        "real German minus a crib should still beat noise plus a crib: {:+.2} vs {whole:+.2}",
        both.1
    );
}

#[test]
#[ignore = "a measurement, not a check"]
fn what_the_best_of_a_big_search_scores_on_nothing() {
    use cipher_break::ciphers::enigma::{Enigma, Plugboard, Settings, rotor_orders};

    let ct = cipher_break::to_letters(
        "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
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
        keep: 5,
        focus: focus.as_ref(),
        focus_scale: focus_scale.as_ref(),
        trace: &trace,
    };

    let orders = rotor_orders(8);
    let mut rng = Rng::new(99);
    let mut scores = Vec::with_capacity(40_000);
    for _ in 0..40_000 {
        let rotors = orders[rng.below(orders.len())];
        let pick = |r: &mut Rng| [r.below(26) as u8, r.below(26) as u8, r.below(26) as u8];
        let mut board = Plugboard::empty();
        let mut free: Vec<u8> = (0..26).collect();
        for _ in 0..10 {
            let a = free.swap_remove(rng.below(free.len()));
            let b = free.swap_remove(rng.below(free.len()));
            board.connect(a, b);
        }
        let settings = Settings::at(rotors, 0, pick(&mut rng), pick(&mut rng));
        scores.push(ctx.score(&Enigma::new(settings, board).run(&ct)));
    }
    let (mean, sd) = cipher_break::stats::moments(&scores);
    println!("  a random naval decipherment of this message scores {mean:+.2} +/- {sd:.2}");

    println!("  {:>10}  {:>9}  {:>9}", "block", "best of it", "predicted");
    let mut points: Vec<(f64, f64)> = Vec::new();
    for size in [100usize, 400, 1_600, 6_400, 25_600] {
        let mut tops: Vec<f64> = scores
            .chunks(size)
            .filter(|c| c.len() == size)
            .map(|c| c.iter().copied().fold(f64::NEG_INFINITY, f64::max))
            .collect();
        if tops.is_empty() {
            continue;
        }
        tops.sort_by(f64::total_cmp);
        let median = tops[tops.len() / 2];
        let guess = mean + sd * (2.0 * (size as f64).ln()).sqrt();
        println!("  {size:>10}  {median:>9.2}  {guess:>9.2}");
        points.push(((size as f64).ln(), median));
    }
    let n = points.len() as f64;
    let sx: f64 = points.iter().map(|p| p.0).sum();
    let sy: f64 = points.iter().map(|p| p.1).sum();
    let sxy: f64 = points.iter().map(|p| p.0 * p.1).sum();
    let sxx: f64 = points.iter().map(|p| p.0 * p.0).sum();
    let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    let intercept = (sy - slope * sx) / n;
    println!("  measured growth: best of N sits near {intercept:+.2} + {slope:.3} * ln N");
    for (name, count, seen) in [
        ("KEINEBESONDEREN", 4_630_211f64, 8.4),
        ("MELDE", 643_910_834.0, 11.7),
        ("GELEITZUG", 2_972_677_852.0, 10.4),
    ] {
        let bar = intercept + slope * count.ln();
        println!(
            "  {name:<16} {count:>15.0} stops, noise would reach {bar:>6.2}, seen {seen:>5.1}  {}",
            if seen > bar { "ABOVE" } else { "below" }
        );
    }
    println!("  and real German of this length reaches +18.0");
}

#[test]
#[ignore = "a measurement, not a check"]
fn how_much_of_the_middle_ring_is_new() {
    use cipher_break::ciphers::enigma::{Enigma, Plugboard, Settings, rotor_orders};

    let ct = cipher_break::to_letters(
        "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
    );
    let orders = rotor_orders(8);
    let mut rng = Rng::new(808);
    let trials = 20_000;
    let mut differs = 0u32;

    for _ in 0..trials {
        let rotors = orders[rng.below(orders.len())];
        let p0 = rng.below(26) as u8;
        let p1 = rng.below(26) as u8;
        let p2 = rng.below(26) as u8;
        let right = rng.below(26) as u8;
        let m = rng.below(26) as u8;

        let with_ring = Settings::at(rotors, 0, [0, m, right], [p0, p1, p2]);
        let shifted = Settings::at(rotors, 0, [0, 0, right], [p0, (p1 + 26 - m) % 26, p2]);

        let a = Enigma::new(with_ring, Plugboard::empty()).run(&ct);
        let b = Enigma::new(shifted, Plugboard::empty()).run(&ct);
        if a != b {
            differs += 1;
        }
    }
    let share = f64::from(differs) / f64::from(trials);
    println!(
        "  {:.1}% of middle-ring settings decipher differently from one the sweep already covers",
        100.0 * share
    );
    println!(
        "  so the space is about {:.1}x the ring-A sweep, not 26x",
        1.0 + 25.0 * share
    );
}

#[test]
#[ignore = "a measurement, not a check"]
fn how_many_wrong_settings_outscore_a_true_one() {
    use cipher_break::ciphers::enigma::{Enigma, Plugboard, Settings, rotor_orders};

    let case = &CASES[2];
    let ct = case.ciphertext();
    let bank = bank();
    let german = bank.model_named("de").expect("german");
    let truth = german.score(
        &Enigma::with_reflector(case.settings(), case.reflector(), Plugboard::empty()).run(&ct),
    );

    let orders = rotor_orders(8);
    let reflectors = cipher_break::ciphers::enigma::naval_reflectors();
    let mut rng = Rng::new(404);
    let trials = 200_000;
    let mut above = 0u32;
    for _ in 0..trials {
        let rotors = orders[rng.below(orders.len())];
        let reflector = reflectors[rng.below(reflectors.len())].1;
        let pick = |r: &mut Rng| [r.below(26) as u8, r.below(26) as u8, r.below(26) as u8];
        let rings = [0, 0, rng.below(26) as u8];
        let settings = Settings::at(rotors, 0, rings, pick(&mut rng));
        let s =
            german.score(&Enigma::with_reflector(settings, reflector, Plugboard::empty()).run(&ct));
        if s >= truth {
            above += 1;
        }
    }
    let share = f64::from(above) / f64::from(trials);
    let space = 336.0 * 104.0 * 26.0 * 26f64.powi(3);
    println!("  the true setting scores {truth:.4}");
    println!(
        "  {:.2}% of wrong settings score at least that much",
        100.0 * share
    );
    println!(
        "  over {space:.3e} settings that is {:.3e} of them ahead of the truth",
        share * space
    );
    println!("  a shortlist would have to be that long before the truth was in it");
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "a sixteen-billion sweep and a million plugboard climbs"]
fn the_naval_attack_breaks_a_short_message_with_the_rings_swept() {
    use cipher_break::attack::{Attack, ENIGMA_LEADS, GpuEnigmaNaval};
    use cipher_break::gpu::Gpu;

    let gpu = Gpu::open().expect("the requested GPU check requires a hardware device");
    let gpu = std::sync::Arc::new(gpu);
    let mut failed = Vec::new();
    for case in CASES
        .iter()
        .filter(|c| c.sweep_rings == 26 && c.text == SIGNAL)
    {
        let ct = case.ciphertext();
        let plain = to_letters(case.text);
        let bank = bank();
        let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
        let quad = german().expect("the German quadgram model");
        let quad_scale = Scale::for_model(&quad, ct.len(), PLANTED_SAMPLES, &mut Rng::new(2));
        let trace = Trace::new(false);
        let ctx = Context {
            judge: &bank,
            scale: &scale,
            plan: Schedule::default(),
            seed: 1,
            keep: 10,
            focus: Some(&quad),
            focus_scale: Some(&quad_scale),
            trace: &trace,
        };
        let attack = GpuEnigmaNaval {
            shortlist: 10_000_000,
            leads: ENIGMA_LEADS,
            focus: "de".to_string(),
            rings: 26,
            middles: 26,
            finish: 4_000,
            gpu: gpu.clone(),
        };

        let start = std::time::Instant::now();
        let found = attack.best(&ct, &ctx);
        let at = found.iter().position(|c| c.plain == plain);
        println!(
            "  {:<32} {:>3.0}s: plaintext at {at:?}",
            case.label,
            start.elapsed().as_secs_f64()
        );
        if at != Some(0) {
            failed.push(case.label);
        }
    }
    assert!(
        failed.is_empty(),
        "the attack has to put the message it was given first: {failed:?}"
    );
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "the real thing"]
fn the_message() {
    use cipher_break::attack::{Attack, ENIGMA_LEADS, GpuEnigmaNaval};
    use cipher_break::gpu::Gpu;

    let gpu = Gpu::open().expect("the requested GPU check requires a hardware device");
    let ct = cipher_break::to_letters(
        "JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF",
    );
    let bank = bank();
    let scale = Scale::build(&bank, ct.len(), PLANTED_SAMPLES, &mut Rng::new(1));
    let quad = german().expect("the German quadgram model");
    let quad_scale = Scale::for_model(&quad, ct.len(), PLANTED_SAMPLES, &mut Rng::new(2));
    let trace = Trace::new(true);
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: Schedule::default(),
        seed: 1,
        keep: 10,
        focus: Some(&quad),
        focus_scale: Some(&quad_scale),
        trace: &trace,
    };

    let mut null_rng = Rng::new(7);
    let mut nulls: Vec<f64> = Vec::new();
    for _ in 0..NULL_SHUFFLES {
        let shuffled = null_rng.shuffled(&ct);
        let attack = GpuEnigmaNaval {
            shortlist: 1_000_000,
            leads: ENIGMA_LEADS,
            focus: "de".to_string(),
            rings: 26,
            middles: 26,
            finish: 2_000,
            gpu: std::sync::Arc::new(Gpu::open().expect("a device")),
        };
        let best = attack
            .best(&shuffled, &ctx)
            .first()
            .map_or(f64::NEG_INFINITY, |c| c.score);
        println!("  a shuffle of the same letters reaches {best:+.2}s");
        nulls.push(best);
    }
    let (nm, nsd) = cipher_break::stats::moments(&nulls);
    println!("  shuffles reach {nm:+.2} +/- {nsd:.2}");

    for (rings, shortlist) in [(1usize, 20_000usize), (26, 1_000_000)] {
        let attack = GpuEnigmaNaval {
            shortlist,
            leads: ENIGMA_LEADS,
            focus: "de".to_string(),
            rings,
            middles: rings,
            finish: 2_000,
            gpu: std::sync::Arc::new(Gpu::open().expect("a device")),
        };
        let start = std::time::Instant::now();
        let found = attack.best(&ct, &ctx);
        println!(
            "\n  === {rings} ring settings, shortlist {shortlist}, {:.0}s ===",
            start.elapsed().as_secs_f64()
        );
        for c in found.iter().take(6) {
            println!("  {:+6.2}s {}", c.score, c.key);
            println!("         {}", cipher_break::from_letters(&c.plain));
        }
    }
    let _ = &gpu;
}

#[cfg(feature = "gpu")]
const NULL_SHUFFLES: usize = 4;
