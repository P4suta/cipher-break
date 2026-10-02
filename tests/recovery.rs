// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "gpu")]
use cipher_break::alphabet::from_letters;
use cipher_break::alphabet::{Letter, to_letters};
use cipher_break::anneal::Schedule;
use cipher_break::attack::{Context, complete_board, score_outside_the_crib};
use cipher_break::bombe::{Menu, Positions, Scratch, Stop, complete_menu, scan_all_with};
use cipher_break::ciphers::enigma::{Enigma, Plugboard, Settings, composite_reflector};
use cipher_break::ngram::Model;
use cipher_break::polyglot::{Polyglot, Scale};
use cipher_break::rng::Rng;
use cipher_break::trace::Trace;

// Published P1030698, including the operator's errors, independently checks the simulator.
// https://enigma.hoerenberg.com/index.php?cat=The+U534+messages&page=P1030698
const PLAIN: &str = "TTTFFFZWOVIERVVVFXDXUUUXAUSBXXTRAVEMUENDEBLEIBENXWEITEREBEFEHLEATWARTKNX";
const CIPHER: &str = "VIDTGYBSPAXVEDJFKONPMXHTCNAAFKXIOWVCZXUTDGFSEWGFAIDHPKQVARAGUAUPWVRBFOWO";
const PLUGS: &str = "CH EJ NV OU TY LG SZ PK DI QB";
const CRIB_LENGTH: usize = 24;

fn board() -> Plugboard {
    let mut board = Plugboard::empty();
    for pair in PLUGS.split_whitespace() {
        let letters = to_letters(pair);
        board.connect(letters[0], letters[1]);
    }
    assert_eq!(board.pairs().len(), 10);
    board
}

fn settings() -> Settings {
    Settings::at([3, 2, 7], 0, [0, 2, 20], [16, 24, 17])
}

fn reflector() -> [u8; 26] {
    composite_reflector(1, 22, 0)
}

fn context<'a>(
    bank: &'a Polyglot,
    scale: &'a Scale,
    model: &'a Model,
    focus_scale: &'a Scale,
    trace: &'a Trace,
) -> Context<'a> {
    Context {
        judge: bank,
        scale,
        plan: Schedule::default(),
        seed: 1,
        keep: 5,
        trace,
        focus: Some(model),
        focus_scale: Some(focus_scale),
    }
}

fn compatible_stop(ct: &[Letter], truth: Settings) -> (Plugboard, u32) {
    let crib = to_letters(&PLAIN[..CRIB_LENGTH]);
    let menu = Menu::place(ct, &crib, 0).expect("a true crib cannot self-encipher");
    assert!(
        menu.closures() > 0,
        "the recovery check must exercise a loop"
    );
    let positions = Positions::of(truth, reflector(), CRIB_LENGTH);
    scan_all_with(&menu, &positions, &mut Scratch::new())
        .into_iter()
        .filter_map(|stop| match stop {
            Stop::Survived { board, known, .. } => Some((board, known)),
            Stop::Refuted => None,
        })
        .flat_map(|partial| complete_menu(&menu, &positions, partial, 10))
        .find(|(forced, known)| {
            (0..26u8).all(|l| (known >> l) & 1 == 0 || forced.map(l) == board().map(l))
        })
        .expect("the CPU menu must retain the ten-lead key")
}

#[test]
fn the_published_short_message_reencrypts_exactly() {
    let plain = to_letters(PLAIN);
    let ct = to_letters(CIPHER);
    assert!((65..=80).contains(&plain.len()));
    assert_eq!(
        Enigma::with_reflector(settings(), reflector(), board()).run(&plain),
        ct
    );
    assert_eq!(
        Enigma::with_reflector(settings(), reflector(), board()).run(&ct),
        plain
    );
}

#[test]
fn the_failed_potsdam_trials_replay_the_target_annotations() {
    // These are the operator's unsuccessful Potsdam trials, not a recovered Thetis key.
    // https://enigma.hoerenberg.com/index.php?cat=Unbroken&page=P1030680
    for (grund, input, expected) in [
        ("MNNS", "OEDM", "ELKC"),
        ("DGUG", "SEDM", "PUYY"),
        ("PUYY", "JCRSAJ", "IPZAYK"),
    ] {
        let letters = to_letters(grund);
        let physical = Settings::at(
            [3, 2, 7],
            0,
            [2, 2, 7],
            [letters[1], letters[2], letters[3]],
        );
        let greek = composite_reflector(1, (letters[0] + 26 - 21) % 26, 0);
        assert_eq!(
            Enigma::with_reflector(physical, greek, board()).run(&to_letters(input)),
            to_letters(expected)
        );
    }
}

#[test]
fn the_cpu_finishes_ten_leads_across_a_double_step() {
    let bank = Polyglot::from_bundle(include_str!("../data/models.bundle"));
    let model = Model::parse(include_str!("../data/german-quadgrams.txt")).expect("German model");
    let plain = to_letters(PLAIN);
    let scale = Scale::build(&bank, plain.len(), 128, &mut Rng::new(1));
    let focus_scale = Scale::for_model(&model, plain.len(), 128, &mut Rng::new(2));
    let trace = Trace::new(false);
    let ctx = context(&bank, &scale, &model, &focus_scale, &trace);
    // U/Z reaches the middle notch on the first press and double-steps on the second.
    let double_step = Settings::at([3, 2, 7], 0, [0, 2, 20], [16, 20, 25]);
    for truth in [settings(), double_step] {
        let ct = Enigma::with_reflector(truth, reflector(), board()).run(&plain);
        let (recovered, plugs, read) = complete_board(
            truth,
            reflector(),
            compatible_stop(&ct, truth),
            10,
            CRIB_LENGTH,
            &ct,
            &ctx,
        );
        assert_eq!(read, plain, "a partial reading is not recovery");
        assert_eq!(plugs, board(), "recover all ten leads");
        assert_eq!(
            Enigma::with_reflector(recovered, reflector(), plugs).run(&read),
            ct
        );
    }
}

#[test]
fn scoring_cannot_credit_a_replaced_crib() {
    let bank = Polyglot::from_bundle(include_str!("../data/models.bundle"));
    let model = Model::parse(include_str!("../data/german-quadgrams.txt")).expect("German model");
    let plain = to_letters(PLAIN);
    let scale = Scale::build(&bank, plain.len(), 128, &mut Rng::new(1));
    let focus_scale = Scale::for_model(&model, plain.len(), 128, &mut Rng::new(2));
    let trace = Trace::new(false);
    let ctx = context(&bank, &scale, &model, &focus_scale, &trace);
    let mut replaced = plain.clone();
    replaced[..CRIB_LENGTH].fill(0);
    assert_eq!(
        score_outside_the_crib(&plain, &ctx, 0, CRIB_LENGTH),
        score_outside_the_crib(&replaced, &ctx, 0, CRIB_LENGTH)
    );
}

#[cfg(feature = "gpu")]
type Recovery = (f64, Settings, Plugboard, Vec<Letter>);

#[cfg(feature = "gpu")]
fn sweep_recovery(
    ct: &[Letter],
    ctx: &Context,
    gpu: &cipher_break::gpu::Gpu,
) -> (f64, Vec<Recovery>) {
    use cipher_break::gpu::BombeJob;
    let model = ctx.focus.expect("German model");
    let crib = to_letters(&PLAIN[..CRIB_LENGTH]);
    let Some(menu) = Menu::place(ct, &crib, 0).filter(|m| m.closures() > 0) else {
        return (f64::NEG_INFINITY, Vec::new());
    };
    let packed = vec![(
        0,
        crib.iter().copied().zip(ct.iter().copied()).collect(),
        menu.hub(),
    )];
    let start = std::time::Instant::now();
    let found = gpu.sweep_bombe(&BombeJob {
        ct,
        logp: model.log_table(),
        order: model.order(),
        orders: &[settings().rotors],
        reflectors: &[reflector()],
        menus: &packed,
        rings: 26,
        middles: 26,
        keep: 64,
    });
    println!(
        "sweep: {} stops, {} shortlisted, {:.3}s",
        found.stops,
        found.best.len(),
        start.elapsed().as_secs_f64()
    );
    let mut completed = Vec::new();
    for hit in found.best {
        let initial = Settings::at(
            settings().rotors,
            0,
            [0, hit.middle.value(), hit.ring.value()],
            hit.positions
                .map(cipher_break::enigma_types::Indicator::value),
        );
        let positions = Positions::of(initial, reflector(), CRIB_LENGTH);
        for stop in scan_all_with(&menu, &positions, &mut Scratch::new()) {
            if let Stop::Survived { board, known, .. } = stop {
                for (forced, known) in complete_menu(&menu, &positions, (board, known), 10) {
                    let (key, plugs, read) = complete_board(
                        initial,
                        reflector(),
                        (forced, known),
                        10,
                        CRIB_LENGTH,
                        ct,
                        ctx,
                    );
                    assert_eq!(
                        Enigma::with_reflector(key, reflector(), plugs).run(&read),
                        ct
                    );
                    if read[..CRIB_LENGTH] != crib {
                        continue;
                    }
                    let score = score_outside_the_crib(&read, ctx, 0, CRIB_LENGTH);
                    completed.push((score, key, plugs, read));
                }
            }
        }
    }
    let rank = |r: &Recovery| {
        cipher_break::attack::penalised(r.0, r.2.pairs().len(), ct.len().saturating_sub(2).max(1))
    };
    completed.sort_unstable_by(|a, b| rank(b).total_cmp(&rank(a)));
    (
        completed.first().map_or(f64::NEG_INFINITY, |c| c.0),
        completed,
    )
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "a bounded GPU recovery and eight identical searches on shuffles; run on the cloud VM"]
fn the_gpu_shortlist_recovers_ten_leads_and_rejects_shuffles() {
    let gpu =
        cipher_break::gpu::Gpu::open().expect("the requested recovery requires a hardware GPU");
    println!("GPU: {}", gpu.name);
    let bank = Polyglot::from_bundle(include_str!("../data/models.bundle"));
    let model = Model::parse(include_str!("../data/german-quadgrams.txt")).expect("German model");
    let plain = to_letters(PLAIN);
    let scale = Scale::build(&bank, plain.len(), 128, &mut Rng::new(1));
    let focus_scale = Scale::for_model(&model, plain.len(), 128, &mut Rng::new(2));
    let trace = Trace::new(false);
    let ctx = context(&bank, &scale, &model, &focus_scale, &trace);

    let ct = to_letters(CIPHER);
    let (truth_score, found) = sweep_recovery(&ct, &ctx, &gpu);
    let top = found
        .first()
        .expect("the true key must survive GPU shortlisting and CPU finishing");
    assert_eq!(
        top.3, plain,
        "the true plaintext must rank first and match exactly"
    );
    assert_eq!(top.2, board());
    println!(
        "recovered: gamma/W B-thin, rotors [4, 3, 8], rings {}, start {}, plugs {PLUGS}\n{}",
        from_letters(&top.1.ring_letters()),
        from_letters(&top.1.position_letters()),
        from_letters(&top.3)
    );
    let mut rng = Rng::new(20_261_002);
    let mut exceeds = 0;
    for i in 0..8 {
        let shuffled = rng.shuffled(&ct);
        let (score, _) = sweep_recovery(&shuffled, &ctx, &gpu);
        println!("shuffle {i}: {score:.6}");
        exceeds += usize::from(score >= truth_score);
    }
    println!(
        "pilot empirical p: {}/9; eight shuffles cannot establish p < 0.001",
        exceeds + 1
    );
    assert_eq!(
        exceeds, 0,
        "the same search on shuffles must not outrank the known message"
    );
}
