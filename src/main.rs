// SPDX-License-Identifier: MIT OR Apache-2.0

use cipher_break::alphabet::{ALPHABET, Letter, from_letters, to_letters};
use cipher_break::anneal::Schedule;
use cipher_break::attack::{Context, registry};
use cipher_break::crib::{Crib, KRIEGSMARINE, KRIEGSMARINE_LONG};
use cipher_break::ngram::Model;
use cipher_break::polyglot::{Polyglot, Scale};
use cipher_break::report::{self, Conclusion};
use cipher_break::rng::Rng;
use cipher_break::stats::{ic_by_period, index_of_coincidence};
use cipher_break::sweep;
use cipher_break::triage;
use rayon::prelude::*;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const BUNDLE: &str = include_str!("../data/models.bundle");

const GERMAN_QUADGRAMS: &str = include_str!("../data/german-quadgrams.txt");

const SCALE_SAMPLES: usize = 256;

const CALIBRATION_SAMPLES: usize = 200;

const TRIAGE_TRIALS: usize = 20_000;

const PERIOD_SHUFFLES: usize = 200;

const REPORT_PERIODS: std::ops::RangeInclusive<usize> = 2..=16;

const PERIOD_COLUMN_MINIMUM: usize = 4;

#[cfg(feature = "gpu")]
const GPU_ENIGMA_SHORTLIST_HELD: usize = 20_000;

#[cfg(feature = "gpu")]
const GPU_ENIGMA_SHORTLIST_SWEPT: usize = 1_000_000;

#[cfg(feature = "gpu")]
const GPU_ENIGMA_FINISH: usize = 2_000;

#[cfg(feature = "gpu")]
const RING_SWEEP_DEPTH: usize = 6;

#[cfg(feature = "gpu")]
const GPU_PERIOD_FLOOR: usize = 4;

const USAGE: &str = "\
cb — a cryptanalysis workbench for classical ciphers

USAGE
  cb <ciphertext|file|->                run the whole catalogue and report
  cb solve   <input> [options]          the same, spelled out
  cb report  <input> [options]          diagnostics only: what the text is
  cb try     <attack> <input>           run one attack by name
  cb crib    <input> [--word W]         where a guessed word could sit, and could not
  cb bombe   <input> [--word W] [--m3]  attack an Enigma message through a crib
             [--rings] [--at N] [--plan] sweep the middle and right rings; only the crib at offset N; the table alone
             [--finish N]               how many stops to finish and read (default 200000)
             [--right-rings]            sweep the right ring only, holding the middle at A
  cb list                               every attack in the catalogue
  cb train   [--order N] [--cutoff N]   learn a model from a corpus on stdin
  cb devices                            what this machine can compute with

OPTIONS
  --effort quick|normal|deep|max   how hard to search        (default normal)
  --depth N                        exhaust keys up to N letters long
  --nulls N                        shuffles each attack is calibrated against
  --top N                          candidates to show per attack     (default 1)
  --models DIR                     language models to use instead of the built-in
  --seed N                         make a run reproducible           (default 1)
  --language de                    a language you already know, for a sharper judge
  --focus FILE                     a quadgram model to judge by instead, for German narrower than the bank's
  --gpu                            run the big exhaustive sweeps on the GPU
  --trace                          say what each stage of each attack did
  --plain                          no colour

The input may be a file, a literal run of letters, or - for standard input.
Everything that is not a letter is ignored.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("cb: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(());
    }
    match args[0].as_str() {
        "bombe" => bombe(&input_from(args.get(1))?, args),
        "crib" => {
            cribs(&input_from(args.get(1))?, args);
            Ok(())
        }
        "list" => {
            list();
            Ok(())
        }
        "devices" => {
            devices();
            Ok(())
        }
        "train" => train(args),
        "report" => report_only(&input_from(args.get(1))?, args),
        "solve" => solve(&input_from(args.get(1))?, args),
        "try" => {
            let name = args.get(1).ok_or("try needs the name of an attack")?;
            try_one(name, &input_from(args.get(2))?, args)
        }
        _ => solve(&input_from(args.first())?, args),
    }
}

fn input_from(arg: Option<&String>) -> Result<Vec<Letter>, String> {
    let arg = arg.ok_or("give me a ciphertext, a file, or - for standard input")?;
    if arg.starts_with('-') && arg != "-" {
        return Err(format!(
            "{arg} is where the ciphertext goes; give me a ciphertext, a file, or - for standard input"
        ));
    }
    let raw = if arg == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| e.to_string())?;
        buf
    } else if Path::new(arg).is_file() {
        std::fs::read_to_string(arg).map_err(|e| e.to_string())?
    } else {
        arg.clone()
    };
    let ls = to_letters(&raw);
    if ls.is_empty() {
        return Err("that input holds no letters".into());
    }
    Ok(ls)
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn number<T: std::str::FromStr>(args: &[String], name: &str, fallback: T) -> T {
    option(args, name)
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

const QUICK: f64 = 0.25;
const DEEP: f64 = 2.0;
const MAX: f64 = 4.0;

#[derive(Clone, Copy)]
struct Effort {
    depth: usize,
    plan: Schedule,
    nulls: usize,
}

fn effort_from(args: &[String]) -> Effort {
    let named = option(args, "--effort").unwrap_or("normal");
    let base = Schedule::default();
    let mut effort = match named {
        "quick" => Effort {
            depth: 3,
            plan: base.scaled(QUICK),
            nulls: 4,
        },
        "deep" => Effort {
            depth: 5,
            plan: base.scaled(DEEP),
            nulls: 16,
        },
        "max" => Effort {
            depth: 6,
            plan: base.scaled(MAX),
            nulls: 24,
        },
        _ => Effort {
            depth: 4,
            plan: base,
            nulls: 8,
        },
    };
    effort.nulls = number(args, "--nulls", effort.nulls);
    effort.depth = number(args, "--depth", effort.depth);
    effort
}

fn models(args: &[String]) -> Result<Polyglot, String> {
    if let Some(dir) = option(args, "--models") {
        return Polyglot::load(&PathBuf::from(dir)).map_err(|e| format!("{dir}: {e}"));
    }
    Ok(Polyglot::from_bundle(BUNDLE))
}

fn focus_model(args: &[String]) -> Option<Model> {
    if let Some(path) = option(args, "--focus") {
        let parsed = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| Model::parse(&text));
        if parsed.is_none() {
            eprintln!("cb: could not read a model from {path}; carrying on without one");
        }
        return parsed;
    }
    match option(args, "--language") {
        Some("de") => Model::parse(GERMAN_QUADGRAMS),
        Some(other) => {
            eprintln!("cb: no high-order model for {other:?}; carrying on without one");
            None
        }
        None => None,
    }
}

fn paint(args: &[String], text: &str) -> String {
    if flag(args, "--plain") || std::env::var_os("NO_COLOR").is_some() {
        strip_ansi(text)
    } else {
        text.to_string()
    }
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(feature = "gpu")]
fn devices() {
    match cipher_break::gpu::Gpu::open() {
        Ok(gpu) => println!("  gpu   {}", gpu.name),
        Err(why) => println!("  gpu   unavailable: {why}"),
    }
    println!("  cpu   {} threads", rayon::current_num_threads());
}

#[cfg(not(feature = "gpu"))]
fn devices() {
    println!("  gpu   not built in (rebuild with --features gpu)");
    println!("  cpu   {} threads", rayon::current_num_threads());
}

#[cfg(feature = "gpu")]
fn with_gpu(
    mut attacks: Vec<Box<dyn cipher_break::attack::Attack>>,
    depth: usize,
) -> Vec<Box<dyn cipher_break::attack::Attack>> {
    let Ok(gpu) = cipher_break::gpu::Gpu::open() else {
        return attacks;
    };
    let gpu = std::sync::Arc::new(gpu);
    attacks.retain(|a| {
        !a.name().starts_with("vigenere period ") && !a.name().starts_with("enigma M4 naval")
    });
    attacks.push(Box::new(cipher_break::attack::GpuEnigmaNaval {
        shortlist: GPU_ENIGMA_SHORTLIST_HELD,
        leads: cipher_break::attack::ENIGMA_LEADS,
        focus: "de".to_string(),
        rings: 1,
        middles: 1,
        finish: GPU_ENIGMA_FINISH,
        gpu: gpu.clone(),
    }));
    if depth >= RING_SWEEP_DEPTH {
        attacks.push(Box::new(cipher_break::attack::GpuEnigmaNaval {
            shortlist: GPU_ENIGMA_SHORTLIST_SWEPT,
            leads: cipher_break::attack::ENIGMA_LEADS,
            focus: "de".to_string(),
            rings: cipher_break::alphabet::ALPHABET,
            middles: cipher_break::alphabet::ALPHABET,
            finish: GPU_ENIGMA_FINISH,
            gpu: gpu.clone(),
        }));
    }
    for period in 1..=depth {
        if period >= GPU_PERIOD_FLOOR {
            attacks.push(Box::new(cipher_break::attack::GpuPeriodicSweep {
                period,
                gpu: gpu.clone(),
            }));
        } else {
            attacks.push(Box::new(cipher_break::attack::PeriodicSweep { period }));
        }
    }
    attacks
}

#[cfg(not(feature = "gpu"))]
fn with_gpu(
    attacks: Vec<Box<dyn cipher_break::attack::Attack>>,
    _depth: usize,
) -> Vec<Box<dyn cipher_break::attack::Attack>> {
    attacks
}

fn cribs(ct: &[Letter], args: &[String]) {
    let words: Vec<String> = match option(args, "--word") {
        Some(word) => vec![word.to_string()],
        None => KRIEGSMARINE.iter().map(|w| (*w).to_string()).collect(),
    };
    let rotors =
        cipher_break::ciphers::enigma::rotor_orders(cipher_break::ciphers::enigma::ROTOR_COUNT)[0];
    let reflector = cipher_break::ciphers::enigma::reflector_wiring(0);
    let naval = f64::from((ALPHABET as u32).pow(3))
        * cipher_break::ciphers::enigma::rotor_orders(cipher_break::ciphers::enigma::ROTOR_COUNT)
            .len() as f64
        * cipher_break::ciphers::enigma::NAVAL_REFLECTOR_COUNT as f64;

    println!(
        "  {:<18} {:>4} {:>7} {:>9} {:>10} {:>9}",
        "crib", "len", "places", "closures", "survive", "to judge"
    );
    for word in words {
        let letters = to_letters(&word);
        let menus: Vec<cipher_break::bombe::Menu> = Crib::against(ct, &letters)
            .offsets
            .iter()
            .filter_map(|&o| cipher_break::bombe::Menu::place(ct, &letters, o))
            .filter(|m| m.closures() > 0)
            .collect();
        if menus.is_empty() {
            println!("  {word:<18} {:>4} {:>7}", letters.len(), 0);
            continue;
        }
        let survive: f64 = menus
            .par_iter()
            .map(|m| m.survival_rate(rotors, reflector))
            .sum::<f64>()
            / menus.len() as f64;
        let closures: Vec<usize> = menus
            .iter()
            .map(cipher_break::bombe::Menu::closures)
            .collect();
        let seconds = survive * naval * menus.len() as f64 * SECONDS_TO_JUDGE_A_STOP
            / num_cpus_or_one() as f64;
        println!(
            "  {word:<18} {:>4} {:>7} {:>9} {:>9.4}% {:>8.0}s",
            letters.len(),
            menus.len(),
            format!(
                "{}-{}",
                closures.iter().min().copied().unwrap_or(0),
                closures.iter().max().copied().unwrap_or(0)
            ),
            100.0 * survive,
            seconds
        );
    }
}

const SECONDS_TO_JUDGE_A_STOP: f64 = 2.14e-6;

fn num_cpus_or_one() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

fn bombe_plan(
    ct: &[Letter],
    words: Vec<String>,
    settings: u64,
    at: Option<usize>,
) -> Vec<(String, usize, f64)> {
    let words: Vec<(String, Vec<cipher_break::bombe::Menu>)> = words
        .into_iter()
        .map(|word| {
            let letters = to_letters(&word);
            let menus: Vec<cipher_break::bombe::Menu> = Crib::against(ct, &letters)
                .offsets
                .iter()
                .filter(|&&o| at.is_none_or(|at| o == at))
                .filter_map(|&o| cipher_break::bombe::Menu::place(ct, &letters, o))
                .filter(|m| m.closures() > 0)
                .collect();
            (word, menus)
        })
        .collect();
    let rotors =
        cipher_break::ciphers::enigma::rotor_orders(cipher_break::ciphers::enigma::ROTOR_COUNT)[0];
    let reflector = cipher_break::ciphers::enigma::reflector_wiring(0);
    let mut rated: Vec<(f64, (String, Vec<cipher_break::bombe::Menu>))> = words
        .into_par_iter()
        .map(|(word, menus)| {
            let rate = if menus.is_empty() {
                f64::INFINITY
            } else {
                menus
                    .iter()
                    .map(|m| m.survival_rate(rotors, reflector))
                    .sum::<f64>()
                    / menus.len() as f64
            };
            (rate, (word, menus))
        })
        .collect();
    rated.sort_by(|a, b| {
        let group = |w: &str| usize::from(!KRIEGSMARINE.contains(&w));
        group(&a.1.0).cmp(&group(&b.1.0)).then(a.0.total_cmp(&b.0))
    });
    let words = rated;

    println!(
        "  {:<28} {:>10}  {:>8}  {:>10}  {:>9}",
        "crib", "placements", "closures", "survive", "to judge"
    );
    let mut worth_sweeping = Vec::new();
    for (rate, (word, menus)) in words {
        if menus.is_empty() {
            println!("  {word:<28} {:>10}  {:>8}", 0, "-");
            continue;
        }
        let closures: Vec<usize> = menus
            .iter()
            .map(cipher_break::bombe::Menu::closures)
            .collect();
        let loosest = menus
            .iter()
            .map(|m| m.chance_stops(settings))
            .fold(0.0f64, f64::max);
        let seconds = rate * settings as f64 * menus.len() as f64 * SECONDS_TO_JUDGE_A_STOP
            / num_cpus_or_one() as f64;
        println!(
            "  {word:<28} {:>10}  {:>8}  {:>9.4}%  {:>8.0}s",
            menus.len(),
            format!(
                "{}-{}",
                closures.iter().min().copied().unwrap_or(0),
                closures.iter().max().copied().unwrap_or(0)
            ),
            100.0 * rate,
            seconds
        );
        worth_sweeping.push((word, menus.len(), loosest));
    }
    println!();

    worth_sweeping
}

const FINISHED_NOISE: usize = 25_600;

fn bombe_one(
    ct: &[Letter],
    ctx: &Context,
    args: &[String],
    attack: &cipher_break::attack::BombeAttack,
    nulls: usize,
    by_chance: f64,
) {
    let naval = attack.naval;
    let outcome = sweep::run(attack, ct, ctx, nulls);
    let standing = attack.stops.load(std::sync::atomic::Ordering::Relaxed);
    print!("{}", paint(args, &report::heading(&outcome.name)));
    print!("{}", paint(args, &report::outcome_row(&outcome)));
    println!(
        "  {standing} settings survived, against {by_chance:.0} the menus let through by chance"
    );
    if standing == 0 {
        let machine = if naval { "naval M4" } else { "M3" };
        let within = match (attack.rings, attack.middles) {
            (true, true) => format!("under any {machine} setting"),
            (true, false) => format!(
                "under any {machine} setting whose middle rotor does not reach its notch inside the crib"
            ),
            _ => format!("under any {machine} setting with its rings at A"),
        };
        let placed = attack
            .at
            .map_or_else(String::new, |at| format!(" at offset {at}"));
        println!("  every setting refuted: this crib is not{placed} in this message {within}");
    } else if by_chance < 1.0 {
        println!(
            "  THE MENUS SHOULD HAVE LEFT NOTHING STANDING. Read the candidates below whatever the verdict says of their scores."
        );
    }
    let finished = attack.finished.load(std::sync::atomic::Ordering::Relaxed);
    if standing > 0 {
        println!("  {finished} of them finished and read");
    }
    let mut calibrator = report::Calibrator::new(ctx.judge, ctx.scale, ctx.seed);
    let language = calibrator.at(ct.len()).language_mean;
    if let Some(top) = outcome.best.first() {
        let shapes = attack.shapes.lock().map(|s| s.clone()).unwrap_or_default();
        let noise = report::best_of_n_fit(
            &cipher_break::attack::finished_noise(
                ct,
                ctx,
                naval,
                attack.at.unwrap_or(0),
                attack.crib.len(),
                &shapes,
                FINISHED_NOISE,
            ),
            standing,
        );
        let (median, chance) = noise.map_or((f64::INFINITY, 1.0), |fit| {
            (fit.median, fit.chance_of_reaching(top.score))
        });
        println!(
            "  best decipherment {:+.1}s; the approximate finishing null reaches {median:+.1}s and estimates a tail of {chance:.2e}; fluent text of this length reads {language:+.1}s",
            top.score
        );
        println!(
            "  this fitted null does not repeat the rotor sweep, shortlisting, or whole-crib rejection; no reading is declared without matched full-search controls"
        );
    }
    for candidate in &outcome.best {
        println!(
            "{}",
            paint(
                args,
                &format!(
                    "  {:+6.1}s {:<3} {}\n       {}",
                    candidate.score,
                    ctx.judge.identify(&candidate.plain).0,
                    candidate.key,
                    from_letters(&candidate.plain)
                )
            )
        );
    }
    let _ = std::io::stdout().flush();
}

#[cfg(feature = "gpu")]
fn bombe_device(args: &[String]) -> Result<Option<std::sync::Arc<cipher_break::gpu::Gpu>>, String> {
    if flag(args, "--plan") {
        return Ok(None);
    }
    match cipher_break::gpu::Gpu::open() {
        Ok(gpu) => Ok(Some(std::sync::Arc::new(gpu))),
        Err(why) if flag(args, "--gpu") => Err(why),
        Err(_) => Ok(None),
    }
}

#[cfg(not(feature = "gpu"))]
fn bombe_device(args: &[String]) -> Result<(), String> {
    if flag(args, "--gpu") && !flag(args, "--plan") {
        return Err("--gpu requires a build with --features gpu".to_string());
    }
    Ok(())
}

fn bombe_words(args: &[String]) -> Vec<String> {
    match option(args, "--word") {
        Some(word) => vec![word.to_string()],
        None => KRIEGSMARINE
            .iter()
            .chain(KRIEGSMARINE_LONG)
            .map(|w| (*w).to_string())
            .collect(),
    }
}

fn bombe(ct: &[Letter], args: &[String]) -> Result<(), String> {
    let words = bombe_words(args);
    let naval = !flag(args, "--m3");
    let rotors = number(args, "--rotors", cipher_break::ciphers::enigma::ROTOR_COUNT);
    let at = option(args, "--at")
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|e| format!("--at: {e}"))?;
    let (right_rings, middle_rings) = if flag(args, "--rings") {
        (true, true)
    } else {
        (flag(args, "--right-rings"), false)
    };
    let rings = if right_rings { ALPHABET as u64 } else { 1 }
        * if middle_rings { ALPHABET as u64 } else { 1 };
    #[cfg(feature = "gpu")]
    let device = bombe_device(args)?;
    #[cfg(not(feature = "gpu"))]
    bombe_device(args)?;

    let settings = (ALPHABET as u64).pow(3)
        * cipher_break::ciphers::enigma::rotor_orders(rotors).len() as u64
        * if naval {
            cipher_break::ciphers::enigma::NAVAL_REFLECTOR_COUNT as u64
        } else {
            cipher_break::ciphers::enigma::REFLECTOR_COUNT as u64
        }
        * rings;

    let worth_sweeping = bombe_plan(ct, words, settings, at);
    if flag(args, "--plan") {
        return Ok(());
    }
    if worth_sweeping.is_empty() {
        println!(
            "  no menu here removes a single setting; a sweep would hand back the search space and call it a result"
        );
        return Ok(());
    }
    let depth = worth_sweeping
        .iter()
        .map(|&(_, _, loosest)| {
            (1.0 + cipher_break::bombe::RANK_OF_TRUTH_WHEN_SHORT as f64 * loosest / settings as f64)
                .ceil() as usize
        })
        .max()
        .unwrap_or(1);
    println!(
        "  sweeping {} cribs, keeping the top {depth} of each so the weakest menu can still surface a true setting",
        worth_sweeping.len()
    );
    let _ = std::io::stdout().flush();

    let bank = models(args)?;
    let effort = effort_from(args);
    let seed = number(args, "--seed", 1u64);
    let scale = Scale::build(
        &bank,
        ct.len(),
        SCALE_SAMPLES,
        &mut Rng::new(seed ^ 0x5CA1E),
    );
    let focus = focus_model(args);
    let focus_scale = focus
        .as_ref()
        .map(|m| Scale::for_model(m, ct.len(), SCALE_SAMPLES, &mut Rng::new(seed ^ 0xF0C05)));
    let trace = cipher_break::trace::Trace::new(flag(args, "--trace"));
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: effort.plan,
        seed,
        keep: number(args, "--top", depth),
        focus: focus.as_ref(),
        focus_scale: focus_scale.as_ref(),
        trace: &trace,
    };

    for (word, placements, by_chance) in worth_sweeping {
        println!();
        println!("  {word} — {placements} placements");
        let _ = std::io::stdout().flush();
        let attack = cipher_break::attack::BombeAttack {
            #[cfg(feature = "gpu")]
            gpu: device.clone(),
            stops: std::sync::atomic::AtomicU64::new(0),
            finished: std::sync::atomic::AtomicU64::new(0),
            shapes: std::sync::Mutex::new(Vec::new()),
            crib: to_letters(&word),
            label: word.clone(),
            rotors_available: rotors,
            naval,
            rings: right_rings,
            middles: middle_rings,
            at,
            finish: number(args, "--finish", cipher_break::attack::BOMBE_FINISH),
        };
        bombe_one(ct, &ctx, args, &attack, effort.nulls, by_chance);
    }
    Ok(())
}

fn list() {
    for attack in registry(cipher_break::attack::MAX_KEY) {
        println!("  {:<38} {}", attack.name(), attack.family());
    }
}

fn train(args: &[String]) -> Result<(), String> {
    let order = number(args, "--order", 3usize);
    let cutoff = number(args, "--cutoff", 1u32);
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())?;
    let model = Model::train(order, &to_letters(&raw));
    let mut out = std::io::stdout().lock();
    out.write_all(model.render(cutoff).as_bytes())
        .map_err(|e| e.to_string())
}

const WARTIME_LEADS: usize = 10;

const REDUNDANCY_SAMPLE: usize = 20_000;

const ENIGMA_NULL_LANGUAGE: &str = "de";

fn unicity_section(ct: &[Letter], bank: &Polyglot, args: &[String], rng: &mut Rng) -> String {
    let mut out = String::new();
    let Some(model) = bank.model_named(option(args, "--language").unwrap_or(ENIGMA_NULL_LANGUAGE))
    else {
        return out;
    };
    let sample = model.sample(REDUNDANCY_SAMPLE, rng);
    let redundancy = report::redundancy(model.score(&sample), model.order());
    out.push_str(&report::heading("IS THE ANSWER EVEN UNIQUE"));
    let _ = writeln!(
        out,
        "  {:.2} bits of redundancy per letter, so {} letters carry {:.0} bits of evidence",
        redundancy,
        ct.len(),
        redundancy * ct.len() as f64
    );
    let _ = writeln!(
        out,
        "  {:<36} {:>10} {:>10}  at this length",
        "cipher", "key bits", "needs"
    );
    let verdict = |needs: f64| {
        if ct.len() as f64 >= needs {
            "one key fits"
        } else {
            "several keys fit — no search can choose"
        }
    };
    for (name, naval) in [
        ("Enigma M3, ten leads", false),
        ("Enigma M4 naval, ten leads", true),
    ] {
        let bits = cipher_break::ciphers::enigma::key_bits(naval, WARTIME_LEADS);
        let needs = bits / redundancy;
        let _ = writeln!(
            out,
            "  {name:<36} {bits:>10.1} {needs:>10.1}  {}",
            verdict(needs)
        );
    }
    let mut seen: Vec<(String, u64)> = registry(effort_from(args).depth)
        .iter()
        .map(|a| (a.name(), a.coverage(ct).keys()))
        .filter(|(_, keys)| *keys > 1)
        .collect();
    seen.sort_by_key(|(_, keys)| *keys);
    seen.dedup_by(|a, b| a.1 == b.1);
    for (name, keys) in seen {
        let needs = report::unicity_distance(keys, redundancy);
        let _ = writeln!(
            out,
            "  {:<36} {:>10.1} {needs:>10.1}  {}",
            name,
            (keys as f64).log2(),
            verdict(needs)
        );
    }
    out.push('\n');
    out
}

fn diagnostics(ct: &[Letter], bank: &Polyglot, args: &[String]) -> String {
    let mut out = String::new();
    let mut rng = Rng::new(number(args, "--seed", 1u64) ^ 0xC0FF_EE00);
    let population =
        triage::random_population(ct.len(), number(args, "--trials", TRIAGE_TRIALS), &mut rng);
    let verdicts = triage::assess_all(&triage::statistics(Some(bank)), ct, &population);
    out.push_str(&report::heading("AGAINST RANDOM LETTERS"));
    out.push_str(&report::statistics_table(&verdicts, "random"));

    if let Some(german) = bank.model_named(ENIGMA_NULL_LANGUAGE) {
        let machines = triage::enigma_population(
            ct.len(),
            number(args, "--trials", TRIAGE_TRIALS),
            german,
            &mut rng,
        );
        let against = triage::assess_all(&triage::statistics(Some(bank)), ct, &machines);
        out.push_str(&report::heading("AGAINST ENIGMA OUTPUT"));
        out.push_str(
            "  a naval machine, fresh rotors and ten leads each draw, enciphering German\n",
        );
        out.push_str(&report::statistics_table(&against, "enigma"));
    }

    let rearranged: Vec<Vec<Letter>> = (0..number(args, "--trials", TRIAGE_TRIALS))
        .map(|_| rng.shuffled(ct))
        .collect();
    let orderings = triage::assess_all(&triage::statistics(Some(bank)), ct, &rearranged);
    out.push_str(&report::heading("AGAINST ITS OWN LETTERS REARRANGED"));
    out.push_str("  the same letters in a different order, so only arrangement is on trial\n");
    out.push_str(&report::statistics_table(&orderings, "shuffled"));

    out.push_str(&unicity_section(ct, bank, args, &mut rng));

    out.push_str(&report::heading("PERIOD"));
    out.push_str("  a period shows itself as columns that are each monoalphabetic\n");
    let _ = writeln!(
        out,
        "  {:<6} {:>8} {:>10} {:>8}",
        "period", "column IC", "shuffled", "z"
    );
    let shuffles: Vec<Vec<Letter>> = (0..PERIOD_SHUFFLES).map(|_| rng.shuffled(ct)).collect();
    for p in *REPORT_PERIODS.start()
        ..=(*REPORT_PERIODS.end())
            .min(ct.len() / PERIOD_COLUMN_MINIMUM)
            .max(2)
    {
        let observed = ic_by_period(ct, p);
        let null: Vec<f64> = shuffles.iter().map(|s| ic_by_period(s, p)).collect();
        let (mean, sd) = cipher_break::stats::moments(&null);
        let _ = writeln!(
            out,
            "  {p:<6} {observed:>8.4} {mean:>10.4} {:>+8.2}",
            (observed - mean) / sd
        );
    }
    out
}

fn report_only(ct: &[Letter], args: &[String]) -> Result<(), String> {
    let bank = models(args)?;
    print!("{}", paint(args, &banner(ct, &bank)));
    print!("{}", paint(args, &diagnostics(ct, &bank, args)));
    Ok(())
}

fn banner(ct: &[Letter], bank: &Polyglot) -> String {
    format!(
        "\n  \x1b[1mcipher-break\x1b[0m  {} letters  ·  {} languages  ·  IC {:.4}\n  {}\n",
        ct.len(),
        bank.len(),
        index_of_coincidence(ct),
        from_letters(ct)
    )
}

fn solve(ct: &[Letter], args: &[String]) -> Result<(), String> {
    let bank = models(args)?;
    if bank.is_empty() {
        return Err("no language models; pass --models DIR".into());
    }
    let effort = effort_from(args);
    let seed = number(args, "--seed", 1u64);
    let keep = number(args, "--top", 1usize);
    let scale = Scale::build(
        &bank,
        ct.len(),
        SCALE_SAMPLES,
        &mut Rng::new(seed ^ 0x5CA1E),
    );
    let focus = focus_model(args);
    let focus_scale = focus
        .as_ref()
        .map(|m| Scale::for_model(m, ct.len(), SCALE_SAMPLES, &mut Rng::new(seed ^ 0xF0C05)));
    let trace = cipher_break::trace::Trace::new(flag(args, "--trace"));
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: effort.plan,
        seed,
        keep: keep.max(1),
        focus: focus.as_ref(),
        focus_scale: focus_scale.as_ref(),
        trace: &trace,
    };
    let cal = bank.calibrate(
        &scale,
        ct.len(),
        CALIBRATION_SAMPLES,
        &mut Rng::new(seed ^ 0xCA11),
    );

    print!("{}", paint(args, &banner(ct, &bank)));
    print!("{}", paint(args, &diagnostics(ct, &bank, args)));

    print!("{}", paint(args, &report::heading("THE CATALOGUE")));
    print!("{}", paint(args, &report::outcome_header()));
    let attacks = if flag(args, "--gpu") {
        with_gpu(registry(effort.depth), effort.depth)
    } else {
        registry(effort.depth)
    };
    let mut outcomes = Vec::with_capacity(attacks.len());
    for attack in &attacks {
        let outcome = sweep::run(attack.as_ref(), ct, &ctx, effort.nulls);
        print!("{}", paint(args, &report::outcome_row(&outcome)));
        let _ = std::io::stdout().flush();
        outcomes.push(outcome);
    }

    if keep > 0 {
        print!(
            "{}",
            paint(args, &report::heading("WHAT EACH ATTACK READ IT AS"))
        );
        let mut ranked: Vec<_> = outcomes
            .iter()
            .flat_map(|o| o.best.iter().map(move |c| (o, c)))
            .collect();
        ranked.sort_unstable_by(|a, b| b.1.score.total_cmp(&a.1.score));
        for (outcome, candidate) in ranked.iter().take(8) {
            println!(
                "{}",
                paint(
                    args,
                    &format!(
                        "  {:+6.1}s {:<3} {:<30} {}\n       {}",
                        candidate.score,
                        bank.identify(&candidate.plain).0,
                        outcome.name,
                        candidate.key,
                        from_letters(&candidate.plain)
                    )
                )
            );
        }
    }

    print!("{}", paint(args, &report::heading("VERDICT")));
    let mut calibrator = report::Calibrator::new(&bank, &scale, seed ^ 0xCA11);
    let conclusion = report::conclude(&outcomes, &mut calibrator, |p| {
        bank.identify(p).0.to_string()
    });
    print!("{}", paint(args, &report::conclusion(&conclusion, &cal)));
    if let Conclusion::Read { .. } = conclusion {
        println!();
    }
    Ok(())
}

fn try_one(name: &str, ct: &[Letter], args: &[String]) -> Result<(), String> {
    let bank = models(args)?;
    let effort = effort_from(args);
    let seed = number(args, "--seed", 1u64);
    let scale = Scale::build(
        &bank,
        ct.len(),
        SCALE_SAMPLES,
        &mut Rng::new(seed ^ 0x5CA1E),
    );
    let focus = focus_model(args);
    let focus_scale = focus
        .as_ref()
        .map(|m| Scale::for_model(m, ct.len(), SCALE_SAMPLES, &mut Rng::new(seed ^ 0xF0C05)));
    let trace = cipher_break::trace::Trace::new(flag(args, "--trace"));
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: effort.plan,
        seed,
        keep: number(args, "--top", 5usize),
        focus: focus.as_ref(),
        focus_scale: focus_scale.as_ref(),
        trace: &trace,
    };
    let attacks = if flag(args, "--gpu") {
        with_gpu(registry(effort.depth), effort.depth)
    } else {
        registry(effort.depth)
    };
    let chosen: Vec<_> = attacks
        .iter()
        .filter(|a| a.name().starts_with(name))
        .collect();
    if chosen.is_empty() {
        return Err(format!(
            "no attack whose name starts with {name:?}; try `cb list`"
        ));
    }
    for attack in chosen {
        let outcome = sweep::run(attack.as_ref(), ct, &ctx, effort.nulls);
        print!("{}", paint(args, &report::heading(&outcome.name)));
        print!("{}", paint(args, &report::outcome_row(&outcome)));
        for candidate in &outcome.best {
            println!(
                "{}",
                paint(
                    args,
                    &format!(
                        "  {:+6.1}s {:<3} {:<28} {}",
                        candidate.score,
                        bank.identify(&candidate.plain).0,
                        candidate.key,
                        from_letters(&candidate.plain)
                    )
                )
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn an_option_is_the_word_after_its_name() {
        let a = args(&["solve", "file", "--top", "7", "--seed", "3"]);
        assert_eq!(option(&a, "--top"), Some("7"));
        assert_eq!(option(&a, "--seed"), Some("3"));
    }

    #[test]
    fn a_missing_option_is_absent() {
        assert_eq!(option(&args(&["solve"]), "--top"), None);
        assert_eq!(
            option(&args(&["--top"]), "--top"),
            None,
            "a name with nothing after it"
        );
    }

    #[test]
    fn an_option_is_found_wherever_it_sits() {
        let a = args(&["a", "b", "c", "d", "--word", "VONVON"]);
        assert_eq!(option(&a, "--word"), Some("VONVON"));
    }

    #[test]
    fn a_flag_is_present_or_it_is_not() {
        assert!(flag(&args(&["solve", "--gpu"]), "--gpu"));
        assert!(!flag(&args(&["solve"]), "--gpu"));
    }

    #[test]
    fn a_number_that_will_not_parse_falls_back() {
        assert_eq!(number(&args(&["--top", "9"]), "--top", 1usize), 9);
        assert_eq!(number(&args(&["--top", "x"]), "--top", 1usize), 1);
        assert_eq!(number(&args(&["--nope"]), "--top", 1usize), 1);
    }

    #[test]
    fn the_named_efforts_differ_and_deepen() {
        let quick = effort_from(&args(&["--effort", "quick"]));
        let normal = effort_from(&args(&[]));
        let deep = effort_from(&args(&["--effort", "deep"]));
        let max = effort_from(&args(&["--effort", "max"]));
        assert!(quick.depth < normal.depth);
        assert!(normal.depth < deep.depth);
        assert!(deep.depth < max.depth);
        assert!(quick.nulls < normal.nulls);
        assert!(quick.plan.steps < max.plan.steps);
    }

    #[test]
    fn an_explicit_depth_and_null_count_win() {
        let e = effort_from(&args(&[
            "--effort", "quick", "--depth", "6", "--nulls", "30",
        ]));
        assert_eq!(e.depth, 6);
        assert_eq!(e.nulls, 30);
    }

    #[test]
    fn an_unknown_effort_is_the_ordinary_one() {
        assert_eq!(
            effort_from(&args(&["--effort", "wat"])).depth,
            effort_from(&args(&[])).depth
        );
    }

    #[test]
    fn colour_can_be_taken_out() {
        let painted = "\x1b[1;32mREAD\x1b[0m here";
        assert_eq!(strip_ansi(painted), "READ here");
        assert_eq!(strip_ansi("nothing to strip"), "nothing to strip");
        assert_eq!(paint(&args(&["--plain"]), painted), "READ here");
    }

    #[test]
    fn the_built_in_bank_carries_every_shipped_model() {
        let bank = models(&args(&[])).expect("the bundle parses");
        assert_eq!(bank.len(), 26, "languages: {:?}", bank.languages());
        assert!(bank.model_named("de").is_some());
        assert!(bank.model_named("ja").is_some());
        assert!(!bank.is_empty());
    }

    #[test]
    fn the_german_model_loads_only_when_asked_for() {
        assert!(focus_model(&args(&[])).is_none());
        assert!(focus_model(&args(&["--language", "de"])).is_some());
        assert!(focus_model(&args(&["--language", "xx"])).is_none());
    }

    #[test]
    fn the_german_model_is_the_quadgram_one() {
        let m = focus_model(&args(&["--language", "de"])).expect("loads");
        assert_eq!(m.order(), 4);
        assert!(m.total() > 1_000_000.0, "trained on {} grams", m.total());
    }

    #[test]
    fn the_catalogue_names_are_distinct() {
        let names: Vec<String> = registry(4).iter().map(|a| a.name()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "two attacks share a name");
    }

    #[test]
    fn the_catalogue_deepens_with_the_depth_it_is_given() {
        assert!(registry(5).len() > registry(3).len());
    }

    #[test]
    fn a_flag_in_the_ciphertext_slot_is_refused_rather_than_deciphered() {
        for flag in ["--help", "--m3", "-x"] {
            let refusal = input_from(Some(&flag.to_string()))
                .expect_err("a flag must never be read as a ciphertext");
            assert!(refusal.contains(flag), "{refusal} should name {flag}");
        }
        assert!(
            input_from(Some(&"HELLO".to_string())).is_ok(),
            "a real ciphertext still goes through"
        );
    }

    #[test]
    fn the_usage_text_lists_every_command_the_parser_accepts() {
        for command in [
            "solve", "report", "crib", "bombe", "try", "list", "devices", "train",
        ] {
            assert!(
                USAGE.contains(command),
                "{command} is not in the usage text"
            );
        }
    }
}
