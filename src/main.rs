// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cb` — break a classical cipher, or find out honestly that you cannot.
//!
//! The command with no subcommand is the one to reach for: hand it a ciphertext and it runs the whole catalogue, calibrates itself, and says either what the message is or exactly what it ruled out on the way to not knowing.

use cipher_break::alphabet::{Letter, from_letters, to_letters};
use cipher_break::anneal::Schedule;
use cipher_break::attack::{Context, registry};
use cipher_break::ngram::Model;
use cipher_break::polyglot::{Polyglot, Scale};
use cipher_break::report::{self, Conclusion};
use cipher_break::rng::Rng;
use cipher_break::stats::{ic_by_period, index_of_coincidence};
use cipher_break::sweep;
use cipher_break::triage;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The language models, carried inside the binary so that `cb` works from any directory with nothing installed beside it.
const BUNDLE: &str = include_str!("../data/models.bundle");

/// A quadgram model of German, for the one case where provenance fixes the language: a Kriegsmarine signal is in German, and a sharper judge than the shared trigram bank is what tells a real plugboard lead from a flattering one.
const GERMAN_QUADGRAMS: &str = include_str!("../data/german-quadgrams.txt");

const USAGE: &str = "\
cb — a cryptanalysis workbench for classical ciphers

USAGE
  cb <ciphertext|file|->                run the whole catalogue and report
  cb solve   <input> [options]          the same, spelled out
  cb report  <input> [options]          diagnostics only: what the text is
  cb try     <attack> <input>           run one attack by name
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
  --gpu                            run the big exhaustive sweeps on the GPU
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
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print!("{USAGE}");
        return Ok(());
    }
    match args[0].as_str() {
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

// --------------------------------------------------------------------------
// input and options
// --------------------------------------------------------------------------

/// Read the ciphertext from wherever it is.
///
/// A path, a dash for standard input, or the letters themselves.
/// Guessing between them is the single largest convenience the tool offers, and it is safe to guess: a path that exists is a path, and anything else is text.
fn input_from(arg: Option<&String>) -> Result<Vec<Letter>, String> {
    let arg = arg.ok_or("give me a ciphertext, a file, or - for standard input")?;
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

/// How hard to search, as one word.
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
            plan: base.scaled(0.25),
            nulls: 4,
        },
        "deep" => Effort {
            depth: 5,
            plan: base.scaled(2.0),
            nulls: 16,
        },
        "max" => Effort {
            depth: 6,
            plan: base.scaled(4.0),
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

/// Load the models: a directory if one was named, the built-in bundle if not.
fn models(args: &[String]) -> Result<Polyglot, String> {
    if let Some(dir) = option(args, "--models") {
        return Polyglot::load(&PathBuf::from(dir)).map_err(|e| format!("{dir}: {e}"));
    }
    Ok(Polyglot::from_bundle(BUNDLE))
}

/// The high-order model for a language the caller says it already knows.
///
/// Nothing loads this unless it is asked for.
/// The tool's whole posture is that it does not know the language, and `--language` is the caller taking responsibility for saying otherwise.
fn focus_model(args: &[String]) -> Option<Model> {
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

// --------------------------------------------------------------------------
// commands
// --------------------------------------------------------------------------

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

/// Swap the processor's periodic sweeps for the device's, where it pays.
///
/// Short periods finish before a dispatch could even be submitted, so they stay where they are; the crossing only earns its keep once a sweep runs to tens of millions of keys.
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
        shortlist: 400,
        leads: 10,
        focus: "de".to_string(),
        gpu: gpu.clone(),
    }));
    for period in 1..=depth {
        if period >= 4 {
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

fn list() {
    for attack in registry(8) {
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

/// Everything that can be said about the text before a key is tried.
fn diagnostics(ct: &[Letter], bank: &Polyglot, args: &[String]) -> String {
    let mut out = String::new();
    let mut rng = Rng::new(number(args, "--seed", 1u64) ^ 0xC0FF_EE00);
    let population =
        triage::random_population(ct.len(), number(args, "--trials", 20_000usize), &mut rng);
    let verdicts: Vec<_> = triage::statistics(Some(bank))
        .iter()
        .map(|st| triage::assess(st, ct, &population))
        .collect();
    out.push_str(&report::heading("AGAINST RANDOM LETTERS"));
    out.push_str(&report::statistics_table(&verdicts, "random"));

    out.push_str(&report::heading("PERIOD"));
    out.push_str("  a period shows itself as columns that are each monoalphabetic\n");
    let _ = writeln!(
        out,
        "  {:<6} {:>8} {:>10} {:>8}",
        "period", "column IC", "shuffled", "z"
    );
    let shuffles: Vec<Vec<Letter>> = (0..200).map(|_| rng.shuffled(ct)).collect();
    for p in 2..=16.min(ct.len() / 4).max(2) {
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
    let scale = Scale::build(&bank, ct.len(), 256, &mut Rng::new(seed ^ 0x5CA1E));
    let focus = focus_model(args);
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: effort.plan,
        seed,
        keep: keep.max(1),
        focus: focus.as_ref(),
    };
    let cal = bank.calibrate(&scale, ct.len(), 200, &mut Rng::new(seed ^ 0xCA11));

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
    let scale = Scale::build(&bank, ct.len(), 256, &mut Rng::new(seed ^ 0x5CA1E));
    let focus = focus_model(args);
    let ctx = Context {
        judge: &bank,
        scale: &scale,
        plan: effort.plan,
        seed,
        keep: number(args, "--top", 5usize),
        focus: focus.as_ref(),
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
