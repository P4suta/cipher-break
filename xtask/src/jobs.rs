// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::process::{Cmd, json_write, now, option, sha};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub fn check(args: &[String]) -> Result<()> {
    if args == ["--quick"] {
        return quick();
    }
    ensure!(args.is_empty(), "use check [--quick]");
    if std::env::var_os("CB_CLOUD_RUN").is_some() {
        let start = Instant::now();
        let limit = Duration::from_mins(70);
        for command in [
            Cmd::new(["mise", "trust", "--yes"]),
            Cmd::new(["mise", "install"]),
            Cmd::new(["mise", "run", "check:worker"]),
        ] {
            command
                .live(
                    limit
                        .checked_sub(start.elapsed())
                        .context("cloud check exceeded its shared time limit")?,
                )?
                .require_success(&command)?;
        }
        Ok(())
    } else {
        crate::cloud::dispatch(&[
            "run".into(),
            "gpu".into(),
            "--standard".into(),
            "--recovery".into(),
        ])
    }
}

fn quick() -> Result<()> {
    let started = Instant::now();
    let limit = Duration::from_secs(60);
    let mut records = Vec::new();
    for argv in [
        vec!["cargo", "fmt", "--all", "--check"],
        vec![
            "cargo",
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--features",
            "gpu",
            "--",
            "-D",
            "warnings",
        ],
        vec!["cargo", "test", "--locked", "--package", "xtask"],
        vec!["cargo", "test", "--locked", "--release", "--lib", "bombe"],
        vec![
            "cargo",
            "test",
            "--locked",
            "--release",
            "--test",
            "recovery",
        ],
    ] {
        let command = Cmd::new(argv)
            .env("CARGO_BUILD_JOBS", "2")
            .env("RAYON_NUM_THREADS", "2");
        let remaining = limit.checked_sub(started.elapsed()).context(
            "local quick check reached its one-minute limit; use mise run check for GCP",
        )?;
        let outcome = command.live(remaining)?;
        records.push(json!({"command": command, "result": outcome}));
        json_write(
            &crate::root().join("reports/quick-check.json"),
            &json!({"maximum_seconds": 60, "build_jobs": 2, "rayon_threads": 2, "commands": records}),
        )?;
        outcome.require_success(&command)?;
    }
    Ok(())
}

pub fn agree(args: &[String]) -> Result<()> {
    ensure!(args.is_empty(), "agree takes no options");
    let rust = Cmd::new([
        "cargo",
        "run",
        "--release",
        "--quiet",
        "--bin",
        "cb",
        "--",
        "report",
        "data/ciphertext.txt",
        "--plain",
    ])
    .checked()?;
    let mut reference = Cmd::new([
        "mise",
        "x",
        "--",
        "cabal",
        "run",
        "-v0",
        "cipher-break-reference",
        "--",
        "analyze",
        "../data/ciphertext.txt",
        "--null",
        "1",
    ]);
    reference.cwd = crate::root().join("reference");
    let haskell = reference.checked()?;
    let rust_ic = rust
        .lines()
        .find(|s| s.starts_with("  cipher-break"))
        .and_then(|s| after(s, "IC"))
        .context("Rust IC was not reported")?;
    let haskell_ic = haskell
        .lines()
        .find_map(|s| s.strip_prefix("IC "))
        .and_then(|s| s.split_whitespace().next())
        .context("Haskell IC was not reported")?;
    ensure!(
        rust_ic == haskell_ic,
        "implementations disagree: Rust IC {rust_ic}, Haskell IC {haskell_ic}"
    );
    println!("rust IC {rust_ic}, haskell IC {haskell_ic}");
    Ok(())
}

fn after<'a>(line: &'a str, token: &str) -> Option<&'a str> {
    let mut words = line.split_whitespace();
    words.find(|&word| word == token)?;
    words.next()
}

pub fn bench(options: &[String]) -> Result<()> {
    let periods = match options {
        [] => vec![4, 5, 6],
        [flag, value] if flag == "--period" => vec![value.parse::<usize>()?],
        _ => anyhow::bail!("use bench [--period N]"),
    };
    ensure!(
        periods.iter().all(|&p| (1..=6).contains(&p)),
        "bench periods must be between one and six"
    );
    if std::env::var_os("CB_CLOUD_RUN").is_none() {
        let mut command = vec![
            "run".into(),
            "gpu".into(),
            "--".into(),
            "cargo".into(),
            "xtask".into(),
            "bench".into(),
        ];
        command.extend_from_slice(options);
        return crate::cloud::dispatch(&command);
    }
    let build = Cmd::new([
        "cargo",
        "build",
        "--release",
        "--features",
        "gpu",
        "--bin",
        "cb",
    ]);
    build
        .live(Duration::from_mins(30))?
        .require_success(&build)?;
    let devices = Cmd::new(["./target/release/cb", "devices"]).checked()?;
    ensure!(
        !devices.contains("unavailable:") && !devices.contains("not built in"),
        "the GPU benchmark requires a hardware adapter: {devices}"
    );
    let mut measurements = Vec::new();
    for period in periods {
        for backend in ["cpu", "gpu"] {
            let mut argv = vec![
                "./target/release/cb".into(),
                "try".into(),
                format!("vigenere period {period}"),
                "data/ciphertext.txt".into(),
                "--nulls".into(),
                "0".into(),
                "--depth".into(),
                "7".into(),
                "--plain".into(),
            ];
            if backend == "gpu" {
                argv.push("--gpu".into());
            }
            let command = Cmd::new(argv);
            let result = command.capture()?;
            result.require_success(&command)?;
            println!("period {period} {backend} real {:.3}s", result.seconds);
            measurements.push(
                json!({"period": period, "backend": backend, "command": command, "result": result}),
            );
        }
    }
    json_write(
        &crate::root().join("reports/bench.json"),
        &json!({"purpose": "runtime only; no plaintext or statistical verdict", "measurements": measurements}),
    )
}

pub fn cribs(options: &[String]) -> Result<()> {
    ensure!(
        (1..=2).contains(&options.len()),
        "use cribs LIST [MODEL_PATH_OR_GS_URI]"
    );
    ensure!(
        std::env::var_os("CB_CLOUD_RUN").is_some(),
        "submit target crib batches through cargo xtask cloud run; heavy local searches are disabled"
    );
    let parsed = crib_lines(&fs::read_to_string(&options[0])?)?;
    let focus = if let Some(model) = options.get(1) {
        if model.starts_with("gs://") {
            anyhow::bail!(
                "GCS models must be staged by cargo xtask cloud run; the worker has no cloud credentials"
            );
        }
        Some(PathBuf::from(model))
    } else {
        None
    };
    let mut build = Cmd::new(["cargo", "build", "--release", "--bin", "cb"]);
    if parsed.iter().any(|p| p.iter().any(|s| s == "--gpu")) {
        build.argv.extend(["--features".into(), "gpu".into()]);
    }
    build
        .live(Duration::from_mins(30))?
        .require_success(&build)?;
    let mut results = Vec::new();
    for words in parsed {
        let (word, rest) = words.split_first().context("crib word")?;
        println!("=== crib {word} {}", rest.join(" "));
        let mut argv = vec![
            "./target/release/cb".into(),
            "bombe".into(),
            "data/ciphertext.txt".into(),
            "--word".into(),
            word.clone(),
        ];
        argv.extend_from_slice(rest);
        argv.extend(focus.as_ref().map_or_else(
            || vec!["--language".into(), "de".into()],
            |p| vec!["--focus".into(), p.to_string_lossy().into_owned()],
        ));
        argv.push("--plain".into());
        let command = Cmd::new(argv);
        let result = command.live(Duration::from_mins(90))?;
        results.push(json!({"command": command, "result": result}));
    }
    let failed = results
        .iter()
        .any(|r| r["result"]["exit_code"] != 0 || r["result"]["timed_out"] == true);
    json_write(&crate::root().join("reports/cribs.json"), &results)?;
    ensure!(
        !failed,
        "at least one crib job failed; see reports/cribs.json"
    );
    Ok(())
}

fn crib_lines(text: &str) -> Result<Vec<Vec<String>>> {
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(|line| {
            let words = shlex::split(line).context("invalid quoting in crib list")?;
            ensure!(
                words
                    .first()
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_uppercase())),
                "crib must be uppercase letters: {line}"
            );
            Ok(words)
        })
        .collect()
}

pub const GPU_TESTS: [(&str, &str); 3] = [
    (
        "enigma",
        "device::the_device_refutes_exactly_what_the_processor_refutes",
    ),
    (
        "enigma",
        "device::climbs_a_plugboard_exactly_as_the_processor_does",
    ),
    (
        "recovery",
        "the_gpu_shortlist_recovers_ten_leads_and_rejects_shuffles",
    ),
];

pub fn recovery(args: &[String]) -> Result<()> {
    ensure!(
        std::env::var_os("CB_CLOUD_RUN").is_some(),
        "run recovery through cargo xtask cloud run gpu --recovery"
    );
    let mut minutes = 80;
    let mut gpu_only = false;
    let mut args = args.iter().cloned();
    while let Some(arg) = args.next() {
        if arg == "--gpu-only" {
            gpu_only = true;
            continue;
        }
        ensure!(arg == "--max-minutes", "unknown recovery option {arg}");
        minutes = option(&mut args, &arg)?.parse::<u64>()?;
    }
    ensure!(
        (1..=90).contains(&minutes),
        "recovery runtime must be between one and ninety minutes"
    );
    let path = crate::root().join("reports/p1030680/recovery-result.json");
    let mut report = json!({
        "status": "running", "started_at": now()?, "maximum_minutes": minutes,
        "fixture": "P1030698: 72 letters, ten plug leads", "seed": 1,
        "shuffle_seed": 20_261_002, "nulls": 8, "shortlist": 64,
        "crib_length": 24, "scope": "one known rotor order and composite reflector; all middle/right rings",
        "whole_key_space_validated": false, "tests": []
    });
    report["full_check_in_this_run"] = json!(!gpu_only);
    report["provenance_sha256"] = json!(crate::audit::provenance()?);
    json_write(&path, &report)?;
    let start = Instant::now();
    let result = recover_tests(
        start,
        Duration::from_secs(minutes * 60),
        &path,
        &mut report,
        gpu_only,
    );
    report["status"] = json!(if result.is_ok() {
        if gpu_only { "gpu_passed" } else { "passed" }
    } else {
        "failed"
    });
    report["finished_at"] = json!(now()?);
    report["seconds"] = json!(start.elapsed().as_secs_f64());
    if let Err(error) = &result {
        report["error"] = json!(format!("{error:#}"));
    }
    json_write(&path, &report)?;
    result
}

fn recover_tests(
    start: Instant,
    limit: Duration,
    path: &std::path::Path,
    report: &mut Value,
    gpu_only: bool,
) -> Result<()> {
    let trust = Cmd::new(["mise", "trust", "--yes"]);
    recorded(&trust, start, limit, path, report)?;
    let install = Cmd::new(["mise", "install"]);
    recorded(&install, start, limit, path, report)?;
    for program in ["rustc", "cargo"] {
        let version = Cmd::new(["mise", "x", "--", program, "--version"]);
        recorded(&version, start, limit, path, report)?;
    }
    let inputs: std::collections::BTreeMap<String, String> = [
        "data/ciphertext.txt",
        "data/german-quadgrams.txt",
        "data/models.bundle",
        "tests/recovery.rs",
    ]
    .iter()
    .map(|p| Ok(((*p).to_owned(), sha(&crate::root().join(p))?)))
    .collect::<Result<_>>()?;
    report["input_sha256"] = json!(inputs);
    for (suite, name) in GPU_TESTS {
        let listing = Cmd::new([
            "mise",
            "x",
            "--",
            "cargo",
            "test",
            "--locked",
            "--release",
            "--features",
            "gpu",
            "--test",
            suite,
            "--",
            "--ignored",
            "--exact",
            name,
            "--list",
        ]);
        let output = recorded(&listing, start, limit, path, report)?;
        exactly_one(&output, name)?;
        let test = Cmd::new([
            "mise",
            "x",
            "--",
            "cargo",
            "test",
            "--locked",
            "--release",
            "--features",
            "gpu",
            "--test",
            suite,
            "--",
            "--ignored",
            "--exact",
            name,
            "--nocapture",
        ]);
        let output = recorded(&test, start, limit, path, report)?;
        ensure!(
            output.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "{suite}::{name} did not execute exactly one passing GPU test"
        );
    }
    if gpu_only {
        // More than 32 retrieval jobs exercise domyjob's finished-workspace retention.
        let probe = json!({"purpose":"artifact transfer integrity only", "payload":"A\u{3042}\n".repeat(30_000)});
        json_write(
            &crate::root().join("reports/p1030680/artifact-probe.json"),
            &probe,
        )?;
    } else {
        let full = Cmd::new(["mise", "run", "check"]);
        recorded(&full, start, limit, path, report)?;
    }
    Ok(())
}

fn recorded(
    command: &Cmd,
    start: Instant,
    limit: Duration,
    path: &std::path::Path,
    report: &mut Value,
) -> Result<String> {
    let remaining = limit
        .checked_sub(start.elapsed())
        .context("recovery exceeded its overall time limit")?;
    let outcome = command.live(remaining)?;
    report["tests"]
        .as_array_mut()
        .context("test records")?
        .push(json!({"command": command, "result": outcome}));
    json_write(path, report)?;
    outcome.require_success(command)?;
    Ok(outcome.stdout)
}

fn exactly_one(output: &str, name: &str) -> Result<()> {
    ensure!(
        output
            .lines()
            .filter(|line| *line == format!("{name}: test"))
            .count()
            == 1,
        "expected exactly one GPU test named {name}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_duplicated_gpu_test_cannot_pass() {
        assert!(exactly_one("0 tests, 0 benchmarks\n", "recovery").is_err());
        assert!(exactly_one("recovery: test\nrecovery: test\n", "recovery").is_err());
        assert!(exactly_one("recovery: test\n1 test, 0 benchmarks\n", "recovery").is_ok());
    }

    #[test]
    fn crib_lists_keep_literal_arguments_and_skip_comments() {
        let parsed = crib_lines("# comment\n\nABC --at 0 --focus '$(literal) model'\n").unwrap();
        assert_eq!(
            parsed,
            vec![vec!["ABC", "--at", "0", "--focus", "$(literal) model"]]
        );
        assert!(crib_lines("ABC --focus 'unfinished").is_err());
    }
}
