// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::process::{Cmd, json_read, json_write, now, option, sha, shell};
use anyhow::{Context, Result, ensure};
use cipher_break::rng::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const MACHINE_SETTINGS: u64 = 336 * 104 * 26_u64.pow(3) * 26_u64.pow(2);

#[derive(Deserialize)]
struct Ledger {
    input_version: String,
    null: Null,
    candidates: Vec<Value>,
}

#[derive(Deserialize, Serialize)]
struct Null {
    method: String,
    seed: u64,
    samples: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
struct Placement {
    offset: usize,
    closures: usize,
    components: usize,
}

fn placements(cipher: &[u8], word: &[u8], offsets: &Value) -> Vec<Placement> {
    if word.len() > cipher.len() {
        return Vec::new();
    }
    (0..=cipher.len() - word.len())
        .filter_map(|at| {
            if offsets != "all"
                && !offsets
                    .as_array()?
                    .iter()
                    .any(|v| v.as_u64() == Some(at as u64))
            {
                return None;
            }
            let pairs = word.iter().zip(&cipher[at..]);
            if pairs.clone().any(|(p, c)| p == c) {
                return None;
            }
            let mut parent = std::array::from_fn::<_, 26, _>(|i| i);
            let mut present = [false; 26];
            let mut closures = 0;
            for (&p, &c) in pairs {
                let p = usize::from(p - b'A');
                let c = usize::from(c - b'A');
                present[p] = true;
                present[c] = true;
                let a = find(&parent, p);
                let b = find(&parent, c);
                if a == b {
                    closures += 1;
                } else {
                    parent[a] = b;
                }
            }
            let components = (0..26)
                .filter(|&i| present[i] && find(&parent, i) == i)
                .count();
            Some(Placement {
                offset: at,
                closures,
                components,
            })
        })
        .collect()
}

fn find(parent: &[usize; 26], mut i: usize) -> usize {
    while parent[i] != i {
        i = parent[i];
    }
    i
}

fn published_plaintext(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path).with_context(|| {
        format!(
            "missing source {}; run cargo xtask p1030680 sources",
            path.display()
        )
    })?;
    let mut text = String::new();
    let mut tag = false;
    for c in raw.chars() {
        match c {
            '<' => {
                tag = true;
                text.push(' ');
            }
            '>' => tag = false,
            _ if !tag => text.push(c),
            _ => (),
        }
    }
    let text = html_escape::decode_html_entities(&text);
    let (_, section) = text
        .split_once("Plaintext:")
        .context("source has no labelled plaintext")?;
    let (plain, _) = section
        .split_once("Interpretation")
        .context("source has no plaintext section boundary")?;
    Ok(plain.chars().filter(|c| !c.is_whitespace()).collect())
}

pub fn provenance() -> Result<BTreeMap<String, String>> {
    let root = crate::root();
    let mut paths: Vec<PathBuf> = [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "mise.toml",
        ".cargo/config.toml",
        "data/cloud-prices.json",
        "tests/recovery.rs",
        "tests/enigma.rs",
        "xtask/Cargo.toml",
        "data/models.bundle",
        "data/german-quadgrams.txt",
        "data/p1030680/candidates.json",
        "data/p1030680/transcription.json",
    ]
    .iter()
    .map(|p| root.join(p))
    .collect();
    for dir in ["src", "xtask/src", "xtask/assets"] {
        collect(&root.join(dir), &mut paths)?;
    }
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            Ok((
                path.strip_prefix(&root)?.to_string_lossy().into_owned(),
                sha(&path)?,
            ))
        })
        .collect()
}

fn collect(dir: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, paths)?;
        } else {
            paths.push(path);
        }
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    let root = crate::root();
    let mut sources = root.join("reports/p1030680/sources");
    let mut output = root.join("reports/p1030680");
    let mut recovery_path = root.join("data/p1030680/recovery-result.json");
    let mut compare = None;
    let mut args = args.iter().cloned();
    while let Some(arg) = args.next() {
        let value = PathBuf::from(option(&mut args, &arg)?);
        match arg.as_str() {
            "--sources" => sources = value,
            "--output" => output = value,
            "--recovery-result" => recovery_path = value,
            "--compare-to" => compare = Some(value),
            _ => anyhow::bail!("unknown audit option {arg}"),
        }
    }
    let (audit, jobs) = build(&sources, &recovery_path)?;
    let prior = prior_runs(&root.join("reports/cloud"))?;
    if let Some(baseline) = compare {
        let old = json_read(&baseline.join("candidate-audit.json"))?;
        ensure!(
            old["candidates"] == audit["candidates"]
                && old["null"] == audit["null"]
                && old["input_sha256"] == audit["input_sha256"],
            "audit differs from the migration baseline"
        );
        let old_prior = json_read(&baseline.join("prior-runs.json"))?;
        if old_prior != prior {
            json_write(&output.join("migration-prior-runs.json"), &prior)?;
            let difference = old_prior
                .as_array()
                .context("baseline runs")?
                .iter()
                .zip(prior.as_array().context("audited runs")?)
                .find(|(old, new)| old != new);
            anyhow::bail!("prior-run coverage differs from the migration baseline: {difference:?}");
        }
        println!(
            "Candidate placements, all null placements, and prior-run coverage match the migration baseline."
        );
    }
    for (name, value) in [
        ("candidate-audit.json", &audit),
        ("jobs.json", &jobs),
        ("prior-runs.json", &prior),
    ] {
        json_write(&output.join(name), value)?;
    }
    for candidate in audit["candidates"].as_array().context("candidate array")? {
        for crib in candidate["cribs"].as_array().context("crib array")? {
            println!(
                "{} {} placements {} raw settings {}",
                string(candidate, "id")?,
                string(crib, "word")?,
                crib["placements"],
                crib["raw_full_ring_settings"]
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn build(sources: &Path, recovery_path: &Path) -> Result<(Value, Value)> {
    let root = crate::root();
    let ledger_path = root.join("data/p1030680/candidates.json");
    let transcription_path = root.join("data/p1030680/transcription.json");
    let ledger: Ledger = serde_json::from_slice(&fs::read(&ledger_path)?)?;
    let transcription = json_read(&transcription_path)?;
    let cipher: Vec<u8> = fs::read(root.join("data/ciphertext.txt"))?
        .into_iter()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    ensure!(
        cipher.len() == 72 && cipher.iter().all(u8::is_ascii_uppercase),
        "expected the reviewed 72-letter body"
    );
    let body = transcription["body_groups"]
        .as_array()
        .context("transcribed body groups")?
        .iter()
        .map(|s| s.as_str().context("body group"))
        .collect::<Result<Vec<_>>>()?
        .join("");
    ensure!(
        cipher == body.as_bytes(),
        "input differs from the reviewed image"
    );
    ensure!(
        ledger.candidates.len() <= 10,
        "candidate ledger exceeds ten hypotheses"
    );
    ensure!(
        ledger.input_version == transcription["version"],
        "input version differs from the transcription"
    );
    ensure!(
        (1..=10_000).contains(&ledger.null.samples) && ledger.null.seed != 0,
        "invalid structural null recipe"
    );
    let mut rng = Rng::new(ledger.null.seed);
    let nulls: Vec<_> = (0..ledger.null.samples)
        .map(|_| rng.shuffled(&cipher))
        .collect();
    let provenance = provenance()?;
    let recovery = if recovery_path.exists() {
        json_read(recovery_path)?
    } else {
        Value::Null
    };
    let recovery_status = recovery_status(&recovery, &provenance);
    let model_sha = sha(&root.join("data/german-quadgrams.txt"))?;
    let mut jobs = vec![json!({
        "id": "recovery", "status": recovery_status, "result": recovery,
        "matches_current_provenance": recovery["provenance_sha256"] == json!(provenance),
        "result_sha256": if recovery_path.exists() { Some(sha(recovery_path)?) } else { None },
        "argv": ["mise", "x", "--", "cargo", "xtask", "cloud", "run", "gpu", "--standard", "--recovery"],
        "input": "published P1030698 and synthetic double-step starts", "model": "data/german-quadgrams.txt",
        "model_sha256": model_sha, "seed": 1, "shuffle_seed": 20_261_002, "nulls": 8,
        "rotor_orders": [[4, 3, 8]], "reflectors": ["gamma/W B-thin"],
        "rings": "all middle/right, left normalized to A", "shortlist": 64, "crib_length": 24,
        "maximum_vm_hours": 2, "maximum_usd": 5
    })];
    let mut candidates = Vec::new();
    for mut candidate in ledger.candidates {
        let cribs = candidate["cribs"].as_array().context("crib array")?.clone();
        let mut results = Vec::new();
        for mut crib in cribs {
            let word = string(&crib, "word")?.to_owned();
            ensure!(
                !word.is_empty() && word.bytes().all(|c| c.is_ascii_uppercase()),
                "crib must contain uppercase letters"
            );
            let message = string(&crib, "source_message")?;
            ensure!(
                message.starts_with('P') && message[1..].bytes().all(|b| b.is_ascii_digit()),
                "invalid source message id"
            );
            let source = sources.join(format!("{message}.html"));
            ensure!(
                published_plaintext(&source)?.contains(&word),
                "{word} is not a contiguous published plaintext fragment"
            );
            ensure!(
                crib["offsets"] == "all"
                    || crib["offsets"]
                        .as_array()
                        .is_some_and(|a| a.iter().all(|v| v.as_u64().is_some())),
                "invalid crib offsets"
            );
            let observed = placements(&cipher, word.as_bytes(), &crib["offsets"]);
            let controls: Vec<_> = nulls
                .iter()
                .map(|sample| placements(sample, word.as_bytes(), &crib["offsets"]))
                .collect();
            let loops: Vec<_> = observed.iter().filter(|m| m.closures > 0).collect();
            crib["source_sha256"] = json!(sha(&source)?);
            crib["placements"] = json!(observed);
            crib["structural_null"] = json!(controls);
            crib["raw_full_ring_settings"] = json!(MACHINE_SETTINGS * loops.len() as u64);
            crib["unique_ring_representatives"] =
                json!("not measured; the implementation removes equivalent traces");
            crib["plugboard_space"] = json!("ten-lead completions are heuristic, not exhausted");
            for menu in loops {
                let argv: Vec<String> = [
                    "cb",
                    "bombe",
                    "data/ciphertext.txt",
                    "--word",
                    &word,
                    "--at",
                    &menu.offset.to_string(),
                    "--rings",
                    "--language",
                    "de",
                    "--seed",
                    "1",
                    "--gpu",
                    "--plain",
                ]
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
                jobs.push(json!({
                    "id": format!("{}-{word}-{}", string(&candidate, "id")?, menu.offset),
                    "eligible": false, "reason": format!("{} Target-specific evidence and a measured whole-scope cost remain required.", string(&candidate, "unknowns")?),
                    "recovery_status": recovery_status, "input_version": ledger.input_version,
                    "input_sha256": sha(&root.join("data/ciphertext.txt"))?,
                    "model": "data/german-quadgrams.txt", "model_sha256": model_sha, "seed": 1,
                    "argv": argv, "shell": shell(&argv), "scope": "a proposed full middle/right ring sweep with capped finishing",
                    "cost_usd": null, "seconds": null,
                    "null": "require the identical placement, selection, finishing, and ranking on same-letter shuffles; the existing fitted finishing null is insufficient for a reading declaration"
                }));
            }
            results.push(crib);
        }
        candidate["cribs"] = json!(results);
        candidates.push(candidate);
    }
    Ok((
        json!({
            "input_version": ledger.input_version, "input_sha256": sha(&root.join("data/ciphertext.txt"))?,
            "ledger_sha256": sha(&ledger_path)?, "transcription_sha256": sha(&transcription_path)?,
            "provenance_sha256": provenance, "null": ledger.null, "candidates": candidates
        }),
        json!({
            "campaign_cap_usd": 50, "recovery_cap_usd": 5, "maximum_parallel_vms": 1,
            "maximum_search_candidates": 3, "provenance_sha256": provenance, "jobs": jobs
        }),
    ))
}

pub fn sources(args: &[String]) -> Result<()> {
    let directory = match args {
        [] => crate::root().join("reports/p1030680/sources"),
        [flag, path] if flag == "--sources" => PathBuf::from(path),
        _ => anyhow::bail!("use sources [--sources DIR]"),
    };
    fs::create_dir_all(&directory)?;
    let ledger = json_read(&crate::root().join("data/p1030680/candidates.json"))?;
    let mut saved = BTreeMap::new();
    for candidate in ledger["candidates"].as_array().context("candidate array")? {
        for crib in candidate["cribs"].as_array().context("crib array")? {
            let id = string(crib, "source_message")?;
            if saved.contains_key(id) {
                continue;
            }
            let path = directory.join(format!("{id}.html"));
            let url = string(candidate, "source")?;
            ensure!(
                url.starts_with("https://enigma.hoerenberg.com/index.php?"),
                "unexpected source host"
            );
            let command = Cmd::new([
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--output",
                &path.to_string_lossy(),
                url,
            ]);
            command.checked()?;
            published_plaintext(&path)?;
            saved.insert(
                id.to_owned(),
                json!({"url": url, "sha256": sha(&path)?, "retrieved_at": now()?}),
            );
        }
    }
    json_write(&directory.join("crib-sources.json"), &saved)
}

fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .with_context(|| format!("missing string {name}"))
}

fn recovery_status<'a>(recovery: &'a Value, provenance: &BTreeMap<String, String>) -> &'a str {
    if !recovery.is_null() && recovery["provenance_sha256"] != json!(provenance) {
        return "stale_provenance";
    }
    recovery["status"]
        .as_str()
        .unwrap_or("pending: cloud hardware recovery has not completed")
}

pub fn prior_runs(folder: &Path) -> Result<Value> {
    if !folder.exists() {
        return Ok(json!([]));
    }
    let mut runs: Vec<_> = fs::read_dir(folder)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    runs.sort();
    let mut output = Vec::new();
    for run in runs {
        let manifest = run.join("manifest.txt");
        if !manifest.exists() {
            continue;
        }
        let text = fs::read_to_string(&manifest)?;
        let command = text
            .lines()
            .find_map(|line| line.strip_prefix("command  "))
            .unwrap_or("");
        let status = run.join("out/status");
        let log = run.join("out/log.txt");
        let mut entry = json!({"id": run.file_name().context("run id")?.to_string_lossy(), "manifest_sha256": sha(&manifest)?, "command": command, "status": if status.exists() { fs::read_to_string(status)?.trim().to_owned() } else { "missing".into() }, "cribs": []});
        if log.exists() {
            entry["log_sha256"] = json!(sha(&log)?);
            entry["cribs"] = parse_log(&String::from_utf8_lossy(&fs::read(log)?), command);
        } else {
            entry["log"] = json!("missing");
        }
        output.push(entry);
    }
    Ok(json!(output))
}

fn parse_log(log: &str, command: &str) -> Value {
    let mut cribs: Vec<Value> = Vec::new();
    for line in log.lines() {
        if let Some(rest) = line.strip_prefix("=== crib ") {
            let word: String = rest.chars().take_while(char::is_ascii_uppercase).collect();
            if !word.is_empty() {
                let tail = &rest[word.len()..];
                let tokens: Vec<_> = tail.split_whitespace().collect();
                let at = tokens
                    .windows(2)
                    .find(|p| p[0] == "--at" || p[0] == "at")
                    .and_then(|p| {
                        p[1].chars()
                            .take_while(char::is_ascii_digit)
                            .collect::<String>()
                            .parse::<u64>()
                            .ok()
                    });
                cribs.push(json!({"word": word, "rings": if tail.contains("--right-rings") || command.contains("--right-rings") { "right only" } else if command.contains("--rings") { "middle and right" } else { "unrecorded" }, "offset": at.map_or_else(|| json!("all or unrecorded"), |a| json!(a)), "state": "started; completion unconfirmed"}));
            }
        }
        let Some(current) = cribs.last_mut() else {
            continue;
        };
        if let Some(number) = number_before(line, " settings survived") {
            current["survived"] = json!(number);
            current["state"] = json!("rotor sweep reported; finishing unconfirmed");
        }
        if let Some(number) = number_before(line, " of them finished and read") {
            current["finished"] = json!(number);
            current["state"] = json!(if number < current["survived"].as_u64().unwrap_or(0) {
                "capped finishing"
            } else {
                "all reported rotor stops finished; plugboard completion remains heuristic"
            });
        }
        if line.contains("not further than chance goes") {
            current["verdict"] = json!("not further than the historical fitted null");
        }
    }
    json!(cribs)
}

fn number_before(line: &str, marker: &str) -> Option<u64> {
    line.split_once(marker)?
        .0
        .split_whitespace()
        .last()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recovery_result_cannot_outlive_its_source_hashes() {
        let current = BTreeMap::from([("src/bombe.rs".to_owned(), "new".to_owned())]);
        for status in ["passed", "gpu_passed", "failed"] {
            let mut result = json!({"status": status, "provenance_sha256": current});
            assert_eq!(recovery_status(&result, &current), status);
            result["provenance_sha256"]["src/bombe.rs"] = json!("old");
            assert_eq!(recovery_status(&result, &current), "stale_provenance");
            result["provenance_sha256"] = Value::Null;
            assert_eq!(recovery_status(&result, &current), "stale_provenance");
        }
        assert!(recovery_status(&Value::Null, &current).starts_with("pending"));
    }

    #[test]
    fn self_enciphering_offsets_are_rejected_in_observed_and_null_runs() {
        assert!(
            placements(b"ABCD", b"AB", &json!("all"))
                .iter()
                .all(|m| m.offset != 0)
        );
        assert!(placements(b"ABCD", b"AB", &json!([0])).is_empty());
        assert!(placements(b"AB", b"ABCD", &json!("all")).is_empty());
        assert_eq!(
            placements(b"BABA", b"ABAB", &json!([0])),
            vec![Placement {
                offset: 0,
                closures: 3,
                components: 1
            }]
        );
    }

    #[test]
    fn capped_or_interrupted_searches_do_not_exclude_a_key_space() {
        let log = "=== crib ABC --at 0 --right-rings\n10 settings survived\n2 of them finished and read\n=== crib DEF --at 3\n";
        let result = parse_log(log, "cb --rings");
        assert_eq!(result[0]["rings"], "right only");
        assert_eq!(result[0]["state"], "capped finishing");
        assert_eq!(result[1]["state"], "started; completion unconfirmed");
        assert_eq!(result[1]["rings"], "middle and right");
        let comma = parse_log("=== crib ABC at 0, rings swept\n", "cb --rings");
        assert_eq!(comma[0]["offset"], 0);
    }
}
