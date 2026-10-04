// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(any(feature = "gpu", test))]
use crate::audit::{Placement, placements};
use crate::process::{Cmd, option};
#[cfg(feature = "gpu")]
use crate::process::{json_read, json_write};
use anyhow::{Context, Result, ensure};
#[cfg(any(feature = "gpu", test))]
use serde_json::{Value, json};
use std::time::{Duration, Instant};

#[cfg(feature = "gpu")]
const REPORT: &str = "reports/p1030680/campaign-result.json";

#[cfg(any(feature = "gpu", test))]
fn queue(cipher: &[u8], word: &[u8], offsets: &Value, at: Option<usize>) -> Vec<Placement> {
    let mut menus = placements(cipher, word, offsets);
    menus.retain(|p| {
        p.closures > 0
            && crate::proof_work::placement_selected(cipher.len(), word.len(), p.offset, at)
    });
    menus.sort_by_key(|p| (std::cmp::Reverse(p.closures), p.offset));
    menus
}

#[cfg(any(feature = "gpu", test))]
fn requested_offset(report: &Value, length: usize, crib: usize) -> Result<Option<usize>> {
    let at: Option<usize> = serde_json::from_value(report["requested_offset"].clone())?;
    ensure!(
        at.is_none_or(|offset| crate::proof_work::placement_selected(length, crib, offset, at)),
        "placement lies outside the ciphertext"
    );
    Ok(at)
}

#[cfg(any(feature = "gpu", test))]
fn search_fits(seconds: &[f64], elapsed: f64, maximum: f64) -> bool {
    seconds.iter().all(|s| s.is_finite() && *s >= 0.0)
        && elapsed.is_finite()
        && maximum.is_finite()
        && elapsed >= 0.0
        && maximum > elapsed
        && seconds.iter().sum::<f64>() <= maximum - elapsed
}

pub fn run(args: &[String]) -> Result<()> {
    ensure!(
        std::env::var_os("CB_CLOUD_RUN").is_some(),
        "run the measured campaign through cargo xtask cloud run gpu --standard -- cargo xtask p1030680 campaign"
    );
    let mut candidate = "C06".to_owned();
    let mut minutes = 90_u64;
    let mut control_only = false;
    let mut reuse_recovery = false;
    let mut at = None;
    let mut args_iter = args.iter().cloned();
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "--candidate" => candidate = option(&mut args_iter, &arg)?,
            "--max-minutes" => minutes = option(&mut args_iter, &arg)?.parse()?,
            "--control-only" => control_only = true,
            "--reuse-recovery" => reuse_recovery = true,
            "--at" => {
                ensure!(at.is_none(), "placement must be specified only once");
                at = Some(option(&mut args_iter, &arg)?.parse::<usize>()?);
            }
            _ => anyhow::bail!("unknown campaign option {arg}"),
        }
    }
    ensure!(
        (1..=100).contains(&minutes),
        "campaign limit must be 1-100 minutes"
    );
    #[cfg(feature = "gpu")]
    return worker(&candidate, minutes, control_only, reuse_recovery, at);
    #[cfg(not(feature = "gpu"))]
    {
        let start = Instant::now();
        let limit = Duration::from_mins(minutes);
        let build = Cmd::new([
            "cargo",
            "build",
            "--locked",
            "--release",
            "--package",
            "xtask",
            "--features",
            "gpu",
        ]);
        build.live(limit)?.require_success(&build)?;
        let left = remaining(start, limit)?;
        let worker_minutes = left.as_secs() / 60;
        ensure!(
            worker_minutes > 0,
            "no campaign time remains after compilation"
        );
        let mut command = Cmd::new([
            "./target/release/xtask",
            "p1030680",
            "campaign",
            "--candidate",
            &candidate,
            "--max-minutes",
            &worker_minutes.to_string(),
        ]);
        if let Some(offset) = at {
            command.argv.extend(["--at".into(), offset.to_string()]);
        }
        if control_only {
            command.argv.push("--control-only".into());
        }
        if reuse_recovery {
            command.argv.push("--reuse-recovery".into());
        }
        command.live(left)?.require_success(&command)
    }
}

fn remaining(start: Instant, limit: Duration) -> Result<Duration> {
    limit
        .checked_sub(start.elapsed())
        .context("campaign reached its time limit")
}

#[cfg(feature = "gpu")]
fn profile(
    gpu: &cipher_break::gpu::Gpu,
    model: &cipher_break::ngram::Model,
    ciphertext: &[u8],
    word: &str,
    placement: Placement,
) -> Result<Value> {
    use cipher_break::alphabet::to_letters;
    use cipher_break::bombe::Menu;
    use cipher_break::ciphers::enigma;
    use cipher_break::gpu::BombeJob;

    let ct = to_letters(std::str::from_utf8(ciphertext)?);
    let crib = to_letters(word);
    ensure!(
        crib.len() <= cipher_break::gpu::BOMBE_MAX_CRIB,
        "crib exceeds GPU capacity"
    );
    let menu = Menu::place(&ct, &crib, placement.offset).context("refuted profile placement")?;
    let packed = vec![(
        placement.offset,
        crib.iter()
            .zip(&ct[placement.offset..])
            .map(|(&a, &b)| (a, b))
            .collect(),
        menu.hub(),
    )];
    let reflectors: Vec<_> = enigma::naval_reflectors()
        .into_iter()
        .map(|(_, wiring)| wiring)
        .collect();
    let orders = [[0, 1, 2], [3, 2, 7], [5, 6, 0], [7, 5, 6]];
    let job = BombeJob {
        ct: &ct,
        logp: model.log_table(),
        order: model.order(),
        orders: &orders[..1],
        reflectors: &reflectors[..1],
        menus: &packed,
        rings: 1,
        middles: 1,
        keep: 64,
    };
    let _ = gpu.sweep_bombe(&job);
    let mut measurements = Vec::new();
    for order in orders {
        let job = BombeJob {
            orders: std::slice::from_ref(&order),
            reflectors: &reflectors,
            rings: 26,
            middles: 26,
            ..job
        };
        let start = Instant::now();
        let found = gpu.sweep_bombe(&job);
        measurements.push(json!({"rotors": order, "seconds": start.elapsed().as_secs_f64(), "stops": found.stops, "kept": found.best.len()}));
    }
    let slowest = measurements
        .iter()
        .filter_map(|m| m["seconds"].as_f64())
        .fold(0.0_f64, f64::max);
    Ok(json!({
        "device": gpu.name, "placement": placement, "sample_orders": measurements,
        "reflectors": reflectors.len(), "middle_rings": 26, "right_rings": 26,
        "full_rotor_orders": 336, "raw_full_settings": 336_u64 * 104 * 26_u64.pow(5),
        "forecast_seconds": slowest * 336.0 * 1.25 + 150.0,
        "forecast_method": "slowest of four notch-pattern orders times 336, plus 25 percent and 150 seconds for planning/finishing; an estimate, not a hard bound"
    }))
}

#[cfg(feature = "gpu")]
fn worker(
    candidate_id: &str,
    minutes: u64,
    control_only: bool,
    reuse_recovery: bool,
    at: Option<usize>,
) -> Result<()> {
    let start = Instant::now();
    let path = crate::root().join(REPORT);
    let mut report = json!({
        "status": "validating", "candidate": candidate_id, "maximum_minutes": minutes,
        "provenance_sha256": crate::audit::provenance()?, "seed": 1, "shuffle_seed": 20_261_002,
        "controls": 1, "reading_declared": false, "searches": [], "queues": {},
        "control_only": control_only, "reuse_recovery": reuse_recovery,
        "requested_offset": at,
        "selection": "apply any explicit placement identically to target and control, then order compatible menus by descending closures and ascending offset; search the first menu in this bounded run",
        "scope": "single-layer M4; all 336 moving-wheel orders, 104 composite reflectors and all middle/right ring representatives; capped finishing"
    });
    json_write(&path, &report)?;
    let result = measured_search(candidate_id, minutes, start, &mut report);
    report["seconds"] = json!(start.elapsed().as_secs_f64());
    if let Err(error) = &result {
        report["status"] = json!("failed_or_interrupted");
        report["error"] = json!(format!("{error:#}"));
    }
    json_write(&path, &report)?;
    result
}

#[cfg(feature = "gpu")]
fn validate_recovery(start: Instant, limit: Duration, report: &mut Value) -> Result<()> {
    let root = crate::root();
    let path = root.join("reports/p1030680/recovery-result.json");
    let recovery = if report["reuse_recovery"] == true {
        json_read(&root.join("data/p1030680/recovery-result.json"))?
    } else {
        crate::jobs::recovery(&[
            "--max-minutes".to_owned(),
            (remaining(start, limit)?.as_secs() / 60)
                .min(55)
                .to_string(),
        ])?;
        json_read(&path)?
    };
    ensure!(
        crate::audit::recovery_status(&recovery, &crate::audit::provenance()?) == "passed",
        "current full recovery gate did not pass"
    );
    ensure!(
        recovery["full_check_in_this_run"] == true,
        "full validation was not executed"
    );
    json_write(&path, &recovery)?;
    report["recovery_result"] = recovery;
    json_write(&root.join(REPORT), report)
}

#[cfg(feature = "gpu")]
fn measured_search(
    candidate_id: &str,
    minutes: u64,
    start: Instant,
    report: &mut Value,
) -> Result<()> {
    use crate::audit;
    use cipher_break::gpu::Gpu;
    use cipher_break::rng::Rng;
    use std::fs;

    let root = crate::root();
    let limit = Duration::from_mins(minutes);
    let path = root.join(REPORT);
    audit::sources(&[])?;
    validate_recovery(start, limit, report)?;
    audit::model(&[])?;
    audit::run(&[
        "--recovery-result".to_owned(),
        "reports/p1030680/recovery-result.json".to_owned(),
    ])?;
    let audited = json_read(&root.join("reports/p1030680/candidate-audit.json"))?;
    let candidate = audited["candidates"]
        .as_array()
        .context("candidate array")?
        .iter()
        .find(|c| c["id"] == candidate_id)
        .context("unknown campaign candidate")?;
    ensure!(
        audit::measurement_candidate(candidate),
        "candidate has no explicit conditional search rationale"
    );
    let crib = candidate["cribs"]
        .as_array()
        .context("crib array")?
        .first()
        .context("missing crib")?;
    let word = crib["word"].as_str().context("crib word")?;
    let ciphertext: Vec<u8> = fs::read(root.join("data/ciphertext.txt"))?
        .into_iter()
        .filter(u8::is_ascii_uppercase)
        .collect();
    let mut rng = Rng::new(20_261_002);
    let control = rng.shuffled(&ciphertext);
    let inputs = [ciphertext, control];
    let at = requested_offset(report, inputs[0].len(), word.len())?;
    let model = audit::training_model()?;
    let gpu = Gpu::open().map_err(anyhow::Error::msg)?;
    report["word"] = json!(word);
    report["source_sha256"] = crib["source_sha256"].clone();
    report["model_sha256"] = json!(crate::process::sha(
        &root.join("reports/p1030680/naval-quadgrams.txt")
    )?);
    report["input_sha256"] = audited["input_sha256"].clone();
    let mut profiles = Vec::new();
    let mut forecasts = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        let menus = queue(input, word.as_bytes(), &crib["offsets"], at);
        report["queues"][index.to_string()] = json!(menus);
        if let Some(placement) = menus.first() {
            let measured = profile(&gpu, &model, input, word, *placement)?;
            forecasts.push(
                measured["forecast_seconds"]
                    .as_f64()
                    .context("runtime estimate")?,
            );
            profiles.push(measured);
        } else {
            forecasts.push(0.0);
            profiles.push(json!({"forecast_seconds": 0.0, "reason": "all placements refuted by self-encipherment or have no loop"}));
        }
        report["profiles"] = json!(profiles);
        json_write(&path, report)?;
        remaining(start, limit)?;
    }
    report["forecast_search_seconds"] = json!(forecasts.iter().sum::<f64>());
    report["elapsed_before_search"] = json!(start.elapsed().as_secs_f64());
    let only_control = report["control_only"] == true;
    let paired_fits = search_fits(
        &forecasts,
        start.elapsed().as_secs_f64(),
        limit.as_secs_f64(),
    );
    let selected = usize::from(only_control);
    if !paired_fits
        && !search_fits(
            &[forecasts[selected]],
            start.elapsed().as_secs_f64(),
            limit.as_secs_f64(),
        )
    {
        report["status"] = json!("deferred_runtime");
        json_write(&path, report)?;
        println!("forecast exceeds the remaining VM window; no full target sweep started");
        return Ok(());
    }
    report["planned_searches"] = json!(if only_control {
        vec![1]
    } else if paired_fits {
        vec![0, 1]
    } else {
        vec![0]
    });
    sweep_queue(&inputs, word, &crib["offsets"], start, limit, report)
}

#[cfg(feature = "gpu")]
fn sweep_queue(
    inputs: &[Vec<u8>],
    word: &str,
    offsets: &Value,
    start: Instant,
    limit: Duration,
    report: &mut Value,
) -> Result<()> {
    use cipher_break::alphabet::from_letters;
    use std::fs;

    let root = crate::root();
    let path = root.join(REPORT);
    let build = Cmd::new([
        "cargo",
        "build",
        "--locked",
        "--release",
        "--features",
        "gpu",
        "--bin",
        "cb",
    ]);
    build
        .live(remaining(start, limit)?)?
        .require_success(&build)?;
    report["status"] = json!("searching");
    json_write(&path, report)?;
    for (index, input) in inputs.iter().enumerate() {
        if !report["planned_searches"]
            .as_array()
            .context("planned searches")?
            .contains(&json!(index))
        {
            continue;
        }
        let at = requested_offset(report, input.len(), word.len())?;
        let menus = queue(input, word.as_bytes(), offsets, at);
        let Some(placement) = menus.first() else {
            continue;
        };
        let input_path = root.join(format!("reports/p1030680/campaign-input-{index}.txt"));
        fs::write(
            &input_path,
            from_letters(&input.iter().map(|b| b - b'A').collect::<Vec<_>>()),
        )?;
        let command = Cmd::new([
            "./target/release/cb",
            "bombe",
            &input_path.to_string_lossy(),
            "--word",
            word,
            "--at",
            &placement.offset.to_string(),
            "--rings",
            "--gpu",
            "--seed",
            "1",
            "--nulls",
            "0",
            "--finish",
            "64",
            "--top",
            "5",
            "--focus",
            "reports/p1030680/naval-quadgrams.txt",
            "--trace",
            "--plain",
        ]);
        let outcome = command.live(remaining(start, limit)?)?;
        let passed = outcome.exit_code == 0 && !outcome.timed_out;
        report["searches"]
            .as_array_mut()
            .context("search records")?
            .push(json!({
                "kind": if index == 0 { "target" } else { "same-letter control" },
                "placement": placement, "command": command, "result": outcome
            }));
        report["status"] = json!(if passed {
            "searching"
        } else {
            "failed_or_interrupted"
        });
        json_write(&path, report)?;
        ensure!(
            passed,
            "campaign search failed or reached its time limit; retained completed scopes are not whole-key exclusions"
        );
    }
    report["status"] = json!(if report["planned_searches"] == json!([0]) {
        "awaiting_control"
    } else {
        "searched"
    });
    report["interpretation"] = json!(
        "The listed queued placements were searched with capped finishing. Unvisited placements remain open. A target-only run requires its recorded matched control in a later bounded run; further controls and independent key/plaintext verification are required before declaring a reading."
    );
    json_write(&path, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_menus_keeps_every_compatible_looped_placement() {
        let cipher = b"ABCDABCDABCD";
        let word = b"BCDB";
        let mut expected = placements(cipher, word, &json!("all"));
        expected.retain(|p| p.closures > 0);
        let ordered = queue(cipher, word, &json!("all"), None);
        assert!(!ordered.is_empty());
        assert_eq!(ordered.len(), expected.len());
        assert!(expected.iter().all(|p| ordered.contains(p)));
        assert!(
            ordered
                .windows(2)
                .all(|pair| pair[0].closures >= pair[1].closures)
        );
        assert!(queue(cipher, b"ABCD", &json!([0]), None).is_empty());
    }

    #[test]
    fn explicit_placement_never_falls_back_to_a_different_menu() {
        let cipher = b"ABCDABCDABCD";
        let word = b"BCDB";
        let all = queue(cipher, word, &json!("all"), None);
        let selected = all[all.len() - 1];
        assert_eq!(
            queue(cipher, word, &json!("all"), Some(selected.offset)),
            vec![selected]
        );
        assert!(queue(cipher, word, &json!("all"), Some(cipher.len())).is_empty());
        assert!(queue(cipher, b"ABCD", &json!("all"), Some(0)).is_empty());
        assert!(queue(cipher, word, &json!([0]), Some(4)).is_empty());
        assert!(queue(cipher, word, &json!("all"), Some(usize::MAX)).is_empty());
    }

    #[test]
    fn explicit_placement_validates_the_numeric_boundary() {
        assert_eq!(
            requested_offset(&json!({"requested_offset": null}), 72, 30).unwrap(),
            None
        );
        assert_eq!(
            requested_offset(&json!({"requested_offset": 42}), 72, 30).unwrap(),
            Some(42)
        );
        for invalid in [json!(43), json!(usize::MAX), json!(-1), json!("42")] {
            assert!(requested_offset(&json!({"requested_offset": invalid}), 72, 30).is_err());
        }
        assert!(requested_offset(&json!({"requested_offset": 0}), 29, 30).is_err());
    }

    #[test]
    fn each_planned_search_must_fit_its_remaining_window() {
        assert!(search_fits(&[20.0, 30.0], 10.0, 60.0));
        assert!(!search_fits(&[20.0, 30.0], 11.0, 60.0));
        assert!(!search_fits(&[f64::NAN], 0.0, 60.0));
        assert!(!search_fits(&[f64::INFINITY], 0.0, 60.0));
        assert!(!search_fits(&[-1.0], 0.0, 60.0));
        assert!(!search_fits(&[0.0], 60.0, 60.0));
    }
}
