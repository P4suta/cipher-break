// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::process::{Cmd, Outcome, json_read, json_write, now, option, sha};
use crate::proof_gate::{
    AssessmentEvidence, Boundary, Check, Completion, Intent, Substitute, accepts, assessed,
};
use crate::proof_work::{Obligation, Selection, Workload, admitted, completed, needs_run, planned};
use crate::search_scope::{self, Scope};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const KANI_VERSION: &str = "0.68.0";
const LEAN_VERSION: &str = "4.34.1";
const BOOTSTRAP: [&str; 9] = [
    "artifact-staging",
    "proof-plan",
    "cloud-proof-command",
    "cloud-proof-work",
    "campaign-placement",
    "lease",
    "proof-gate",
    "negative-gate",
    "search-scope",
];

struct Case {
    name: &'static str,
    scope: Scope,
    source: &'static str,
    harness: &'static str,
    covers: usize,
    assertions: usize,
}

impl Case {
    fn required(&self) -> bool {
        self.name != "propagation"
    }

    fn obligation(&self) -> Obligation {
        match self.name {
            "queue-contract" => Obligation::Queue,
            "settle-partitions" => Obligation::Partition,
            "propagation" => Obligation::Propagation,
            name if name.starts_with("settle-") => Obligation::Reciprocal,
            _ => Obligation::Independent,
        }
    }

    fn harness_source(&self) -> &str {
        match self.name {
            "queue-contract" => "proofs/queue-contract.rs",
            name if name.starts_with("settle-") => "proofs/settle-contract.rs",
            _ => self.source,
        }
    }

    fn contract(&self) -> Option<&str> {
        match self.name {
            "queue-contract" => Some("Scratch::queue"),
            _ => None,
        }
    }

    fn uses_z3(&self) -> bool {
        matches!(self.name, "propagation" | "false-claim-z3")
    }
}

const CASES: &[Case] = &[
    Case {
        name: "artifact-staging",
        scope: Scope::LocalLemma,
        source: "proofs/artifacts.rs",
        harness: "all_artifacts_are_staged_before_any_read_and_failures_stop_transfer",
        covers: 3,
        assertions: 3,
    },
    Case {
        name: "proof-plan",
        scope: Scope::LocalLemma,
        source: "proofs/work.rs",
        harness: "requested_proofs_include_their_contract_prerequisites",
        covers: 3,
        assertions: 7,
    },
    Case {
        name: "cloud-proof-command",
        scope: Scope::LocalLemma,
        source: "proofs/work.rs",
        harness: "verification_commands_require_every_fixed_argument_and_a_registered_case",
        covers: 5,
        assertions: 14,
    },
    Case {
        name: "campaign-placement",
        scope: Scope::LocalLemma,
        source: "proofs/work.rs",
        harness: "explicit_placements_preserve_valid_offsets_without_overflow_or_fallback",
        covers: 4,
        assertions: 4,
    },
    Case {
        name: "cloud-proof-work",
        scope: Scope::LocalLemma,
        source: "proofs/work.rs",
        harness: "verification_bootstrap_cannot_authorize_an_unproved_ciphertext_search",
        covers: 6,
        assertions: 8,
    },
    Case {
        name: "search-scope",
        scope: Scope::LocalLemma,
        source: "proofs/search-scope.rs",
        harness: "local_lemmas_cannot_replace_a_required_search_contract",
        covers: 2,
        assertions: 3,
    },
    Case {
        name: "lease",
        scope: Scope::LocalLemma,
        source: "proofs/lease.rs",
        harness: "ownership_releases_exactly_once_and_failed_acquisition_never_releases",
        covers: 4,
        assertions: 11,
    },
    Case {
        name: "cli-agreement",
        scope: Scope::LocalLemma,
        source: "proofs/gate.rs",
        harness: "both_implementations_must_report_the_known_fixture_ic",
        covers: 2,
        assertions: 3,
    },
    Case {
        name: "scratch-reset",
        scope: Scope::LocalLemma,
        source: "proofs/scratch.rs",
        harness: "bombe::a_new_scratch_run_forgets_every_mapping_and_preserves_stored_values",
        covers: 2,
        assertions: 4,
    },
    Case {
        name: "queue-contract",
        scope: Scope::LocalLemma,
        source: "proofs/queue.rs",
        harness: "bombe::queue_checks_existing_partners_and_frames_every_new_assignment",
        covers: 3,
        assertions: 3,
    },
    Case {
        name: "settle-partitions",
        scope: Scope::LocalLemma,
        source: "proofs/settle.rs",
        harness: "bombe::reciprocal_cases_partition_every_pair_of_assignment_states",
        covers: 2,
        assertions: 2,
    },
    Case {
        name: "settle-same",
        scope: Scope::LocalLemma,
        source: "proofs/settle.rs",
        harness: "bombe::reciprocal_assignments_of_the_same_letter",
        covers: 2,
        assertions: 6,
    },
    Case {
        name: "settle-both-new",
        scope: Scope::LocalLemma,
        source: "proofs/settle.rs",
        harness: "bombe::reciprocal_assignments_of_two_new_letters",
        covers: 2,
        assertions: 6,
    },
    Case {
        name: "settle-first-new",
        scope: Scope::LocalLemma,
        source: "proofs/settle.rs",
        harness: "bombe::reciprocal_assignments_with_only_the_first_letter_new",
        covers: 2,
        assertions: 6,
    },
    Case {
        name: "settle-second-new",
        scope: Scope::LocalLemma,
        source: "proofs/settle.rs",
        harness: "bombe::reciprocal_assignments_with_only_the_second_letter_new",
        covers: 2,
        assertions: 6,
    },
    Case {
        name: "settle-both-known",
        scope: Scope::LocalLemma,
        source: "proofs/settle.rs",
        harness: "bombe::reciprocal_assignments_of_two_known_letters",
        covers: 2,
        assertions: 6,
    },
    Case {
        name: "propagation",
        scope: Scope::LocalLemma,
        source: "proofs/propagation.rs",
        harness: "bombe::a_consistent_plugboard_guess_is_never_refuted_by_propagation",
        covers: 2,
        assertions: 2,
    },
    Case {
        name: "plugboard",
        scope: Scope::LocalLemma,
        source: "proofs/plugboard.rs",
        harness: "machine::connecting_leads_preserves_every_valid_plugboard_involution",
        covers: 2,
        assertions: 5,
    },
    Case {
        name: "placement-bounds",
        scope: Scope::LocalLemma,
        source: "proofs/menu.rs",
        harness: "bombe::placement_bounds_match_checked_addition_for_every_machine_integer",
        covers: 3,
        assertions: 1,
    },
    Case {
        name: "coordinates",
        scope: Scope::LocalLemma,
        source: "proofs/coordinates.rs",
        harness: "ring_coordinate_round_trips",
        covers: 3,
        assertions: 4,
    },
    Case {
        name: "clock",
        scope: Scope::LocalLemma,
        source: "proofs/stepping.rs",
        harness: "machine::one_press_obeys_the_notches_before_stepping",
        covers: 3,
        assertions: 3,
    },
    Case {
        name: "double-step",
        scope: Scope::LocalLemma,
        source: "proofs/stepping.rs",
        harness: "machine::a_notch_reached_by_the_right_carry_causes_a_double_step",
        covers: 2,
        assertions: 2,
    },
    Case {
        name: "left-ring",
        scope: Scope::LocalLemma,
        source: "proofs/stepping.rs",
        harness: "machine::normalizing_the_left_ring_preserves_offsets_and_one_step",
        covers: 1,
        assertions: 4,
    },
    Case {
        name: "rotor-inverse",
        scope: Scope::LocalLemma,
        source: "proofs/wiring.rs",
        harness: "machine::every_published_rotor_inverts_at_every_offset",
        covers: 1,
        assertions: 1,
    },
    Case {
        name: "reflector",
        scope: Scope::LocalLemma,
        source: "proofs/wiring.rs",
        harness: "machine::every_naval_reflector_is_an_involution_without_a_fixed_point",
        covers: 1,
        assertions: 2,
    },
    Case {
        name: "crib-offset",
        scope: Scope::LocalLemma,
        source: "proofs/menu.rs",
        harness: "bombe::an_out_of_range_crib_offset_is_rejected_without_overflow",
        covers: 2,
        assertions: 1,
    },
    Case {
        name: "self-encryption",
        scope: Scope::LocalLemma,
        source: "proofs/menu.rs",
        harness: "bombe::a_single_letter_crib_is_refuted_exactly_when_it_enciphers_itself",
        covers: 2,
        assertions: 3,
    },
    Case {
        name: "proof-gate",
        scope: Scope::LocalLemma,
        source: "proofs/gate.rs",
        harness: "an_accepted_proof_excludes_missing_failed_and_vacuous_evidence",
        covers: 4,
        assertions: 18,
    },
    Case {
        name: "negative-gate",
        scope: Scope::LocalLemma,
        source: "proofs/gate.rs",
        harness: "a_negative_control_requires_one_actual_expected_refutation",
        covers: 2,
        assertions: 9,
    },
    Case {
        name: "false-claim",
        scope: Scope::LocalLemma,
        source: "proofs/coordinate-counterexample.rs",
        harness: "an_incorrect_round_trip_is_refuted",
        covers: 0,
        assertions: 1,
    },
    Case {
        name: "false-claim-z3",
        scope: Scope::LocalLemma,
        source: "proofs/coordinate-counterexample.rs",
        harness: "an_incorrect_round_trip_is_refuted",
        covers: 0,
        assertions: 1,
    },
];

const _: () = assert!(CASES.len() <= search_scope::MAX_CASES);

fn sources(case: &Case) -> Result<BTreeMap<String, String>> {
    let mut paths = vec![case.source, "xtask/src/proof_gate.rs"];
    if matches!(
        case.source,
        "proofs/queue.rs" | "proofs/settle.rs" | "proofs/propagation.rs"
    ) {
        paths.push("proofs/queue-contract.rs");
    }
    if matches!(case.source, "proofs/settle.rs" | "proofs/propagation.rs") {
        paths.push("proofs/settle-contract.rs");
    }
    if case.source == "proofs/work.rs" {
        paths.extend([
            "xtask/src/proof_work.rs",
            "xtask/src/cloud.rs",
            "xtask/src/campaign.rs",
            "xtask/src/jobs.rs",
            "xtask/src/bootstrap.rs",
            ".cargo/config.toml",
            "mise.toml",
        ]);
    } else if case.source == "proofs/artifacts.rs" {
        paths.extend([
            "xtask/src/artifacts.rs",
            "xtask/src/runner.rs",
            "xtask/src/cloud.rs",
        ]);
    } else if case.source == "proofs/search-scope.rs" {
        paths.push("xtask/src/search_scope.rs");
    } else if case.source == "proofs/lease.rs" {
        paths.push("xtask/src/lease.rs");
    } else if case.source == "proofs/gate.rs" {
        paths.push("xtask/src/agreement.rs");
    } else {
        paths.extend(["src/alphabet.rs", "src/enigma_types.rs"]);
        if !matches!(
            case.source,
            "proofs/coordinates.rs" | "proofs/coordinate-counterexample.rs"
        ) {
            paths.push("src/ciphers/enigma.rs");
        }
        if matches!(
            case.source,
            "proofs/menu.rs"
                | "proofs/propagation.rs"
                | "proofs/scratch.rs"
                | "proofs/queue.rs"
                | "proofs/settle.rs"
        ) {
            paths.push("src/bombe.rs");
        }
    }
    hashes(paths)
}

fn hashes<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<BTreeMap<String, String>> {
    paths
        .into_iter()
        .map(|path| Ok((path.into(), sha(&crate::root().join(path))?)))
        .collect()
}

fn number(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .with_context(|| format!("missing proof count {field}"))
}

fn validate_verifier(case: &Case, report: &Value) -> Result<()> {
    if case.uses_z3() {
        ensure!(
            report["tools"]["solvers"]
                == json!([{"name":"z3", "version":"Z3 version 5.1.0 - 64 bit"}]),
            "unexpected SMT solver version"
        );
    }
    ensure!(
        report["metadata"]["version"] == "1.0"
            && report["metadata"]["kani_version"] == KANI_VERSION
            && report["metadata"]["build_mode"] == "release"
            && report["metadata"]["target"]
                .as_str()
                .is_some_and(|target| matches!(
                    target,
                    "aarch64-apple-darwin"
                        | "x86_64-apple-darwin"
                        | "aarch64-unknown-linux-gnu"
                        | "x86_64-unknown-linux-gnu"
                )),
        "unsupported proof schema, target or build semantics"
    );
    ensure!(
        report["tools"]["kani"] == KANI_VERSION,
        "unexpected Kani version"
    );
    ensure!(
        report["tools"]["cbmc"] == "6.11.0 (cbmc-6.11.0)",
        "unexpected CBMC version"
    );
    ensure!(
        report["tools"]["rustc"] == "rustc 1.100.0-nightly (8925ea358 2026-08-20)",
        "unexpected verifier compiler"
    );
    Ok(())
}

fn validate_harness(case: &Case, report: &Value) -> Result<()> {
    let metadata = report["harness_metadata"]
        .as_array()
        .context("missing harness metadata")?;
    ensure!(
        metadata.len() == 1 && metadata[0]["pretty_name"] == case.harness,
        "missing or unexpected proof harness"
    );
    let kind = case.contract().map_or_else(
        || "Proof".to_string(),
        |target| format!("ProofForContract {{ target_fn: \"{target}\" }}"),
    );
    ensure!(
        metadata[0]["attributes"]["kind"] == kind
            && metadata[0]["attributes"]["should_panic"] == false,
        "proof harness attributes changed"
    );
    if case.contract().is_some() {
        ensure!(
            metadata[0]["contract"]["contracted_function_name"]
                .as_str()
                .is_some_and(|name| !name.is_empty())
                && metadata[0]["contract"]["recursion_tracker"].is_null(),
            "missing or unexpected function contract instrumentation"
        );
    }
    ensure!(
        metadata[0]["source"]["file"] == case.harness_source(),
        "proof harness source differs"
    );
    Ok(())
}

fn validate_kani(case: &Case, report: &Value, result: &Outcome) -> Result<usize> {
    validate_verifier(case, report)?;
    validate_harness(case, report)?;
    let results = report["verification_results"]["results"]
        .as_array()
        .context("missing proof results")?;
    ensure!(
        results.len() == 1 && results[0]["harness_id"] == case.harness,
        "proof did not execute the exact harness"
    );
    let summary = &report["verification_results"]["summary"];
    let intent = if case.source == "proofs/coordinate-counterexample.rs" {
        Intent::Refute
    } else {
        Intent::Prove
    };
    let completion = Completion {
        total: number(summary, "total_harnesses")?,
        executed: number(summary, "executed")?,
        successful: number(summary, "successful")?,
        failed: number(summary, "failed")?,
        completed: summary["status"] == "completed",
        exit_code: result.exit_code,
        timed_out: result.timed_out,
    };
    let expected_failure =
        "assertion failed: indicator.against(ring).with_ring(ring) == indicator.step()";
    let checks = results[0]["checks"]
        .as_array()
        .context("missing proof checks")?;
    let mut assertions = 0;
    let mut covers = 0;
    let contract_prefix = case
        .contract()
        .map(|target| format!("bombe::{target}::{{closure#"));
    let classified: Vec<_> = checks
        .iter()
        .map(|check| {
            let is_assertion = (check["location"]["file"] == case.harness_source()
                && check["description"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("assertion failed:")))
                || contract_prefix.as_ref().is_some_and(|prefix| {
                    check["category"] == "assertion"
                        && check["location"]["file"] == "proofs/../src/bombe.rs"
                        && check["function"]
                            .as_str()
                            .is_some_and(|function| function.starts_with(prefix))
                        && check["description"]
                            .as_str()
                            .is_some_and(|description| description.starts_with("|result: &bool|"))
                });
            if is_assertion {
                assertions += 1;
            }
            match check["status"].as_str() {
                Some("Success") if is_assertion => Check::AssertionPassed,
                Some("Success") => Check::Passed,
                Some("Satisfied") if check["category"] == "cover" => {
                    covers += 1;
                    Check::CoverSatisfied
                }
                Some("Unreachable") if !is_assertion && check["category"] != "cover" => {
                    Check::UnreachableSafety
                }
                Some("Failure")
                    if intent == Intent::Refute
                        && is_assertion
                        && check["description"] == expected_failure =>
                {
                    Check::ExpectedRefutation
                }
                _ => Check::Rejected,
            }
        })
        .collect();
    ensure!(
        assertions == case.assertions && covers == case.covers,
        "required assertions or reachability witnesses disappeared in {}: assertions {assertions}, covers {covers}",
        case.name
    );
    ensure!(
        accepts(intent, completion, &classified),
        "incomplete, refuted, unreachable or unexpected verification result for {}",
        case.name
    );
    ensure!(
        results[0]["status"]
            == if intent == Intent::Prove {
                "Success"
            } else {
                "Failure"
            },
        "inconsistent proof status"
    );
    Ok(checks.len())
}

fn receipt_path(name: &str) -> PathBuf {
    crate::root()
        .join("reports/proofs")
        .join(format!("{name}-receipt.json"))
}

fn model_root() -> PathBuf {
    crate::root().join("reports/proofs/models")
}

fn reserve_models(case: &Case) -> Result<PathBuf> {
    let root = model_root();
    fs::create_dir_all(&root)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    for attempt in 0..64 {
        let directory = root.join(format!(
            "{}-{}-{nonce}-{attempt}",
            case.name,
            std::process::id()
        ));
        match fs::create_dir(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("reserve fresh proof model outputs"),
        }
    }
    bail!("proof model reservation exhausted its collision bound")
}

fn checked_model_directory(case: &Case, receipt: &Value) -> Result<PathBuf> {
    let directory = PathBuf::from(
        receipt["model_directory"]
            .as_str()
            .context("proof lacks isolated model outputs; rerun it")?,
    );
    let name = directory
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid proof model directory")?;
    let suffix = name
        .strip_prefix(&format!("{}-", case.name))
        .context("model outputs belong to a different proof case")?;
    ensure!(
        directory.parent() == Some(model_root().as_path())
            && !suffix.is_empty()
            && suffix.chars().all(|c| c.is_ascii_digit() || c == '-')
            && fs::symlink_metadata(&directory)?.file_type().is_dir(),
        "model outputs must be in their reserved case directory"
    );
    Ok(directory)
}

fn model_hash(report: &Value, directory: &std::path::Path) -> Result<String> {
    let path = PathBuf::from(
        report["harness_metadata"][0]["goto_file"]
            .as_str()
            .context("verifier omitted its generated model")?,
    );
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        path.parent() == Some(directory) && metadata.is_file() && metadata.len() > 0,
        "the generated model is absent or outside this proof's isolated outputs"
    );
    sha(&path)
}

fn validate_model(case: &Case, receipt: &Value) -> Result<()> {
    let directory = checked_model_directory(case, receipt)?;
    ensure!(
        receipt["command"] == json!(kani_command(case, &directory)?)
            || receipt["command"] == json!(kani_command_with_limit(case, &directory, "300s")?),
        "proof used different verification settings"
    );
    ensure!(
        receipt["model_sha256"] == model_hash(&receipt["report"], &directory)?,
        "proof model changed after verification"
    );
    Ok(())
}

fn kani_command(case: &Case, directory: &std::path::Path) -> Result<Cmd> {
    kani_command_with_limit(case, directory, "30s")
}

fn kani_command_with_limit(
    case: &Case,
    directory: &std::path::Path,
    harness_limit: &str,
) -> Result<Cmd> {
    let report_path = crate::root()
        .join("reports/proofs")
        .join(format!("{}-raw.json", case.name));
    let mut command = Cmd::new([
        "kani",
        case.source,
        "--harness",
        case.harness,
        "--exact",
        "--jobs",
        "1",
        "--force-build",
        "--keep-temps",
        "--target-dir",
        directory.to_str().context("proof model directory")?,
        "-Z",
        "unstable-options",
        "--harness-timeout",
        harness_limit,
        "--output-format",
        "terse",
        "--export-json",
        report_path.to_str().context("proof report path")?,
    ])
    .env(
        "RUSTFLAGS",
        "--edition=2024 --check-cfg=cfg(test) -A dead_code",
    );
    if case.contract().is_none()
        && case.source != "proofs/coordinate-counterexample.rs"
        && case.name != "propagation"
        && case.name != "cloud-proof-command"
    {
        command.argv.push("--quiet".into());
    }
    if matches!(
        case.name,
        "propagation" | "scratch-reset" | "placement-bounds" | "crib-offset" | "self-encryption"
    ) {
        command.argv.extend(["-Z".into(), "loop-contracts".into()]);
    }
    if matches!(
        case.source,
        "proofs/menu.rs"
            | "proofs/propagation.rs"
            | "proofs/scratch.rs"
            | "proofs/queue.rs"
            | "proofs/settle.rs"
    ) {
        command
            .argv
            .extend(["-Z".into(), "function-contracts".into()]);
    }
    if case.name == "propagation" {
        command.argv.extend(["-Z".into(), "stubbing".into()]);
    }
    if case.uses_z3() {
        command.argv.extend(["--solver".into(), "z3".into()]);
    }
    Ok(command)
}

fn run_case(case: &Case, remaining: Duration) -> Result<()> {
    let before = sources(case)?;
    let dependencies = dependency_hashes(case)?;
    let directory = reserve_models(case)?;
    let report_path = crate::root()
        .join("reports/proofs")
        .join(format!("{}-raw.json", case.name));
    if report_path.exists() {
        fs::remove_file(&report_path)?;
    }
    let command = if hosted() {
        kani_command_with_limit(case, &directory, "300s")?
    } else {
        kani_command(case, &directory)?
    };
    json_write(
        &receipt_path(case.name),
        &json!({"status":"running", "source_sha256":before, "dependencies_sha256":dependencies, "command":command, "model_directory":directory}),
    )?;
    let result = command.live(remaining);
    let report = json_read(&report_path).context(
        "verifier produced no readable result; compilation failure is not a negative control",
    );
    let checked = match (&result, &report) {
        (Ok(result), Ok(report)) => validate_kani(case, report, result).and_then(|checks| {
            ensure!(
                before == sources(case)?,
                "proof source changed during verification"
            );
            ensure!(
                dependencies == dependency_hashes(case)?,
                "verified contract changed during verification"
            );
            Ok((checks, model_hash(report, &directory)?))
        }),
        (Err(error), _) | (_, Err(error)) => Err(anyhow::anyhow!("{error:#}")),
    };
    json_write(
        &receipt_path(case.name),
        &json!({
            "status":if checked.is_ok() { "verified" } else { "failed" },
            "finished_at":now()?, "source_sha256":before,
            "dependencies_sha256":dependencies,
            "command":command, "result":result.as_ref().ok(), "report":report.as_ref().ok(),
            "model_directory":directory,
            "model_sha256":checked.as_ref().ok().map(|(_, digest)| digest),
            "error":checked.as_ref().err().map(|error| format!("{error:#}")),
        }),
    )?;
    checked?;
    Ok(())
}

fn lean_sources() -> Result<BTreeMap<String, String>> {
    hashes([
        "proofs/lean/CipherProofs.lean",
        "proofs/lean/lean-toolchain",
        "proofs/lean/lakefile.toml",
    ])
}

fn matching_sources(saved: &Value, current: &BTreeMap<String, String>) -> Result<bool> {
    let mut saved: BTreeMap<String, String> = serde_json::from_value(saved.clone())?;
    saved.remove("xtask/src/formal.rs");
    Ok(&saved == current)
}

fn validate_lean(output: &str) -> Result<()> {
    for theorem in [
        "trace_length",
        "conjugating_a_reflector_preserves_its_involution",
        "conjugating_a_reflector_preserves_the_absence_of_fixed_points",
        "normalization_preserves_every_trace",
        "deduplication_preserves_every_key",
        "a_finishing_cap_can_discard_the_true_candidate",
    ] {
        let prefix = format!("'CipherProofs.{theorem}' ");
        let matching: Vec<_> = output
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .collect();
        ensure!(
            matching.len() == 1,
            "missing or duplicate axiom audit for {theorem}"
        );
        let suffix = matching[0]
            .strip_prefix(&prefix)
            .context("axiom audit prefix")?;
        if suffix != "does not depend on any axioms" {
            let axioms = suffix
                .strip_prefix("depends on axioms: [")
                .and_then(|s| s.strip_suffix(']'))
                .context("unrecognized axiom audit")?;
            ensure!(
                axioms
                    .split(", ")
                    .all(|a| matches!(a, "propext" | "Quot.sound" | "Classical.choice")),
                "non-foundational axiom in {theorem}: {axioms}"
            );
        }
    }
    Ok(())
}

fn run_lean(remaining: Duration) -> Result<()> {
    let started = Instant::now();
    let before = lean_sources()?;
    let mut version = Cmd::new(["lean", "--version"]);
    version.cwd = crate::root().join("proofs/lean");
    let version_result = version.live(remaining.min(Duration::from_secs(10)))?;
    version_result.require_success(&version)?;
    let installed = version_result.stdout;
    ensure!(
        installed.contains(&format!("version {LEAN_VERSION},")),
        "wrong Lean toolchain"
    );
    let mut command = Cmd::new([
        "lake",
        "env",
        "lean",
        "-DwarningAsError=true",
        "CipherProofs.lean",
    ]);
    command.cwd = version.cwd;
    json_write(
        &receipt_path("lean"),
        &json!({"status":"running", "source_sha256":before}),
    )?;
    let result = command.live(
        remaining
            .checked_sub(started.elapsed())
            .context("Lean proof exceeded its shared time limit")?,
    )?;
    let checked = result
        .require_success(&command)
        .and_then(|()| validate_lean(&result.stdout));
    ensure!(
        before == lean_sources()?,
        "Lean proof source changed during verification"
    );
    json_write(
        &receipt_path("lean"),
        &json!({"status":if checked.is_ok() {"verified"} else {"failed"}, "finished_at":now()?, "source_sha256":before, "version":installed, "command":command,"result":result}),
    )?;
    checked
}

fn dependency_hashes(case: &Case) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    let required: &[&str] = match case.name {
        "propagation" => &[
            "settle-partitions",
            "settle-same",
            "settle-both-new",
            "settle-first-new",
            "settle-second-new",
            "settle-both-known",
        ],
        name if name.starts_with("settle-") && name != "settle-partitions" => &["queue-contract"],
        _ => &[],
    };
    for &name in required {
        let dependency = CASES
            .iter()
            .find(|case| case.name == name)
            .context("missing verified contract prerequisite")?;
        verify_case(dependency)?;
        hashes.insert(dependency.name.into(), sha(&receipt_path(dependency.name))?);
    }
    Ok(hashes)
}

fn verify_case(case: &Case) -> Result<()> {
    let receipt = json_read(&receipt_path(case.name))?;
    ensure!(
        assessed(
            Boundary::Native,
            AssessmentEvidence {
                current: matching_sources(&receipt["source_sha256"], &sources(case)?)?,
                core_proved: receipt["status"] == "verified",
                justified: false,
                substitute: Substitute::Missing,
            }
        ),
        "missing, failed or stale proof {}",
        case.name
    );
    let dependencies = dependency_hashes(case)?;
    if !dependencies.is_empty() {
        ensure!(
            receipt["dependencies_sha256"] == json!(dependencies),
            "missing or changed verified contract for {}",
            case.name
        );
    }
    validate_model(case, &receipt)?;
    let outcome: Outcome = serde_json::from_value(receipt["result"].clone())?;
    validate_kani(case, &receipt["report"], &outcome)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assessment {
    schema: u32,
    whole_search_proved: bool,
    exploratory_proof: String,
    exploratory_reason: String,
    exploratory_revisit: String,
    boundaries: Vec<AssessedBoundary>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssessedBoundary {
    scope: String,
    kind: String,
    sources: Vec<String>,
    required_proofs: Vec<String>,
    reason: String,
    limits: String,
    revisit: String,
}

fn assessment() -> Result<Assessment> {
    serde_json::from_value(json_read(&crate::root().join("proofs/assurance.json"))?)
        .context("invalid required assurance assessment")
}

fn boundary_kind(kind: &str) -> Result<Boundary> {
    match kind {
        "external" => Ok(Boundary::External),
        "empirical" => Ok(Boundary::Empirical),
        "unsupported-model" => Ok(Boundary::UnsupportedModel),
        _ => bail!("unjustified boundary classification {kind}"),
    }
}

fn validate_assessment(assessment: &Assessment) -> Result<()> {
    ensure!(
        assessment.schema == 1
            && !assessment.whole_search_proved
            && assessment.exploratory_proof == "propagation"
            && !assessment.exploratory_reason.trim().is_empty()
            && !assessment.exploratory_revisit.trim().is_empty(),
        "missing assessment or unsupported whole-search proof claim"
    );
    let required: Vec<_> = search_scope::REQUIRED
        .iter()
        .map(|scope| format!("{scope:?}"))
        .collect();
    let mut scopes = std::collections::BTreeSet::new();
    for boundary in &assessment.boundaries {
        ensure!(
            required.contains(&boundary.scope) && scopes.insert(&boundary.scope),
            "unknown or duplicate assessed scope"
        );
        boundary_kind(&boundary.kind)?;
        ensure!(
            !boundary.reason.trim().is_empty()
                && !boundary.limits.trim().is_empty()
                && !boundary.revisit.trim().is_empty()
                && !boundary.sources.is_empty()
                && !boundary.required_proofs.is_empty(),
            "boundary {} needs a reason, limits, follow-up, sources and core proofs",
            boundary.scope
        );
        for path in &boundary.sources {
            ensure!(
                (path.starts_with("src/") || path.starts_with("xtask/src/"))
                    && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
                    && crate::root().join(path).is_file(),
                "invalid production source in assurance assessment"
            );
        }
        for name in &boundary.required_proofs {
            ensure!(
                CASES
                    .iter()
                    .any(|case| case.name == name && case.required()),
                "boundary cannot rely on an unknown or exploratory proof"
            );
        }
    }
    ensure!(
        scopes.len() == required.len(),
        "an assurance boundary was omitted"
    );
    Ok(())
}

fn verify_assessment(recovery: &Value) -> Result<()> {
    let assessment = assessment()?;
    validate_assessment(&assessment)?;
    let current = crate::audit::recovery_status(recovery, &crate::audit::provenance()?) == "passed";
    crate::jobs::verify_recovery_evidence(recovery)?;
    for boundary in &assessment.boundaries {
        for name in &boundary.required_proofs {
            verify_case(
                CASES
                    .iter()
                    .find(|case| case.name == name)
                    .context("missing core proof")?,
            )?;
        }
        ensure!(
            assessed(
                boundary_kind(&boundary.kind)?,
                AssessmentEvidence {
                    current,
                    core_proved: true,
                    justified: true,
                    substitute: if recovery["nulls"] == 8 {
                        Substitute::Controlled
                    } else {
                        Substitute::Passed
                    },
                }
            ),
            "stale or missing substitute evidence for {}",
            boundary.scope
        );
    }
    Ok(())
}

fn verify_proofs() -> Result<()> {
    for case in CASES.iter().filter(|case| case.required()) {
        verify_case(case)?;
    }
    let receipt = json_read(&receipt_path("lean"))?;
    ensure!(
        receipt["status"] == "verified"
            && matching_sources(&receipt["source_sha256"], &lean_sources()?)?,
        "missing or stale Lean proof"
    );
    ensure!(
        receipt["version"]
            .as_str()
            .is_some_and(|s| s.contains(&format!("version {LEAN_VERSION},"))),
        "Lean receipt has the wrong toolchain"
    );
    let outcome: Outcome = serde_json::from_value(receipt["result"].clone())?;
    ensure!(
        outcome.exit_code == 0 && !outcome.timed_out,
        "Lean did not complete"
    );
    validate_lean(&outcome.stdout)?;
    Ok(())
}

fn verify() -> Result<()> {
    verify_proofs()?;
    verify_assessment(&json_read(
        &crate::root().join("data/p1030680/recovery-result.json"),
    )?)
}

pub fn recovery_attestation(recovery: &Value) -> Result<()> {
    let _lock = lock(&crate::root().join("reports/proofs"))?;
    verify_proofs()?;
    verify_assessment(recovery)?;
    let receipts = CASES
        .iter()
        .filter(|case| case.required())
        .map(|case| Ok((case.name, sha(&receipt_path(case.name))?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    json_write(
        &crate::root().join("reports/proofs/recovery-attestation.json"),
        &json!({
            "status":"scoped_assurance_verified", "whole_search_proved":false,
            "assessment_sha256":sha(&crate::root().join("proofs/assurance.json"))?,
            "receipt_validator_sha256":sha(&crate::root().join("xtask/src/formal.rs"))?,
            "native_receipt_sha256":receipts, "lean_receipt_sha256":sha(&receipt_path("lean"))?,
            "recovery_provenance_sha256":recovery["provenance_sha256"],
            "recovery_receipt_sha256":sha(&crate::root().join("reports/p1030680/recovery-result.json"))?,
            "exploratory_obligations":["propagation"]
        }),
    )?;
    bundle()
}

fn verify_search() -> Result<()> {
    verify()?;
    for case in CASES {
        verify_case(case)?;
    }
    let scopes: Vec<_> = CASES.iter().map(|case| case.scope).collect();
    ensure!(
        scopes.len() <= search_scope::MAX_CASES,
        "proof scope registry exceeds the verified bound; extend its native proof first"
    );
    ensure!(
        search_scope::complete(&scopes),
        "required search proof contracts remain incomplete: {:?}",
        search_scope::REQUIRED
            .iter()
            .filter(|scope| !scopes.contains(scope))
            .collect::<Vec<_>>()
    );
    Ok(())
}

pub fn named_case(name: &str) -> bool {
    matches!(name, "lean" | "settle-contract" | "bootstrap" | "native")
        || CASES.iter().any(|case| case.name == name)
}

pub fn workload_attestation(workload: Workload) -> Result<Value> {
    let _lock = lock(&crate::root().join("reports/proofs"))?;
    let result = match workload {
        Workload::Search => verify_search().and_then(|()| attestation_locked()),
        Workload::Verification | Workload::Recovery | Workload::Experiment => {
            (|| -> Result<Value> {
                let mut cases = Vec::new();
                for name in BOOTSTRAP {
                    let case = CASES
                        .iter()
                        .find(|case| case.name == name)
                        .context("missing bootstrap contract")?;
                    verify_case(case)?;
                    cases.push(json!({"case":name, "receipt_sha256":sha(&receipt_path(name))?, "source_sha256":sources(case)?}));
                }
                let recovery = if workload == Workload::Experiment {
                    let report =
                        json_read(&crate::root().join("data/p1030680/recovery-result.json"))?;
                    ensure!(
                        crate::audit::recovery_status(&report, &crate::audit::provenance()?)
                            == "passed"
                            && report["full_check_in_this_run"] == true,
                        "bounded experiments require current full known-key recovery and matched recovery controls"
                    );
                    json!({"sha256":sha(&crate::root().join("data/p1030680/recovery-result.json"))?, "status":"passed"})
                } else {
                    Value::Null
                };
                Ok(
                    json!({"status":"bounded_workload_admitted", "workload":format!("{workload:?}"), "whole_search_proved":false,
                "scope":"fixed proof or known-key recovery commands, or a bounded sourced candidate experiment with current empirical recovery; remaining solver proof gaps stay explicit",
                "recovery":recovery,
                "cases":cases, "receipt_validator_sha256":sha(&crate::root().join("xtask/src/formal.rs"))?}),
                )
            })()
        }
    };
    let evidence = completed(workload, result.is_ok());
    let attestation = result?;
    ensure!(admitted(workload, evidence), "workload evidence rejected");
    Ok(attestation)
}

fn hosted() -> bool {
    std::env::var_os("CB_CLOUD_RUN").is_some()
        || std::env::var("GITHUB_ACTIONS").is_ok_and(|value| value == "true")
}

fn selection(name: Option<&str>) -> Selection {
    match name {
        None => Selection::All,
        Some("settle-contract") => Selection::Reciprocal,
        Some(name) => Selection::One(
            CASES
                .iter()
                .find(|case| case.name == name)
                .map_or(Obligation::Independent, Case::obligation),
        ),
    }
}

fn attestation_locked() -> Result<Value> {
    verify()?;
    let cases = CASES
        .iter()
        .filter(|case| case.required())
        .map(|case| {
            let receipt = json_read(&receipt_path(case.name))?;
            Ok(json!({
                "case":case.name, "harness":case.harness,
                "scope":format!("{:?}",case.scope),
                "source_sha256":receipt["source_sha256"],
                "receipt_sha256":sha(&receipt_path(case.name))?,
                "tools":receipt["report"]["tools"],
                "target":receipt["report"]["metadata"]["target"],
                "summary":receipt["report"]["verification_results"]["summary"],
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"status":"scoped_assurance_verified", "whole_search_proved":false,
        "assessment_sha256":sha(&crate::root().join("proofs/assurance.json"))?,
        "recovery_receipt_sha256":sha(&crate::root().join("data/p1030680/recovery-result.json"))?,
        "exploratory_obligations":["propagation"],
        "receipt_validator_sha256":sha(&crate::root().join("xtask/src/formal.rs"))?,
        "cases":cases, "lean_source_sha256":lean_sources()?,
        "lean_receipt_sha256":sha(&receipt_path("lean"))?}),
    )
}

fn lock(directory: &std::path::Path) -> Result<crate::lease::HeldFile> {
    fs::create_dir_all(directory)?;
    crate::lease::file(&directory.join("verification.lock"))
        .context("cannot acquire exclusive ownership of the proof output directory")
}

pub fn run(args: &[String]) -> Result<()> {
    if args == ["--list"] {
        return run_proofs(args);
    }
    let _lock = lock(&crate::root().join("reports/proofs"))?;
    let result = run_proofs(args);
    if hosted() && args != ["--verify"] {
        let bundled = bundle();
        return match (result, bundled) {
            (Err(proof), Err(bundle)) => {
                Err(proof.context(format!("proof artifact also failed: {bundle:#}")))
            }
            (Err(proof), Ok(())) => Err(proof),
            (Ok(()), bundle) => bundle,
        };
    }
    result
}

fn bundle() -> Result<()> {
    let artifact = Cmd::new([
        "tar",
        "-czf",
        "reports/proof-bundle.tar.gz",
        "reports/proofs",
    ]);
    artifact
        .live(Duration::from_secs(30))?
        .require_success(&artifact)
}

fn run_proofs(args: &[String]) -> Result<()> {
    if args == ["--list"] {
        for case in CASES {
            println!("{}: {}", case.name, case.harness);
        }
        println!("lean: abstract trace, representative coverage and capped selection");
        return Ok(());
    }
    if args == ["--verify"] {
        return verify();
    }
    if args == ["--verify-search"] {
        return verify_search();
    }
    let mut selected = None;
    let mut maximum_seconds = 60;
    let mut args = args.iter().cloned();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--case" => selected = Some(option(&mut args, &arg)?),
            "--max-seconds" => {
                maximum_seconds = option(&mut args, &arg)?
                    .parse()
                    .context("proof time limit")?;
            }
            _ => bail!("use prove [--case NAME] [--max-seconds N] | --list | --verify"),
        }
    }
    ensure!(
        (1..=3600).contains(&maximum_seconds),
        "proof time limit must be 1..3600 seconds"
    );
    ensure!(
        maximum_seconds <= 60 || hosted(),
        "proofs longer than one minute run on GCP or the hosted CI proof worker"
    );
    if let Some(name) = &selected {
        ensure!(named_case(name), "unknown proof case {name}");
    }
    fs::create_dir_all(crate::root().join("reports/proofs"))?;
    let start = Instant::now();
    let limit = Duration::from_secs(maximum_seconds);
    let remaining = || {
        limit
            .checked_sub(start.elapsed())
            .context("proof command exceeded its shared time limit")
    };
    let selection = selection(selected.as_deref());
    for case in CASES {
        let requested = selected.as_ref().map_or_else(
            || case.required(),
            |name| {
                case.name == name
                    || (name == "settle-contract" && case.name.starts_with("settle-"))
                    || (name == "bootstrap" && BOOTSTRAP.contains(&case.name))
                    || (name == "native" && case.required())
            },
        );
        if selected.is_none() && !case.required() {
            continue;
        }
        if planned(selection, case.obligation(), requested)
            && needs_run(requested, !requested && verify_case(case).is_ok())
        {
            run_case(case, remaining()?)?;
        }
    }
    if selected
        .as_ref()
        .is_none_or(|name| matches!(name.as_str(), "lean" | "native"))
    {
        run_lean(remaining()?)?;
    }
    if selected.as_deref() == Some("native") {
        verify_proofs()?;
    }
    if selected.is_none() {
        verify()?;
        json_write(
            &crate::root().join("reports/proofs/summary.json"),
            &attestation_locked()?,
        )?;
    }
    println!(
        "Verified {} within {:.2}s; mathematical models do not prove the complete search pipeline",
        selected.as_deref().unwrap_or("the declared proof suite"),
        start.elapsed().as_secs_f64()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_assurance_cannot_omit_a_contract_or_turn_a_timeout_into_a_proof() {
        let original: Value =
            serde_json::from_str(include_str!("../../proofs/assurance.json")).unwrap();
        let valid: Assessment = serde_json::from_value(original.clone()).unwrap();
        validate_assessment(&valid).unwrap();
        for mutation in [
            "omitted",
            "duplicate",
            "timeout",
            "exploratory",
            "no-reason",
            "full-claim",
        ] {
            let mut bad = original.clone();
            match mutation {
                "omitted" => {
                    bad["boundaries"].as_array_mut().unwrap().pop();
                }
                "duplicate" => bad["boundaries"][1] = bad["boundaries"][0].clone(),
                "timeout" => bad["boundaries"][0]["kind"] = json!("timeout"),
                "exploratory" => bad["boundaries"][0]["required_proofs"] = json!(["propagation"]),
                "no-reason" => bad["boundaries"][0]["reason"] = json!(" "),
                "full-claim" => bad["whole_search_proved"] = json!(true),
                _ => unreachable!(),
            }
            assert!(
                validate_assessment(&serde_json::from_value(bad).unwrap()).is_err(),
                "{mutation}"
            );
        }
        let mut unknown = original;
        unknown["skip_proofs"] = json!(true);
        assert!(serde_json::from_value::<Assessment>(unknown).is_err());
        assert!(
            CASES
                .iter()
                .filter(|case| !case.required())
                .all(|case| case.name == "propagation")
        );
    }

    #[test]
    fn isolated_contract_jobs_plan_prerequisites_in_registry_order() {
        let plan = |name: &str| {
            CASES
                .iter()
                .filter(|case| {
                    planned(
                        selection(Some(name)),
                        case.obligation(),
                        case.name == name
                            || (name == "settle-contract" && case.name.starts_with("settle-")),
                    )
                })
                .map(|case| case.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(plan("settle-same"), ["queue-contract", "settle-same"]);
        assert_eq!(
            plan("propagation"),
            [
                "queue-contract",
                "settle-partitions",
                "settle-same",
                "settle-both-new",
                "settle-first-new",
                "settle-second-new",
                "settle-both-known",
                "propagation",
            ]
        );
        assert_eq!(plan("settle-contract"), plan("propagation")[..7]);
        assert_eq!(plan("coordinates"), ["coordinates"]);
        assert!(plan("lean").is_empty());
    }

    #[test]
    fn axiom_audits_reject_missing_theorems_and_sorry() {
        assert!(validate_lean("").is_err());
        let names = [
            "trace_length",
            "conjugating_a_reflector_preserves_its_involution",
            "conjugating_a_reflector_preserves_the_absence_of_fixed_points",
            "normalization_preserves_every_trace",
            "deduplication_preserves_every_key",
            "a_finishing_cap_can_discard_the_true_candidate",
        ];
        let good = names
            .map(|name| format!("'CipherProofs.{name}' depends on axioms: [propext, Quot.sound]"))
            .join("\n");
        assert!(validate_lean(&good).is_ok());
        assert!(validate_lean(&good.replace("Quot.sound", "sorryAx")).is_err());
        assert!(validate_lean(&format!("{good}\n{good}")).is_err());
    }

    #[test]
    fn verifier_receipts_cannot_lose_harnesses_or_witnesses() {
        let case = CASES
            .iter()
            .find(|case| case.name == "coordinates")
            .unwrap();
        let report: Value =
            serde_json::from_str(include_str!("../data/proof-validator-fixture.json")).unwrap();
        let outcome = Outcome {
            exit_code: 0,
            seconds: 0.1,
            timed_out: false,
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(validate_kani(case, &report, &outcome).is_ok());
        let mut missing = report.clone();
        missing["verification_results"]["summary"]["executed"] = json!(0);
        assert!(validate_kani(case, &missing, &outcome).is_err());
        missing = report.clone();
        missing["verification_results"]["results"] = json!([]);
        assert!(validate_kani(case, &missing, &outcome).is_err());
        missing = report.clone();
        missing["verification_results"]["results"][0]["checks"][0]["status"] = json!("Unreachable");
        assert!(validate_kani(case, &missing, &outcome).is_err());
        missing = report.clone();
        missing["metadata"]["target"] = json!("i686-unknown-linux-gnu");
        assert!(validate_kani(case, &missing, &outcome).is_err());
        missing = report.clone();
        missing["tools"]["kani"] = json!("0.67.0");
        assert!(validate_kani(case, &missing, &outcome).is_err());
        let timed_out = Outcome {
            timed_out: true,
            ..outcome
        };
        assert!(validate_kani(case, &report, &timed_out).is_err());
    }

    #[test]
    fn function_contracts_require_target_instrumentation_and_reachable_postconditions() {
        let case = CASES
            .iter()
            .find(|case| case.name == "queue-contract")
            .unwrap();
        let report: Value = serde_json::from_str(include_str!(
            "../data/queue-contract-validator-fixture.json"
        ))
        .unwrap();
        let outcome = Outcome {
            exit_code: 0,
            seconds: 0.1,
            timed_out: false,
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(validate_kani(case, &report, &outcome).is_ok());
        let mut missing = report.clone();
        missing["harness_metadata"][0]["attributes"]["kind"] = json!("Proof");
        assert!(validate_kani(case, &missing, &outcome).is_err());
        missing = report.clone();
        missing["harness_metadata"][0]["contract"] = Value::Null;
        assert!(validate_kani(case, &missing, &outcome).is_err());
        let checks = report["verification_results"]["results"][0]["checks"]
            .as_array()
            .unwrap();
        let postcondition = checks
            .iter()
            .position(|check| {
                check["description"]
                    .as_str()
                    .is_some_and(|text| text.starts_with("|result: &bool|"))
            })
            .unwrap();
        for status in ["Unreachable", "Failure", "Undetermined"] {
            missing = report.clone();
            missing["verification_results"]["results"][0]["checks"][postcondition]["status"] =
                json!(status);
            assert!(validate_kani(case, &missing, &outcome).is_err());
        }
        missing = report.clone();
        missing["verification_results"]["results"][0]["checks"]
            .as_array_mut()
            .unwrap()
            .remove(postcondition);
        assert!(validate_kani(case, &missing, &outcome).is_err());
    }

    #[test]
    fn proof_outputs_have_one_owner_until_its_handle_closes() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("cb-proof-lock-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let owner = lock(&directory).unwrap();
        assert!(lock(&directory).is_err());
        drop(owner);
        drop(lock(&directory).unwrap());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn source_bindings_reject_changed_inputs_and_accept_currently_revalidated_receipts() {
        let current = BTreeMap::from([("proofs/example.rs".into(), "exact-proof-input".into())]);
        let mut saved = json!(current);
        saved["xtask/src/formal.rs"] = json!("historical-receipt-validator");
        assert!(matching_sources(&saved, &current).unwrap());
        saved["proofs/example.rs"] = json!("different-production-input");
        assert!(!matching_sources(&saved, &current).unwrap());
        saved = json!(current);
        saved["unknown-input.rs"] = json!("unexpected");
        assert!(!matching_sources(&saved, &current).unwrap());
        saved = json!({});
        assert!(!matching_sources(&saved, &current).unwrap());
    }

    #[test]
    fn reserved_models_reject_reuse_other_cases_and_changed_bytes() {
        let case = CASES
            .iter()
            .find(|case| case.name == "coordinates")
            .unwrap();
        let first = reserve_models(case).unwrap();
        let second = reserve_models(case).unwrap();
        assert_ne!(first, second);
        let model = first.join("example.symtab.out");
        fs::write(&model, "original verified model").unwrap();
        let reused = second.join("model.out");
        fs::write(&reused, "original verified model").unwrap();
        let mut receipt = json!({
            "model_directory":first,
            "command":kani_command(case, &first).unwrap(),
            "model_sha256":sha(&model).unwrap(),
            "report":{"harness_metadata":[{"goto_file":model}]},
        });
        assert!(validate_model(case, &receipt).is_ok());
        receipt["report"]["harness_metadata"][0]["goto_file"] = json!(reused);
        assert!(validate_model(case, &receipt).is_err());
        receipt["report"]["harness_metadata"][0]["goto_file"] = json!(model);
        let other = CASES.iter().find(|case| case.name == "clock").unwrap();
        assert!(validate_model(other, &receipt).is_err());
        fs::write(&model, "different model").unwrap();
        assert!(validate_model(case, &receipt).is_err());
        fs::remove_dir_all(first).unwrap();
        fs::remove_dir_all(second).unwrap();
    }
}
