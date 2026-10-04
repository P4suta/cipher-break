// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::process::{Cmd, Outcome, home, json_read, json_write, now, option, sha};
use crate::proof_work::{Workload, needs_proof_tools};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const PROJECT: &str = "cipher-break-511266";

#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum RecoveryScope {
    Full,
    GpuOnly,
}

#[derive(Debug, Serialize)]
pub struct Config {
    pub project: String,
    pub zone: String,
    pub machine: String,
    pub kind: String,
    pub hours: u64,
    pub standard: bool,
    pub dry_run: bool,
    pub recovery: bool,
    pub recovery_scope: RecoveryScope,
    pub price_file: PathBuf,
    pub ssh_key: Option<PathBuf>,
    pub command: Vec<String>,
}

impl Config {
    fn parse(args: &[String], require_command: bool) -> Result<Self> {
        let mut args = args.iter().cloned().peekable();
        let kind = if args.peek().is_some_and(|s| s == "cpu" || s == "gpu") {
            args.next().context("kind")?
        } else {
            "gpu".into()
        };
        let mut config = Self {
            project: PROJECT.into(),
            zone: "us-central1-a".into(),
            machine: if kind == "gpu" {
                "g2-standard-8"
            } else {
                "n1-standard-8"
            }
            .into(),
            kind,
            hours: 2,
            standard: false,
            dry_run: false,
            recovery: false,
            recovery_scope: RecoveryScope::Full,
            price_file: crate::root().join("data/cloud-prices.json"),
            ssh_key: None,
            command: Vec::new(),
        };
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--project" => config.project = option(&mut args, &arg)?,
                "--zone" => config.zone = option(&mut args, &arg)?,
                "--machine" => config.machine = option(&mut args, &arg)?,
                "--hours" => config.hours = option(&mut args, &arg)?.parse()?,
                "--price-file" => config.price_file = option(&mut args, &arg)?.into(),
                "--ssh-key" => config.ssh_key = Some(option(&mut args, &arg)?.into()),
                "--standard" => config.standard = true,
                "--dry-run" => config.dry_run = true,
                "--recovery" => config.recovery = true,
                "--gpu-only" => config.recovery_scope = RecoveryScope::GpuOnly,
                "--" => {
                    config.command.extend(args);
                    break;
                }
                _ => bail!("unknown cloud option {arg}"),
            }
        }
        ensure!(
            (1..=2).contains(&config.hours),
            "a VM may run for one or two hours at most"
        );
        ensure!(
            valid_id(&config.project) && valid_id(&config.zone),
            "invalid project or zone id"
        );
        ensure!(
            matches!(config.machine.as_str(), "g2-standard-8" | "n1-standard-8"),
            "supported machines are g2-standard-8 and n1-standard-8"
        );
        ensure!(
            config.kind == "gpu" || config.machine == "n1-standard-8",
            "CPU jobs use n1-standard-8"
        );
        ensure!(
            !config.recovery || (config.kind == "gpu" && config.command.is_empty()),
            "--recovery needs a GPU and cannot be combined with another command"
        );
        ensure!(
            config.recovery_scope != RecoveryScope::GpuOnly || config.recovery,
            "--gpu-only requires --recovery"
        );
        ensure!(
            !require_command || config.recovery || !config.command.is_empty(),
            "give --recovery or a command after --"
        );
        Ok(config)
    }

    fn region(&self) -> Result<&str> {
        self.zone
            .rsplit_once('-')
            .map(|(region, _)| region)
            .context("zone has no region")
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

trait Api {
    fn call(&mut self, args: Vec<String>) -> Result<Outcome>;

    fn json(&mut self, args: Vec<String>) -> Result<Value> {
        let command = Cmd::new(args.iter().cloned());
        let result = self.call(args)?;
        result.require_success(&command)?;
        Ok(serde_json::from_str(&result.stdout)?)
    }
}

struct Gcloud {
    directory: PathBuf,
    sequence: usize,
}

impl Api for Gcloud {
    fn call(&mut self, args: Vec<String>) -> Result<Outcome> {
        let command = Cmd::new(args).env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1");
        let outcome = command.capture()?;
        self.sequence += 1;
        json_write(
            &self
                .directory
                .join(format!("gcloud-{:03}.json", self.sequence)),
            &json!({"at": now()?, "command": command, "result": outcome}),
        )?;
        Ok(outcome)
    }
}

fn command(parts: &[&str], project: &str) -> Vec<String> {
    let mut result: Vec<_> = parts.iter().map(|s| (*s).to_owned()).collect();
    result.extend([format!("--project={project}"), "--format=json".into()]);
    result
}

fn empty_resources(api: &mut impl Api, project: &str) -> Result<(Value, Value)> {
    let instances = api.json(command(
        &["gcloud", "compute", "instances", "list"],
        project,
    ))?;
    let disks = api.json(command(&["gcloud", "compute", "disks", "list"], project))?;
    ensure!(
        instances.as_array().context("instance list")?.is_empty(),
        "an instance already exists in {project}; no second VM or retry started"
    );
    ensure!(
        disks.as_array().context("disk list")?.is_empty(),
        "a disk already exists in {project}; inspect it before creating or retrying"
    );
    Ok((instances, disks))
}

fn preflight(api: &mut impl Api, config: &Config) -> Result<Value> {
    let project = api.json(command(
        &["gcloud", "projects", "describe", &config.project],
        &config.project,
    ))?;
    ensure!(
        project["lifecycleState"] == "ACTIVE",
        "{} is not ACTIVE; no VM started",
        config.project
    );
    let billing = api.json(command(
        &["gcloud", "billing", "projects", "describe", &config.project],
        &config.project,
    ))?;
    ensure!(
        billing["billingEnabled"] == true,
        "{} has no enabled billing; no VM started",
        config.project
    );
    let (instances, disks) = empty_resources(api, &config.project)?;
    let global = api.json(command(
        &["gcloud", "compute", "project-info", "describe"],
        &config.project,
    ))?;
    let regional = api.json(command(
        &["gcloud", "compute", "regions", "describe", config.region()?],
        &config.project,
    ))?;
    quota(&regional, "CPUS", 8.0)?;
    if config.kind == "gpu" {
        quota(&global, "GPUS_ALL_REGIONS", 1.0)?;
        quota(
            &regional,
            if config.machine == "g2-standard-8" {
                "NVIDIA_L4_GPUS"
            } else {
                "NVIDIA_T4_GPUS"
            },
            1.0,
        )?;
    }
    Ok(
        json!({"at": now()?, "project": project, "billing": billing, "instances": instances, "disks": disks, "global": global, "region": regional, "credit_coverage": "requires a current Billing Credits observation; billingEnabled is insufficient"}),
    )
}

fn quota(value: &Value, metric: &str, required: f64) -> Result<()> {
    let record = value["quotas"]
        .as_array()
        .context("quota records")?
        .iter()
        .find(|q| q["metric"] == metric)
        .with_context(|| format!("missing quota {metric}"))?;
    let available = record["limit"].as_f64().context("quota limit")?
        - record["usage"].as_f64().context("quota usage")?;
    ensure!(
        available >= required,
        "{metric} has {available} available; {required} required"
    );
    Ok(())
}

fn estimate(config: &Config, at: OffsetDateTime) -> Result<Value> {
    let prices = json_read(&config.price_file)?;
    ensure!(
        prices["currency"] == "USD",
        "prices must be recorded in USD"
    );
    let checked = OffsetDateTime::parse(
        prices["checked_at"].as_str().context("price check time")?,
        &Rfc3339,
    )?;
    let age = at - checked;
    ensure!(
        age >= time::Duration::ZERO
            && age
                <= time::Duration::days(
                    prices["maximum_age_days"]
                        .as_i64()
                        .context("price expiry")?
                        .min(7)
                ),
        "regional price evidence is expired or future dated; update the price file before provisioning"
    );
    let key = format!("{}/{}/{}", config.region()?, config.machine, config.kind);
    let vm = prices["vm_hourly"][&key]
        .as_f64()
        .with_context(|| format!("no reviewed price for {key}"))?;
    let disk = prices["balanced_disk_gib_hourly"]
        .as_f64()
        .context("disk price")?
        * 60.0;
    let ip = prices["ephemeral_ipv4_hourly"]
        .as_f64()
        .context("IP price")?;
    let reserve = prices["egress_storage_tax_fx_reserve"]
        .as_f64()
        .context("other cost reserve")?;
    ensure!(
        [vm, disk, ip, reserve]
            .iter()
            .all(|n| n.is_finite() && *n >= 0.0)
            && vm > 0.0
            && reserve >= 1.25,
        "invalid price or insufficient transfer/tax reserve"
    );
    let maximum = (vm + disk + ip) * config.hours as f64 + reserve;
    Ok(
        json!({"checked_at": prices["checked_at"], "price_sha256": sha(&config.price_file)?, "regional_key": key, "vm_hourly_usd": vm, "disk_hourly_usd": disk, "ipv4_hourly_usd": ip, "other_reserve_usd": reserve, "maximum_estimated_usd": maximum, "maximum_hours": config.hours, "spending_authorization":"owner-approved promotional-credit use; one VM and two-hour deletion limit", "sources": prices["sources"], "settled_usd": null, "credit_deduction_assumed": false}),
    )
}

fn create_args(config: &Config, name: &str, deadline: &str, metadata: &Path) -> Vec<String> {
    let mut args = command(
        &["gcloud", "compute", "instances", "create", name],
        &config.project,
    );
    args.extend([
        format!("--zone={}", config.zone),
        format!("--machine-type={}", config.machine),
        format!(
            "--provisioning-model={}",
            if config.standard { "STANDARD" } else { "SPOT" }
        ),
        format!("--termination-time={deadline}"),
        "--instance-termination-action=DELETE".into(),
        "--maintenance-policy=TERMINATE".into(),
        "--no-restart-on-failure".into(),
        "--reservation-affinity=none".into(),
        "--image=ubuntu-2404-noble-amd64-v20260918".into(),
        "--image-project=ubuntu-os-cloud".into(),
        "--boot-disk-size=60GB".into(),
        "--boot-disk-type=pd-balanced".into(),
        "--boot-disk-auto-delete".into(),
        "--no-service-account".into(),
        "--no-scopes".into(),
        "--metadata=enable-oslogin=FALSE,block-project-ssh-keys=TRUE".into(),
        format!("--metadata-from-file=ssh-keys={}", metadata.display()),
        format!("--labels=cipher-break-run={name}"),
        "--quiet".into(),
    ]);
    if config.kind == "gpu" && config.machine == "n1-standard-8" {
        args.push("--accelerator=type=nvidia-tesla-t4,count=1".into());
    }
    args
}

fn verify_created(instance: &Value, name: &str, deadline: &str) -> Result<()> {
    ensure!(
        instance["name"] == name && instance["labels"]["cipher-break-run"] == name,
        "created instance does not match the recorded run"
    );
    ensure!(
        instance["scheduling"]["instanceTerminationAction"] == "DELETE",
        "API did not retain VM deletion behavior"
    );
    let actual = OffsetDateTime::parse(
        instance["scheduling"]["terminationTime"]
            .as_str()
            .context("returned deadline")?,
        &Rfc3339,
    )?;
    ensure!(
        actual == OffsetDateTime::parse(deadline, &Rfc3339)?,
        "API changed the absolute VM deadline"
    );
    ensure!(
        instance["disks"]
            .as_array()
            .context("instance disks")?
            .iter()
            .any(|d| d["boot"] == true && d["autoDelete"] == true),
        "API did not retain boot-disk auto-delete"
    );
    Ok(())
}

pub fn dispatch(args: &[String]) -> Result<()> {
    let (action, args) = args
        .split_first()
        .context("give a cloud action; see cargo xtask help")?;
    match action.as_str() {
        "run" => {
            let config = Config::parse(args, true)?;
            let workload = if config.recovery {
                Workload::Recovery
            } else if experiment_command(&config.command) {
                Workload::Experiment
            } else {
                Workload::Search
            };
            run(&config, workload)
        }
        "prove" => {
            let (case, options) = args
                .split_first()
                .context("use cloud prove CASE [CLOUD_OPTIONS]")?;
            ensure!(crate::formal::named_case(case), "unknown proof case {case}");
            let mut options = std::iter::once("cpu".to_owned())
                .chain(options.iter().cloned())
                .collect::<Vec<_>>();
            options.push("--standard".into());
            let mut config = Config::parse(&options, false)?;
            ensure!(
                config.kind == "cpu" && !config.recovery && config.command.is_empty(),
                "cloud prove accepts only CPU configuration options"
            );
            config.command = vec![
                "cargo".into(),
                "xtask".into(),
                "prove".into(),
                "--case".into(),
                case.clone(),
                "--max-seconds".into(),
                "3300".into(),
            ];
            run(&config, Workload::Verification)
        }
        "preflight" => {
            let config = Config::parse(args, false)?;
            let directory = crate::root().join("reports/p1030680/xtask-preflight");
            let mut api = Gcloud {
                directory: directory.clone(),
                sequence: 0,
            };
            let prices = estimate(&config, OffsetDateTime::now_utc())?;
            let checks = preflight(&mut api, &config)?;
            json_write(
                &directory.join("preflight.json"),
                &json!({"checks": checks, "estimate": prices}),
            )?;
            println!(
                "ACTIVE project, enabled billing, unused instance/disk space, and CPU/GPU quotas verified.\nMaximum list-price estimate: USD {:.4} before credits.",
                prices["maximum_estimated_usd"]
                    .as_f64()
                    .context("maximum estimate")?
            );
            Ok(())
        }
        "bootstrap" => crate::bootstrap::dispatch(args),
        "fetch" => fetch(args),
        "cleanup" => cleanup_saved(args),
        "ls" => {
            let project = match args {
                [] => PROJECT,
                [flag, project] if flag == "--project" => project,
                _ => bail!("use cloud ls [--project ID]"),
            };
            let command = Cmd::new(command(
                &["gcloud", "compute", "instances", "list"],
                project,
            ));
            command
                .live(Duration::from_secs(120))?
                .require_success(&command)
        }
        _ => bail!("unknown cloud action {action}"),
    }
}

fn lock() -> Result<crate::lease::HeldFile> {
    let directory = home()?.join(".local/state/cipher-break");
    fs::create_dir_all(&directory)?;
    crate::lease::file(&directory.join("cloud.lock"))
        .context("cannot acquire the single-VM operation lock")
}

struct StagedJudge(Option<PathBuf>);

impl Drop for StagedJudge {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn stage_judge(config: &Config, name: &str) -> Result<(Vec<String>, StagedJudge, Value)> {
    let mut argv = config.command.clone();
    let mut stage = StagedJudge(None);
    if argv.len() == 5 && argv[..3] == ["cargo", "xtask", "cribs"] && argv[4].starts_with("gs://") {
        let source = argv[4].clone();
        let relative = format!("data/cloud-judge-{name}.txt");
        let path = crate::root().join(&relative);
        ensure!(
            !path.exists(),
            "refusing to replace an existing staged model"
        );
        stage.0 = Some(path.clone());
        Cmd::new([
            "gcloud",
            "storage",
            "cp",
            "--quiet",
            &source,
            &path.to_string_lossy(),
        ])
        .checked()?;
        argv[4] = relative;
        let record = json!({"source": source, "snapshot_path": argv[4], "sha256": sha(&path)?, "downloaded_on": "controller; no cloud credentials are sent to the VM"});
        return Ok((argv, stage, record));
    }
    Ok((argv, stage, Value::Null))
}

#[allow(clippy::too_many_lines)]
fn run(config: &Config, workload: Workload) -> Result<()> {
    if workload == Workload::Verification {
        ensure!(
            proof_command(&config.command),
            "verification dispatch requires a registered proof command"
        );
    }
    if workload == Workload::Recovery {
        ensure!(
            config.recovery && config.command.is_empty(),
            "recovery dispatch requires the fixed recovery job"
        );
    }
    if workload == Workload::Experiment {
        ensure!(
            !config.recovery && config.kind == "gpu" && experiment_command(&config.command),
            "experiment dispatch requires a bounded candidate campaign on a GPU"
        );
    }
    let at = OffsetDateTime::now_utc();
    let cost = estimate(config, at)?;
    let deadline = (at + time::Duration::hours(i64::try_from(config.hours)?))
        .replace_nanosecond(0)?
        .format(&Rfc3339)?;
    let name = format!(
        "cb-{}-{}-{}",
        at.unix_timestamp(),
        at.nanosecond(),
        config.kind
    );
    let directory = crate::root().join("reports/cloud").join(&name);
    let metadata = directory.join("ssh-metadata.txt");
    let argv = create_args(config, &name, &deadline, &metadata);
    if config.dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"config": config, "workload":format!("{workload:?}"), "estimate": cost, "create_argv": argv, "deadline": deadline, "remote_execution": "domyjob", "creates_resources": false})
            )?
        );
        return Ok(());
    }
    let _lock = lock()?;
    let release = crate::runner::local_ready()?;
    crate::jobs::quick_for(workload)?;
    let mut api = Gcloud {
        directory: directory.clone(),
        sequence: 0,
    };
    let checks = preflight(&mut api, config)?;
    let reserved = committed_estimates(&crate::root().join("reports/cloud"))?;
    let maximum = cost["maximum_estimated_usd"]
        .as_f64()
        .context("maximum estimate")?;
    let prior_recovery = recovery_vm_estimates(&crate::root().join("reports/cloud"))?;
    let key = public_key(config.ssh_key.as_deref())?;
    let (job_command, _staged_judge, judge_record) = stage_judge(config, &name)?;
    fs::create_dir_all(&directory)?;
    fs::write(
        &metadata,
        format!(
            "{}:{key}\n",
            std::env::var("USER").unwrap_or_else(|_| "yasunobu".into())
        ),
    )?;
    let identity = directory.join("identity.pub");
    fs::write(&identity, format!("{key}\n"))?;
    let mut manifest = json!({
        "id": name, "at": now()?, "config": config, "create_argv": argv,
        "deadline": deadline, "estimate": cost, "preflight": checks,
        "prior_reserved_estimate_usd": reserved, "prior_recovery_runtime_bound_usd": prior_recovery,
        "domyjob_release": release,
        "controller_proof_attestation": crate::formal::workload_attestation(workload)?,
        "staged_judge": judge_record,
        "head": Cmd::new(["git", "rev-parse", "HEAD"]).checked()?.trim(),
        "provenance_sha256": crate::audit::provenance()?,
        "uncommitted_diff_sha256": crate::process::hash(Cmd::new(["git", "diff", "HEAD"]).checked()?.as_bytes()),
        "status": "creating", "reserved_estimate_usd": maximum,
        "snapshot": "domyjob sends the current checkout, including uncommitted files, respecting ignore rules"
    });
    json_write(&directory.join("manifest.json"), &manifest)?;
    let operation = (|| -> Result<()> {
        let outcome = api.call(argv)?;
        if outcome.exit_code != 0 {
            let resources = empty_resources(&mut api, &config.project);
            if resources.is_ok() {
                manifest["reserved_estimate_usd"] = json!(0);
                manifest["status"] = json!("create failed; no VM or disk present");
                json_write(&directory.join("manifest.json"), &manifest)?;
            }
            resources?;
            bail!(
                "VM creation failed; no retry started: {}",
                outcome.stderr.trim()
            );
        }
        let returned: Value = serde_json::from_str(&outcome.stdout)?;
        let instance = returned
            .as_array()
            .and_then(|a| a.first())
            .context("created instance response")?;
        manifest["instance"] = instance.clone();
        manifest["status"] = json!("created");
        json_write(&directory.join("manifest.json"), &manifest)?;
        verify_created(instance, &name, &deadline)?;
        let address = instance["networkInterfaces"][0]["accessConfigs"][0]["natIP"]
            .as_str()
            .context("VM external IP")?;
        let target = ssh_config(&name, address, &identity, &directory)?;
        manifest["ssh_target"] = json!(target);
        json_write(&directory.join("manifest.json"), &manifest)?;
        await_ssh_with(&target, Duration::from_secs(180), &directory, Cmd::live)?;
        crate::bootstrap::setup(&target, config.kind == "gpu", &directory)?;
        let proof_path = if needs_proof_tools(
            workload,
            config.recovery && config.recovery_scope == RecoveryScope::Full,
        ) {
            Some(crate::bootstrap::proof_tools(&target, &directory)?)
        } else {
            None
        };
        let remote_home = crate::runner::checked(&target, ["printenv", "HOME"])?
            .trim()
            .to_owned();
        let mut remote_path = format!(
            "{remote_home}/.local/bin:{remote_home}/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        );
        if let Some(path) = proof_path {
            remote_path = format!("{path}:{remote_path}");
        }
        let mut submission_args = vec![
            "run".into(),
            target.clone(),
            "--".into(),
            "/usr/bin/env".into(),
            format!("PATH={remote_path}"),
            "MISE_AUTO_INSTALL=false".into(),
            "CB_CLOUD_RUN=1".into(),
        ];
        submission_args.extend(if config.recovery {
            let mut worker = vec![
                "cargo".into(),
                "xtask".into(),
                "p1030680".into(),
                "recovery".into(),
                "--max-minutes".into(),
                (config.hours * 60 - 15).min(80).to_string(),
            ];
            if config.recovery_scope == RecoveryScope::GpuOnly {
                worker.push("--gpu-only".into());
            }
            worker
        } else {
            job_command
        });
        manifest["submission_provenance_sha256"] = json!(crate::audit::provenance()?);
        json_write(&directory.join("manifest.json"), &manifest)?;
        let submission = crate::runner::command(submission_args);
        let result = submission.capture()?;
        json_write(
            &directory.join("submission.json"),
            &json!({"command": submission, "result": result}),
        )?;
        result.require_success(&submission)?;
        let job = job_reference(&result.stdout)?;
        manifest["job"] = json!(job);
        manifest["status"] = json!("submitted");
        json_write(&directory.join("manifest.json"), &manifest)?;
        let wait = crate::runner::command(["wait", &job]);
        let remaining = OffsetDateTime::parse(&deadline, &Rfc3339)? - OffsetDateTime::now_utc();
        let limit = Duration::from_secs(remaining.whole_seconds().max(1) as u64);
        let result = wait.live(limit)?;
        json_write(
            &directory.join("wait.json"),
            &json!({"command": wait, "result": result}),
        )?;
        fetch_job(
            &job,
            &directory,
            &result_artifacts(config.recovery, &config.recovery_scope, &config.command),
        )?;
        if config.recovery_scope == RecoveryScope::GpuOnly {
            manifest["artifact_transfer_probe"] = json!({"status":"passed", "bytes":fs::metadata(directory.join("out/artifact-probe.json"))?.len(), "sha256":sha(&directory.join("out/artifact-probe.json"))?});
        }
        result.require_success(&wait)?;
        manifest["status"] = json!("job completed");
        Ok(())
    })();
    if let Err(error) = &operation {
        manifest["error"] = json!(format!("{error:#}"));
        manifest["status"] = json!("failed");
    }
    let cleanup = delete_owned(&mut api, config, &name);
    remove_ssh_config(&name)?;
    manifest["cleanup_verified"] = json!(cleanup.is_ok());
    manifest["finished_at"] = json!(now()?);
    if cleanup.is_ok() {
        bound_after_cleanup(&mut manifest)?;
    }
    if let Err(error) = &cleanup {
        manifest["cleanup_error"] = json!(format!("{error:#}"));
    }
    json_write(&directory.join("manifest.json"), &manifest)?;
    cleanup?;
    operation?;
    println!(
        "Results: {}\nVM and boot disk deletion verified.",
        directory.display()
    );
    Ok(())
}

fn proof_command(command: &[String]) -> bool {
    let slots = std::array::from_fn(|index| command.get(index).map(String::as_bytes));
    let registered = command
        .get(4)
        .is_some_and(|name| crate::formal::named_case(name));
    crate::proof_work::proof_command(command.len(), slots, registered)
}

fn experiment_command(command: &[String]) -> bool {
    crate::proof_work::experiment_command(
        command.len(),
        std::array::from_fn(|index| command.get(index).map(String::as_bytes)),
    )
}

fn committed_estimates(directory: &Path) -> Result<f64> {
    if !directory.exists() {
        return Ok(0.0);
    }
    let mut total = 0.0;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path().join("manifest.json");
        if path.exists() {
            total += json_read(&path)?["reserved_estimate_usd"]
                .as_f64()
                .context("run's reserved estimate")?;
        }
    }
    Ok(total)
}

fn recovery_vm_estimates(directory: &Path) -> Result<f64> {
    if !directory.exists() {
        return Ok(0.0);
    }
    let mut total = 0.0;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path().join("manifest.json");
        if path.exists() {
            let manifest = json_read(&path)?;
            if manifest["config"]["recovery"] == true {
                let reserved = manifest["reserved_estimate_usd"]
                    .as_f64()
                    .context("recovery reservation")?;
                // The incoming estimate reserves USD 1.25 for the entire pilot's transfers and tax, including previous startup failures.
                let other = manifest["estimate"]["other_reserve_usd"]
                    .as_f64()
                    .context("pilot overhead reservation")?;
                total += (reserved - other).max(0.0);
            }
        }
    }
    Ok(total)
}

fn bound_after_cleanup(manifest: &mut Value) -> Result<()> {
    if manifest["cleanup_verified"] != true || !manifest["instance"].is_object() {
        return Ok(());
    }
    let start = OffsetDateTime::parse(
        manifest["at"].as_str().context("creation request time")?,
        &Rfc3339,
    )?;
    let end = OffsetDateTime::parse(
        manifest["finished_at"]
            .as_str()
            .context("verified cleanup time")?,
        &Rfc3339,
    )?;
    ensure!(end >= start, "cleanup precedes the creation request");
    let hours = ((end - start).as_seconds_f64() + 60.0) / 3600.0;
    let estimate = &manifest["estimate"];
    let rate = ["vm_hourly_usd", "disk_hourly_usd", "ipv4_hourly_usd"]
        .iter()
        .map(|key| estimate[key].as_f64().context("recorded hourly price"))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .sum::<f64>();
    let bounded = hours * rate
        + estimate["other_reserve_usd"]
            .as_f64()
            .context("other reserve")?;
    let original = estimate["maximum_estimated_usd"]
        .as_f64()
        .context("original estimate")?;
    manifest["reserved_estimate_usd"] = json!(bounded.min(original));
    manifest["runtime_cost_bound_basis"] = json!(
        "on-demand price from before creation until verified deletion, plus one minute and the original transfer/tax reserve; settled billing remains unknown"
    );
    Ok(())
}

fn await_ssh_with(
    target: &str,
    limit: Duration,
    directory: &Path,
    mut probe: impl FnMut(&Cmd, Duration) -> Result<Outcome>,
) -> Result<()> {
    let command = Cmd::new([
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        target,
        "true",
    ]);
    let start = std::time::Instant::now();
    let mut attempts = Vec::new();
    eprintln!("Waiting for authenticated SSH access on the new VM.");
    loop {
        let remaining = limit.checked_sub(start.elapsed()).context(
            "authenticated SSH did not become ready before its deadline; inspect ssh-ready.json",
        )?;
        let outcome = probe(&command, remaining.min(Duration::from_secs(10)))?;
        let ready = outcome.exit_code == 0 && !outcome.timed_out;
        attempts.push(json!({"command": command, "result": outcome}));
        json_write(
            &directory.join("ssh-ready.json"),
            &json!({"maximum_seconds": limit.as_secs_f64(), "attempts": attempts}),
        )?;
        if ready {
            return Ok(());
        }
        let remaining = limit
            .checked_sub(start.elapsed())
            .context("authenticated SSH did not become ready before its deadline")?;
        std::thread::sleep(remaining.min(Duration::from_secs(2)));
    }
}

fn public_key(path: Option<&Path>) -> Result<String> {
    let text = if let Some(path) = path {
        fs::read_to_string(path)?
    } else {
        let socket = home()?.join("Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock");
        let mut command = Cmd::new(["ssh-add", "-L"]);
        if std::env::var_os("SSH_AUTH_SOCK").is_none() && socket.exists() {
            command = command.env("SSH_AUTH_SOCK", socket.to_string_lossy());
        }
        command.checked()?
    };
    let line = text
        .lines()
        .find(|line| line.starts_with("ssh-ed25519 "))
        .context(
            "no existing Ed25519 public key; use --ssh-key PUBLIC_KEY or unlock the SSH agent",
        )?;
    let fields: Vec<_> = line.split_whitespace().take(2).collect();
    ensure!(
        fields.len() == 2
            && fields[1]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')),
        "invalid public SSH key"
    );
    Ok(fields.join(" "))
}

fn delete_owned(api: &mut impl Api, config: &Config, name: &str) -> Result<()> {
    let instances = api.json(command(
        &["gcloud", "compute", "instances", "list"],
        &config.project,
    ))?;
    if let Some(instance) = instances
        .as_array()
        .context("instance list")?
        .iter()
        .find(|i| i["name"] == name)
    {
        ensure!(
            instance["labels"]["cipher-break-run"] == name,
            "refusing to delete an instance without this run's ownership label"
        );
        let zone = instance["zone"]
            .as_str()
            .context("instance zone")?
            .rsplit('/')
            .next()
            .context("zone name")?;
        ensure!(
            zone == config.zone,
            "instance zone differs from the manifest"
        );
        let args = command(
            &[
                "gcloud",
                "compute",
                "instances",
                "delete",
                name,
                &format!("--zone={zone}"),
                "--quiet",
            ],
            &config.project,
        );
        let result = api.call(args.clone())?;
        result.require_success(&Cmd::new(args))?;
    }
    let instances = api.json(command(
        &["gcloud", "compute", "instances", "list"],
        &config.project,
    ))?;
    ensure!(
        !instances
            .as_array()
            .context("instance list")?
            .iter()
            .any(|i| i["name"] == name),
        "VM remains after deletion"
    );
    let disks = api.json(command(
        &["gcloud", "compute", "disks", "list"],
        &config.project,
    ))?;
    ensure!(
        !disks
            .as_array()
            .context("disk list")?
            .iter()
            .any(|d| d["name"] == name || d["labels"]["cipher-break-run"] == name),
        "boot disk remains after deletion; inspect before retrying"
    );
    Ok(())
}

fn ssh_config(name: &str, address: &str, identity: &Path, directory: &Path) -> Result<String> {
    address
        .parse::<std::net::Ipv4Addr>()
        .context("invalid VM IP address")?;
    let user = std::env::var("USER").unwrap_or_else(|_| "yasunobu".into());
    ensure!(
        user.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')),
        "invalid SSH username"
    );
    let file = home()?.join(".ssh/config");
    fs::create_dir_all(file.parent().context("SSH config directory")?)?;
    let existing = if file.exists() {
        fs::read_to_string(&file)?
    } else {
        String::new()
    };
    ensure!(
        !existing.contains(&format!("# cipher-break {name}")),
        "SSH run alias already exists"
    );
    let block = format!(
        "# cipher-break {name}\nHost {name}\n  HostName {address}\n  User {user}\n  IdentityFile \"{}\"\n  IdentitiesOnly yes\n  ForwardAgent no\n  StrictHostKeyChecking accept-new\n  UserKnownHostsFile \"{}\"\n  ConnectTimeout 20\n# end cipher-break {name}\n",
        identity.display(),
        directory.join("known_hosts").display()
    );
    crate::gcp::private_write(&file, insert_ssh_block(&existing, &block).as_bytes())?;
    Ok(name.to_owned())
}

fn insert_ssh_block(existing: &str, block: &str) -> String {
    let mut offset = 0;
    for line in existing.split_inclusive('\n') {
        let keyword = line.split_whitespace().next().unwrap_or("");
        if keyword.eq_ignore_ascii_case("Host") || keyword.eq_ignore_ascii_case("Match") {
            break;
        }
        offset += line.len();
    }
    let (preamble, hosts) = existing.split_at(offset);
    let newline = if !preamble.is_empty() && !preamble.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    format!("{preamble}{newline}{block}{hosts}")
}

fn remove_ssh_config(name: &str) -> Result<()> {
    let file = home()?.join(".ssh/config");
    if !file.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(&file)?;
    let start = format!("# cipher-break {name}\n");
    let end = format!("# end cipher-break {name}\n");
    if let Some((before, rest)) = text.split_once(&start) {
        let (_, after) = rest
            .split_once(&end)
            .context("incomplete managed SSH block")?;
        crate::gcp::private_write(&file, format!("{before}{after}").as_bytes())?;
    }
    Ok(())
}

fn job_reference(text: &str) -> Result<String> {
    let reference = text.trim();
    let (target, id) = reference
        .split_once(':')
        .context("domyjob returned no job reference; do not resubmit an ambiguous job")?;
    ensure!(
        !target.is_empty()
            && !id.is_empty()
            && reference
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b':')),
        "invalid domyjob job reference"
    );
    Ok(reference.to_owned())
}

fn result_path(recovery: bool, command: &[String]) -> Option<&'static str> {
    if recovery {
        Some("p1030680/recovery-result.json")
    } else if proof_command(command) {
        Some("proof-bundle.tar.gz")
    } else if command.starts_with(&["cargo".into(), "xtask".into(), "bench".into()]) {
        Some("bench.json")
    } else if command.starts_with(&["cargo".into(), "xtask".into(), "cribs".into()]) {
        Some("cribs.json")
    } else if command.starts_with(&[
        "cargo".into(),
        "xtask".into(),
        "p1030680".into(),
        "campaign".into(),
    ]) {
        Some("p1030680/campaign-result.json")
    } else {
        None
    }
}

fn result_artifacts(
    recovery: bool,
    scope: &RecoveryScope,
    command: &[String],
) -> Vec<&'static str> {
    let mut artifacts: Vec<_> = result_path(recovery, command).into_iter().collect();
    if recovery {
        artifacts.push(match scope {
            RecoveryScope::Full => "proof-bundle.tar.gz",
            RecoveryScope::GpuOnly => "p1030680/artifact-probe.json",
        });
    }
    artifacts
}

fn fetch_job(job: &str, directory: &Path, artifacts: &[&str]) -> Result<()> {
    fs::create_dir_all(directory.join("out"))?;
    let logs = crate::runner::command(["logs", job]).checked()?;
    fs::write(directory.join("out/log.txt"), logs)?;
    let status = crate::runner::command(["status", job]).capture()?;
    fs::write(directory.join("out/status"), &status.stdout)?;
    if artifacts.is_empty() {
        return Ok(());
    }
    let (target, id) = job.split_once(':').context("job reference")?;
    let home = crate::runner::checked(target, ["printenv", "HOME"])?;
    let mut files = Vec::new();
    for artifact in artifacts {
        let destination = directory
            .join("out")
            .join(Path::new(artifact).file_name().context("artifact name")?);
        let paths = crate::runner::checked(
            target,
            [
                "find",
                &format!("{}/.local/state/domyjob", home.trim()),
                "-path",
                &format!("*/{id}/workspace/reports/{artifact}"),
                "-type",
                "f",
            ],
        )?;
        let paths: Vec<_> = paths.lines().collect();
        ensure!(paths.len() == 1, "result path is missing or ambiguous");
        files.push((paths[0].to_owned(), destination));
    }
    crate::runner::read_files(target, &files)?;
    for (artifact, (_, destination)) in artifacts.iter().zip(files) {
        if *artifact == "proof-bundle.tar.gz" {
            continue;
        }
        let report = json_read(&destination)?;
        if *artifact == "p1030680/recovery-result.json" {
            json_write(
                &crate::root().join("data/p1030680/recovery-result.json"),
                &report,
            )?;
        } else if *artifact == "p1030680/campaign-result.json" {
            json_write(
                &crate::root().join("reports/p1030680/campaign-result.json"),
                &report,
            )?;
            if let Some(recovery) = report.get("recovery_result") {
                ensure!(
                    crate::audit::recovery_status(recovery, &crate::audit::provenance()?)
                        == "passed",
                    "campaign recovery result is incomplete or belongs to different source code"
                );
                json_write(
                    &crate::root().join("data/p1030680/recovery-result.json"),
                    recovery,
                )?;
            }
        }
    }
    Ok(())
}

fn run_directory(id: &str) -> Result<PathBuf> {
    ensure!(
        !id.is_empty()
            && (valid_id(id) || id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "invalid run id"
    );
    Ok(crate::root().join("reports/cloud").join(id))
}

fn fetch(args: &[String]) -> Result<()> {
    let legacy = args.iter().any(|s| s == "--legacy");
    let ids: Vec<_> = args.iter().filter(|s| s.as_str() != "--legacy").collect();
    ensure!(ids.len() <= 1, "use cloud fetch [RUN_ID] [--legacy]");
    if let Some(id) = ids.first() {
        let directory = run_directory(id)?;
        if legacy {
            fs::create_dir_all(&directory)?;
            Cmd::new([
                "gcloud",
                "storage",
                "cp",
                "--quiet",
                "-r",
                &format!("gs://{PROJECT}-runs/runs/{id}/*"),
                &directory.to_string_lossy(),
            ])
            .checked()?;
        } else {
            let manifest = json_read(&directory.join("manifest.json"))?;
            if manifest["cleanup_verified"] == true {
                ensure!(
                    directory.join("out/log.txt").exists(),
                    "the VM is deleted and no submitted job log was retained; inspect its saved bootstrap and API records"
                );
            } else {
                let job = manifest["job"]
                    .as_str()
                    .context("run has no submitted domyjob job")?;
                let command: Vec<String> =
                    serde_json::from_value(manifest["config"]["command"].clone())?;
                fetch_job(
                    job,
                    &directory,
                    &result_artifacts(
                        manifest["config"]["recovery"] == true,
                        &if manifest["config"]["recovery_scope"] == "GpuOnly" {
                            RecoveryScope::GpuOnly
                        } else {
                            RecoveryScope::Full
                        },
                        &command,
                    ),
                )?;
            }
        }
        println!("Results: {}", directory.display());
    } else if legacy {
        print!(
            "{}",
            Cmd::new([
                "gcloud",
                "storage",
                "ls",
                &format!("gs://{PROJECT}-runs/runs/")
            ])
            .checked()?
        );
    } else {
        let directory = crate::root().join("reports/cloud");
        if directory.exists() {
            let mut paths: Vec<_> = fs::read_dir(directory)?
                .map(|e| e.map(|e| e.path()))
                .collect::<std::io::Result<_>>()?;
            paths.sort();
            for path in paths.into_iter().filter(|p| p.is_dir()) {
                println!(
                    "{}",
                    path.file_name().context("run directory")?.to_string_lossy()
                );
            }
        }
    }
    Ok(())
}

fn cleanup_saved(args: &[String]) -> Result<()> {
    let [id] = args else {
        bail!("use cloud cleanup RUN_ID");
    };
    let _lock = lock()?;
    let directory = run_directory(id)?;
    let mut manifest = json_read(&directory.join("manifest.json"))?;
    let config: SavedConfig = serde_json::from_value(manifest["config"].clone())?;
    let parsed = Config::parse(
        &[
            config.kind,
            "--project".into(),
            config.project,
            "--zone".into(),
            config.zone,
            "--machine".into(),
            config.machine,
        ],
        false,
    )?;
    let mut api = Gcloud {
        directory: directory.join("cleanup"),
        sequence: 0,
    };
    delete_owned(&mut api, &parsed, id)?;
    remove_ssh_config(id)?;
    manifest["cleanup_verified"] = json!(true);
    if manifest["finished_at"].is_null() {
        manifest["finished_at"] = json!(now()?);
    }
    bound_after_cleanup(&mut manifest)?;
    json_write(&directory.join("manifest.json"), &manifest)?;
    println!("VM and boot disk deletion verified for {id}.");
    Ok(())
}

#[derive(Deserialize)]
struct SavedConfig {
    kind: String,
    project: String,
    zone: String,
    machine: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_hardware_recovery_installs_the_same_proof_tools_as_a_proof_worker() {
        let full = Config::parse(&["gpu".into(), "--recovery".into()], true).unwrap();
        assert!(needs_proof_tools(
            Workload::Recovery,
            full.recovery_scope == RecoveryScope::Full
        ));
        let gpu_only = Config::parse(
            &["gpu".into(), "--recovery".into(), "--gpu-only".into()],
            true,
        )
        .unwrap();
        assert!(!needs_proof_tools(
            Workload::Recovery,
            gpu_only.recovery_scope == RecoveryScope::Full
        ));
        assert!(needs_proof_tools(Workload::Verification, false));
        assert!(!needs_proof_tools(Workload::Search, true));
    }
    use std::collections::VecDeque;

    #[test]
    fn c06_explicit_positions_cover_the_actual_compatible_menus() {
        let cipher: Vec<_> = include_bytes!("../../data/ciphertext.txt")
            .iter()
            .copied()
            .filter(u8::is_ascii_uppercase)
            .collect();
        let menus = crate::audit::placements(
            &cipher,
            b"FFFTTTNICHTZULOESENFUNKLEITUNG",
            &serde_json::json!("all"),
        );
        let mut command: Vec<_> = [
            "cargo",
            "xtask",
            "p1030680",
            "campaign",
            "--candidate",
            "C06",
            "--max-minutes",
            "100",
            "--at",
            "0",
            "--reuse-recovery",
        ]
        .map(str::to_owned)
        .into();
        for offset in 0..=cipher.len() {
            command[9] = offset.to_string();
            assert_eq!(
                experiment_command(&command),
                menus
                    .iter()
                    .any(|menu| menu.offset == offset && menu.closures > 0),
                "offset {offset}",
            );
        }
        for invalid in ["-1", "018", "18x", "", "18446744073709551616"] {
            command[9] = invalid.into();
            assert!(!experiment_command(&command));
        }
    }

    #[test]
    fn bounded_experiments_accept_only_sourced_candidates_and_fixed_runtime_options() {
        let base: Vec<String> = [
            "cargo",
            "xtask",
            "p1030680",
            "campaign",
            "--candidate",
            "C03",
            "--max-minutes",
            "100",
        ]
        .map(str::to_owned)
        .into();
        assert!(experiment_command(&base));
        for flags in [
            vec!["--control-only"],
            vec!["--reuse-recovery"],
            vec!["--control-only", "--reuse-recovery"],
        ] {
            let mut command = base.clone();
            command.extend(flags.into_iter().map(str::to_owned));
            assert!(experiment_command(&command));
        }
        let mut suffix = base.clone();
        suffix[5] = "C06".into();
        suffix.extend(["--at".into(), "42".into(), "--reuse-recovery".into()]);
        assert!(experiment_command(&suffix));
        suffix[5] = "C03".into();
        assert!(!experiment_command(&suffix));
        suffix[5] = "C06".into();
        suffix[9] = "40".into();
        assert!(!experiment_command(&suffix));
        for (index, replacement) in [
            (0, "sh"),
            (2, "solve"),
            (3, "recovery"),
            (4, "--word"),
            (5, "C05"),
            (6, "--hours"),
            (7, "0"),
            (7, "101"),
        ] {
            let mut command = base.clone();
            command[index] = replacement.into();
            assert!(!experiment_command(&command));
        }
        let mut command = base;
        command.extend(["--control-only".into(), "--control-only".into()]);
        assert!(!experiment_command(&command));
    }

    #[test]
    fn all_recovery_artifacts_are_collected_in_one_batch() {
        assert_eq!(
            result_artifacts(true, &RecoveryScope::Full, &[]),
            ["p1030680/recovery-result.json", "proof-bundle.tar.gz"]
        );
        assert_eq!(
            result_artifacts(true, &RecoveryScope::GpuOnly, &[]),
            [
                "p1030680/recovery-result.json",
                "p1030680/artifact-probe.json"
            ]
        );
        let proof: Vec<_> = [
            "cargo",
            "xtask",
            "prove",
            "--case",
            "coordinates",
            "--max-seconds",
            "3300",
        ]
        .map(str::to_owned)
        .into();
        assert_eq!(
            result_artifacts(false, &RecoveryScope::Full, &proof),
            ["proof-bundle.tar.gz"]
        );
        assert!(result_artifacts(false, &RecoveryScope::Full, &[]).is_empty());
    }

    #[test]
    fn verification_dispatch_rejects_other_programs_arguments_and_unregistered_proofs() {
        let command: Vec<_> = [
            "cargo",
            "xtask",
            "prove",
            "--case",
            "settle-contract",
            "--max-seconds",
            "3300",
        ]
        .map(str::to_owned)
        .into();
        assert!(proof_command(&command));
        assert_eq!(result_path(false, &command), Some("proof-bundle.tar.gz"));
        for (index, replacement) in [
            (0, "sh"),
            (1, "run"),
            (2, "solve"),
            (3, "--"),
            (4, "unknown-proof"),
            (5, "--gpu"),
            (6, "3601"),
        ] {
            let mut invalid = command.clone();
            invalid[index] = replacement.into();
            assert!(!proof_command(&invalid));
        }
        for length in 0..command.len() {
            assert!(!proof_command(&command[..length]));
        }
        let mut appended = command;
        appended.push("--gpu".into());
        assert!(!proof_command(&appended));
    }

    #[test]
    fn ssh_readiness_requires_authenticated_success_within_its_deadline() {
        let directory = std::env::temp_dir().join(format!(
            "cipher-break-ssh-ready-{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut calls = 0;
        assert!(
            await_ssh_with("cloud", Duration::ZERO, &directory, |_, _| {
                calls += 1;
                unreachable!("an expired deadline must not start authentication")
            })
            .is_err()
        );
        assert_eq!(calls, 0);
        let mut responses = VecDeque::from([(255, false), (0, true), (0, false)]);
        await_ssh_with(
            "cloud",
            Duration::from_secs(10),
            &directory,
            |command, limit| {
                assert_eq!(command.argv.last().unwrap(), "true");
                assert!(command.argv.iter().any(|a| a == "BatchMode=yes"));
                assert!(limit <= Duration::from_secs(10));
                let (exit_code, timed_out) = responses.pop_front().unwrap();
                Ok(Outcome {
                    exit_code,
                    timed_out,
                    seconds: 0.0,
                    stdout: String::new(),
                    stderr: "Permission denied (publickey).".to_owned(),
                })
            },
        )
        .unwrap();
        assert!(responses.is_empty());
        let report = json_read(&directory.join("ssh-ready.json")).unwrap();
        assert_eq!(report["attempts"].as_array().unwrap().len(), 3);
        assert_eq!(report["attempts"][0]["result"]["exit_code"], 255);
        assert_eq!(report["attempts"][1]["result"]["timed_out"], true);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn managed_hosts_preserve_global_includes_and_existing_host_precedence() {
        let existing = "# global\nInclude ~/.orbstack/ssh/config\nHost linux\n  HostName home\nHost *\n  ForwardAgent yes\n";
        let block = "Host cloud\n  ForwardAgent no\n";
        assert_eq!(
            insert_ssh_block(existing, block),
            "# global\nInclude ~/.orbstack/ssh/config\nHost cloud\n  ForwardAgent no\nHost linux\n  HostName home\nHost *\n  ForwardAgent yes\n"
        );
    }

    struct Fake {
        responses: VecDeque<Value>,
        calls: Vec<Vec<String>>,
    }
    impl Api for Fake {
        fn call(&mut self, args: Vec<String>) -> Result<Outcome> {
            self.calls.push(args);
            Ok(Outcome {
                exit_code: 0,
                seconds: 0.0,
                timed_out: false,
                stdout: self
                    .responses
                    .pop_front()
                    .context("unexpected cloud call")?
                    .to_string(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn inactive_billing_or_existing_resources_stop_before_creation() {
        let config = Config::parse(&[], false).unwrap();
        for responses in [
            vec![json!({"lifecycleState": "DELETE_REQUESTED"})],
            vec![
                json!({"lifecycleState": "ACTIVE"}),
                json!({"billingEnabled": false}),
            ],
            vec![
                json!({"lifecycleState": "ACTIVE"}),
                json!({"billingEnabled": true}),
                json!([{"name":"existing"}]),
                json!([]),
            ],
            vec![
                json!({"lifecycleState": "ACTIVE"}),
                json!({"billingEnabled": true}),
                json!([]),
                json!([{"name":"orphan"}]),
            ],
        ] {
            let mut fake = Fake {
                responses: responses.into(),
                calls: Vec::new(),
            };
            assert!(preflight(&mut fake, &config).is_err());
            assert!(!fake.calls.iter().any(|c| c.iter().any(|s| s == "create")));
        }
    }

    #[test]
    fn runtime_machine_and_prices_are_bounded_before_provisioning() {
        for args in [["--hours", "3"], ["--machine", "a3-highgpu-8g"]] {
            assert!(Config::parse(&args.map(str::to_owned), false).is_err());
        }
        let config = Config::parse(&[], false).unwrap();
        let at = OffsetDateTime::parse("2026-10-03T00:00:00Z", &Rfc3339).unwrap();
        let cost = estimate(&config, at).unwrap();
        assert!(
            (cost["maximum_estimated_usd"].as_f64().unwrap() - 2.983_686_944).abs() < 0.000_001
        );
        assert!(estimate(&config, at + time::Duration::days(8)).is_err());
    }

    #[test]
    fn both_gpu_variants_keep_absolute_deletion_and_no_credentials() {
        for machine in ["g2-standard-8", "n1-standard-8"] {
            let config = Config::parse(&["--machine".into(), machine.into()], false).unwrap();
            let args = create_args(
                &config,
                "cb-example",
                "2026-10-03T02:00:00Z",
                Path::new("public metadata.txt"),
            );
            assert!(args.contains(&"--termination-time=2026-10-03T02:00:00Z".into()));
            assert!(args.contains(&"--instance-termination-action=DELETE".into()));
            assert!(args.contains(&"--boot-disk-auto-delete".into()));
            assert!(args.contains(&"--no-service-account".into()));
            assert!(!args.iter().any(|s| s.starts_with("--max-run-duration")));
            assert_eq!(
                args.iter().any(|s| s.starts_with("--accelerator")),
                machine == "n1-standard-8"
            );
            assert!(args.contains(&"--metadata-from-file=ssh-keys=public metadata.txt".into()));
        }
    }

    #[test]
    fn an_ambiguous_failed_create_does_not_allow_a_retry() {
        let mut fake = Fake {
            responses: vec![json!([{"name":"cb-example"}]), json!([])].into(),
            calls: Vec::new(),
        };
        assert!(empty_resources(&mut fake, PROJECT).is_err());
        assert_eq!(fake.calls.len(), 2);
    }

    #[test]
    fn only_verified_cleanup_can_reduce_a_cost_reservation() {
        let mut manifest = json!({"at":"2026-10-03T00:00:00Z", "finished_at":"2026-10-03T00:02:00Z", "instance":{}, "cleanup_verified":false, "reserved_estimate_usd":3.0, "estimate":{"vm_hourly_usd":1.0,"disk_hourly_usd":0.0,"ipv4_hourly_usd":0.0,"other_reserve_usd":1.25,"maximum_estimated_usd":3.0}});
        bound_after_cleanup(&mut manifest).unwrap();
        assert_eq!(manifest["reserved_estimate_usd"], 3.0);
        manifest["cleanup_verified"] = json!(true);
        bound_after_cleanup(&mut manifest).unwrap();
        assert!((manifest["reserved_estimate_usd"].as_f64().unwrap() - 1.3).abs() < 0.000_001);
    }

    #[test]
    fn pilot_counts_all_failed_vm_time_with_one_shared_overhead_reserve() {
        let directory =
            std::env::temp_dir().join(format!("cipher-break-pilot-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        for (id, reserved) in [("failed-1", 1.3), ("failed-2", 1.4), ("no-vm", 0.0)] {
            json_write(&directory.join(id).join("manifest.json"), &json!({"config":{"recovery":true},"reserved_estimate_usd":reserved,"estimate":{"other_reserve_usd":1.25}})).unwrap();
        }
        let compute = recovery_vm_estimates(&directory).unwrap();
        assert!((compute - 0.2).abs() < 0.000_001);
        fs::remove_dir_all(directory).unwrap();
    }
}
