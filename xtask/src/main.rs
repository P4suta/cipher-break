// SPDX-License-Identifier: MIT OR Apache-2.0

mod audit;
mod bootstrap;
mod cloud;
mod gcp;
mod jobs;
mod process;
mod runner;

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the workspace")
        .to_path_buf()
}

fn main() -> std::process::ExitCode {
    match dispatch(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<()> {
    let (command, rest) = args
        .split_first()
        .map_or(("help", &[][..]), |(a, b)| (a.as_str(), b));
    match command {
        "agree" => jobs::agree(rest),
        "check" => jobs::check(rest),
        "bench" => jobs::bench(rest),
        "cribs" => jobs::cribs(rest),
        "cloud" => cloud::dispatch(rest),
        "gcp" if rest == ["runners"] => runner::install_personal(),
        "gcp" => gcp::dispatch(rest),
        "p1030680" => match rest.split_first().map(|(a, b)| (a.as_str(), b)) {
            Some(("audit", options)) => audit::run(options),
            Some(("sources", options)) => audit::sources(options),
            Some(("model", options)) => audit::model(options),
            Some(("recovery", options)) => jobs::recovery(options),
            _ => bail!("use p1030680 sources, model, audit, or recovery; see cargo xtask help"),
        },
        "help" | "--help" | "-h" => {
            println!(
                "cargo xtask check [--quick]  (full checks run on GCP)\n\
                 cargo xtask agree\n\
                 cargo xtask bench [--period N]\n\
                 cargo xtask cribs LIST [MODEL_PATH_OR_GS_URI]\n\
                 cargo xtask p1030680 sources [--sources DIR]\n\
                 cargo xtask p1030680 model\n\
                 cargo xtask p1030680 audit [--sources DIR] [--output DIR] [--recovery-result FILE]\n\
                 cargo xtask p1030680 recovery [--max-minutes N] [--gpu-only]  (through domyjob on a cloud GPU)\n\
                 cargo xtask cloud preflight [--project ID] [--zone ZONE] [--machine TYPE]\n\
                 cargo xtask cloud run cpu|gpu [--hours 1|2] [--machine TYPE] [--zone ZONE]\n\
                     [--project ID] [--standard] [--price-file FILE] [--ssh-key PUBLIC_KEY]\n\
                     [--dry-run] [--recovery [--gpu-only] | -- COMMAND ARG...]\n\
                 cargo xtask cloud bootstrap SSH_TARGET [--gpu]\n\
                 cargo xtask cloud fetch [RUN_ID] [--legacy]\n\
                 cargo xtask cloud cleanup RUN_ID\n\
                 cargo xtask cloud ls [--project ID]\n\
                 cargo xtask gcp setup\n\
                 cargo xtask gcp runners  (install the pinned release on Mac, Linux, and Windows)\n\
                 cargo xtask gcp check [--project ID]"
            );
            Ok(())
        }
        _ => bail!("unknown task {command}; see cargo xtask help"),
    }
}
