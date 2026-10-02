// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::process::{Cmd, Outcome, json_write, now};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

const MISE_VERSION: &str = "2026.9.15";
const RUST_VERSION: &str = "1.98.1";

pub fn remote(target: &str, args: impl IntoIterator<Item = impl Into<String>>) -> Cmd {
    crate::runner::remote(target, args)
}

pub fn dispatch(args: &[String]) -> Result<()> {
    let (target, rest) = args
        .split_first()
        .context("use cloud bootstrap SSH_TARGET [--gpu]")?;
    ensure!(
        rest.is_empty() || rest == ["--gpu"],
        "use cloud bootstrap SSH_TARGET [--gpu]"
    );
    setup(
        target,
        !rest.is_empty(),
        &crate::root().join("reports/cloud-bootstrap"),
    )
}

pub fn setup(target: &str, gpu: bool, directory: &Path) -> Result<()> {
    ensure!(
        !target.is_empty()
            && target
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'@')),
        "give one explicit SSH host alias"
    );
    let mut records = Vec::new();
    crate::runner::install_node(target, directory)?;
    ensure!(
        execute(&remote(target, ["uname", "-s"]), directory, &mut records)?
            .stdout
            .trim()
            == "Linux",
        "bootstrap requires Linux"
    );
    ensure!(
        execute(&remote(target, ["uname", "-m"]), directory, &mut records)?
            .stdout
            .trim()
            == "x86_64",
        "bootstrap requires x86_64"
    );
    let home = execute(
        &remote(target, ["printenv", "HOME"]),
        directory,
        &mut records,
    )?
    .stdout
    .trim()
    .to_owned();
    ensure!(
        home.starts_with('/') && !home.contains(['\n', '\r']),
        "invalid remote home path"
    );
    execute(
        &remote(target, ["sudo", "apt-get", "update", "-qq"]),
        directory,
        &mut records,
    )?;
    let mut packages = vec![
        "sudo",
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        "build-essential",
        "pkg-config",
        "curl",
        "ca-certificates",
        "git",
        "libffi-dev",
        "libgmp-dev",
        "libncurses-dev",
        "libtinfo6",
        "xz-utils",
        "zstd",
    ];
    if gpu {
        packages.extend(["libvulkan1", "vulkan-tools"]);
    }
    execute(&remote(target, packages), directory, &mut records)?;
    if gpu {
        driver(target, directory, &mut records)?;
    }
    tools(target, &home, directory, &mut records)?;
    json_write(
        &directory.join("bootstrap.json"),
        &json!({"status": "passed", "target": target, "gpu": gpu, "finished_at": now()?, "commands": records}),
    )
}

fn execute(command: &Cmd, directory: &Path, records: &mut Vec<Value>) -> Result<Outcome> {
    let mut outcome = command.live(Duration::from_secs(600))?;
    records.push(json!({"command": command, "result": outcome}));
    json_write(
        &directory.join("bootstrap.json"),
        &json!({"status": "running", "commands": records}),
    )?;
    outcome.require_success(command)?;
    outcome.stdout = crate::runner::output(&outcome.stdout)?.to_owned();
    Ok(outcome)
}

fn driver(target: &str, directory: &Path, records: &mut Vec<Value>) -> Result<()> {
    let kernel = execute(&remote(target, ["uname", "-r"]), directory, records)?
        .stdout
        .trim()
        .to_owned();
    ensure!(
        !kernel.is_empty()
            && kernel
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_')),
        "invalid kernel version"
    );
    let mut selected = None;
    for branch in [
        "580-server-open",
        "580-open",
        "570-server-open",
        "570-open",
        "550-server",
        "550",
    ] {
        let module = format!("linux-modules-nvidia-{branch}-{kernel}");
        let probe = remote(target, ["apt-cache", "show", &module]);
        let outcome = probe.capture()?;
        records.push(json!({"command": probe, "result": outcome}));
        if outcome.exit_code == 0 && !crate::runner::output(&outcome.stdout)?.trim().is_empty() {
            selected = Some((module, format!("nvidia-driver-{branch}")));
            break;
        }
    }
    let (module, package) = selected.context(
        "no prebuilt NVIDIA module for this kernel; inspect before installing a different driver",
    )?;
    execute(
        &remote(
            target,
            [
                "sudo",
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                &module,
                &package,
            ],
        ),
        directory,
        records,
    )?;
    execute(
        &remote(target, ["sudo", "modprobe", "nvidia"]),
        directory,
        records,
    )?;
    execute(&remote(target, ["nvidia-smi"]), directory, records)?;
    let summary = execute(
        &remote(target, ["vulkaninfo", "--summary"]),
        directory,
        records,
    )?;
    ensure!(
        summary.stdout.contains("NVIDIA"),
        "Vulkan did not report an NVIDIA hardware device"
    );
    Ok(())
}

fn tools(target: &str, home: &str, directory: &Path, records: &mut Vec<Value>) -> Result<()> {
    let cache = format!("{home}/.cache/cipher-break/bootstrap");
    let bin = format!("{home}/.local/bin");
    execute(
        &remote(target, ["mkdir", "-p", &cache, &bin]),
        directory,
        records,
    )?;
    let mise_name = format!("mise-v{MISE_VERSION}-linux-x64");
    let base = format!("https://github.com/jdx/mise/releases/download/v{MISE_VERSION}");
    let checksums = execute(
        &remote(
            target,
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                &format!("{base}/SHASUMS256.txt"),
            ],
        ),
        directory,
        records,
    )?
    .stdout;
    let expected = checksums
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let hash = parts.next()?;
            (parts
                .next()?
                .trim_start_matches('*')
                .trim_start_matches("./")
                == mise_name)
                .then_some(hash)
        })
        .context("mise release checksum is missing")?;
    let mise = format!("{cache}/{mise_name}");
    download(
        target,
        &format!("{base}/{mise_name}"),
        &mise,
        directory,
        records,
    )?;
    verify(target, &mise, expected, directory, records)?;
    execute(
        &remote(
            target,
            ["install", "-m", "755", &mise, &format!("{bin}/mise")],
        ),
        directory,
        records,
    )?;

    install_rust(target, home, &cache, directory, records)?;
    execute(
        &remote(target, [&format!("{bin}/mise"), "--version"]),
        directory,
        records,
    )?;
    execute(
        &remote(target, [&format!("{home}/.cargo/bin/rustc"), "--version"]),
        directory,
        records,
    )?;
    Ok(())
}

fn install_rust(
    target: &str,
    home: &str,
    cache: &str,
    directory: &Path,
    records: &mut Vec<Value>,
) -> Result<()> {
    let rustup_url =
        "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init";
    let expected = execute(
        &remote(
            target,
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                &format!("{rustup_url}.sha256"),
            ],
        ),
        directory,
        records,
    )?
    .stdout;
    let rustup = format!("{cache}/rustup-init");
    download(target, rustup_url, &rustup, directory, records)?;
    verify(
        target,
        &rustup,
        expected
            .split_whitespace()
            .next()
            .context("rustup checksum is missing")?,
        directory,
        records,
    )?;
    execute(
        &remote(target, ["chmod", "755", &rustup]),
        directory,
        records,
    )?;
    execute(
        &remote(
            target,
            [
                &rustup,
                "-y",
                "--profile",
                "minimal",
                "--default-toolchain",
                RUST_VERSION,
            ],
        ),
        directory,
        records,
    )?;
    ensure!(
        home.starts_with('/'),
        "remote Rust user home must be absolute"
    );
    Ok(())
}

fn download(
    target: &str,
    url: &str,
    path: &str,
    directory: &Path,
    records: &mut Vec<Value>,
) -> Result<()> {
    execute(
        &remote(
            target,
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--output",
                path,
                url,
            ],
        ),
        directory,
        records,
    )?;
    Ok(())
}

fn verify(
    target: &str,
    path: &str,
    expected: &str,
    directory: &Path,
    records: &mut Vec<Value>,
) -> Result<()> {
    ensure!(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid vendor checksum"
    );
    let actual = execute(&remote(target, ["sha256sum", path]), directory, records)?.stdout;
    ensure!(
        actual.split_whitespace().next() == Some(expected),
        "vendor checksum mismatch for {path}"
    );
    Ok(())
}
