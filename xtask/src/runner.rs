// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::process::{Cmd, home, json_read, json_write, now, sha};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const RELEASE: &str = "v0.0.0";
const LINUX: &str = "domyjob-0.0.0-x86_64-unknown-linux-gnu";
const WINDOWS: &str = "domyjob-0.0.0-x86_64-pc-windows-msvc";
const MAC_SHA: &str = "24a551a961cfa8b7348df385d5e81205663cd5cb121ea5d3ff3e2ff0104c782c";
const LINUX_SHA: &str = "3dc8d25827ce2dd37a64acc5e6b04841e611915f9b16c4e4135873652a38ff6c";
const WINDOWS_SHA: &str = "9b675a0ef0af25ce5a37ce1c70a683e24f18cad4d1d2a55aeed7b1a191274cd8";
const MAC_PACKAGE: &str = "domyjob-0.0.0-aarch64-apple-darwin.pkg";
const MAC_PACKAGE_SHA: &str = "5071ce0e793c582a0d0e21289c60cfac8e7bcbc40c9b6240311f0f142124df23";

fn directory() -> PathBuf {
    crate::root().join("reports/p1030680/domyjob-release")
}

fn mac() -> PathBuf {
    directory().join("mac-expanded/payload.pkg/Payload/Library/domyjob/bin/domyjob")
}

fn fetch_release() -> Result<()> {
    fs::create_dir_all(directory())?;
    for (name, digest) in [
        (MAC_PACKAGE.to_owned(), MAC_PACKAGE_SHA),
        (format!("{LINUX}.tar.gz"), LINUX_SHA),
        (format!("{WINDOWS}.tar.gz"), WINDOWS_SHA),
    ] {
        let path = directory().join(&name);
        if !path.exists() {
            Cmd::new([
                "gh",
                "release",
                "download",
                RELEASE,
                "--repo",
                "P4suta/domyjob",
                "--pattern",
                &name,
                "--dir",
                &directory().to_string_lossy(),
            ])
            .checked()?;
        }
        ensure!(
            sha(&path)? == digest,
            "official release digest mismatch: {name}"
        );
    }
    let package = directory().join(MAC_PACKAGE);
    let signature =
        Cmd::new(["pkgutil", "--check-signature", &package.to_string_lossy()]).checked()?;
    ensure!(
        signature.contains("Notarization: trusted by the Apple notary")
            && signature.contains("Developer ID Installer: Yasunobu Sakashita (XMBQLW82L9)"),
        "Mac release is not the expected notarized installer"
    );
    if !mac().exists() {
        Cmd::new([
            "pkgutil",
            "--expand-full",
            &package.to_string_lossy(),
            &directory().join("mac-expanded").to_string_lossy(),
        ])
        .checked()?;
    }
    Ok(())
}

fn hello(binary: &Path) -> Result<String> {
    let mut child = Command::new(binary)
        .arg("node")
        .env("DOMYJOB_STATE", directory().join("probe-state"))
        .env("DOMYJOB_REFRESH", "never")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let request = br#"{"request":"hello"}"#;
    let mut input = child.stdin.take().context("node input")?;
    input.write_all(&u32::try_from(request.len())?.to_be_bytes())?;
    input.write_all(request)?;
    drop(input);
    let output = child.wait_with_output()?;
    ensure!(output.status.success(), "release node hello failed");
    let mut stream = output.stdout.as_slice();
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    ensure!(
        usize::try_from(u32::from_be_bytes(length))? == stream.len(),
        "invalid node frame"
    );
    let reply: Value = serde_json::from_slice(stream)?;
    ensure!(reply["reply"] == "hello", "node did not return hello");
    Ok(format!(
        "{:016x}",
        reply["body"]["build"]
            .as_u64()
            .context("build fingerprint")?
    ))
}

pub fn local_ready() -> Result<Value> {
    let path = home()?.join(".cargo/bin/domyjob");
    ensure!(
        sha(&path)? == MAC_SHA,
        "install the pinned domyjob release with cargo xtask gcp runners before creating a VM"
    );
    let manifest = json_read(&directory().join("installation.json"))?;
    ensure!(
        manifest["status"] == "passed",
        "domyjob release installation has not passed verification"
    );
    let binary = directory().join(LINUX).join("domyjob");
    ensure!(
        sha(&binary)?
            == manifest["linux_binary_sha256"]
                .as_str()
                .context("Linux binary checksum")?,
        "cached Linux release changed"
    );
    Ok(manifest)
}

pub fn command(args: impl IntoIterator<Item = impl Into<String>>) -> Cmd {
    let mut command = Cmd::new(["mise", "x", "--", "domyjob"]).env("DOMYJOB_REFRESH", "never");
    command.argv.extend(args.into_iter().map(Into::into));
    command
}

pub fn remote(target: &str, args: impl IntoIterator<Item = impl Into<String>>) -> Cmd {
    let mut command = command(["on", target, "--wait", "--"]);
    command.argv.extend(args.into_iter().map(Into::into));
    command
}

pub fn output(text: &str) -> Result<&str> {
    let (reference, rest) = text.split_once('\n').context("domyjob job reference")?;
    let (state, log) = rest.split_once('\n').context("domyjob job state")?;
    ensure!(
        state.starts_with(&format!("{reference} finished ")),
        "domyjob on did not finish"
    );
    Ok(log)
}

pub fn checked(target: &str, args: impl IntoIterator<Item = impl Into<String>>) -> Result<String> {
    Ok(output(&remote(target, args).checked()?)?.to_owned())
}

// domyjob retains a bounded log tail, so large artifacts need small, checked chunks.
pub fn read_file(target: &str, path: &str, destination: &Path) -> Result<()> {
    // Each on command admits another job and can evict the original finished workspace.
    let temporary = checked(
        target,
        ["mktemp", "-d", "-t", "cipher-break-artifact.XXXXXXXX"],
    )?;
    let temporary = temporary.trim();
    ensure!(
        temporary.starts_with("/tmp/cipher-break-artifact.") && !temporary.contains(['\n', '\r']),
        "unexpected remote artifact directory"
    );
    let staged = format!("{temporary}/artifact");
    let copied = checked(target, ["cp", "--", path, &staged]);
    let result = copied.and_then(|_| read_staged_file(target, &staged, destination));
    let cleanup = checked(target, ["rm", "-f", "--", &staged])
        .and_then(|_| checked(target, ["rmdir", "--", temporary]));
    result?;
    cleanup?;
    Ok(())
}

fn read_staged_file(target: &str, path: &str, destination: &Path) -> Result<()> {
    let length = checked(target, ["wc", "-c", "--", path])?
        .split_whitespace()
        .next()
        .context("remote artifact length")?
        .parse::<usize>()?;
    ensure!(
        length <= 4 * 1024 * 1024,
        "remote artifact exceeds four MiB"
    );
    let digest = checked(target, ["sha256sum", "--", path])?
        .split_whitespace()
        .next()
        .context("remote artifact digest")?
        .to_owned();
    let partial = destination.with_extension("partial");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    let mut bytes = Vec::with_capacity(length);
    for offset in (0..length).step_by(4096) {
        let expected = (length - offset).min(4096);
        let hex = checked(
            target,
            [
                "od",
                "-An",
                "-v",
                "-tx1",
                "-N",
                &expected.to_string(),
                "-j",
                &offset.to_string(),
                "--",
                path,
            ],
        )?;
        let chunk = hex_chunk(&hex, expected)?;
        file.write_all(&chunk)?;
        bytes.extend(chunk);
    }
    ensure!(
        crate::process::hash(&bytes) == digest,
        "remote artifact changed or was truncated during transfer"
    );
    file.sync_all()?;
    fs::rename(partial, destination)?;
    Ok(())
}

fn hex_chunk(hex: &str, expected: usize) -> Result<Vec<u8>> {
    let bytes = hex
        .split_whitespace()
        .map(|word| {
            ensure!(word.len() == 2, "invalid artifact hex byte");
            Ok(u8::from_str_radix(word, 16)?)
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        bytes.len() == expected,
        "remote artifact chunk is truncated"
    );
    Ok(bytes)
}

// SSH transfers only the verified prebuilt node before domyjob exists on a new VM.
// All subsequent commands and jobs run through domyjob.
pub fn install_node(target: &str, records: &Path) -> Result<()> {
    let release = local_ready()?;
    ensure!(
        target
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')),
        "invalid SSH alias"
    );
    let binary = directory().join(LINUX).join("domyjob");
    let transfer = Cmd::new([
        "scp",
        "-O",
        "-v",
        "-o",
        "BatchMode=yes",
        &binary.to_string_lossy(),
        &format!("{target}:.domyjob-release-upload"),
    ]);
    let outcome = transfer.live(Duration::from_secs(120))?;
    json_write(
        &records.join("domyjob-transfer.json"),
        &json!({"command": transfer, "result": outcome}),
    )?;
    outcome.require_success(&transfer)?;
    let tag = release["build"].as_str().context("release build")?;
    ensure!(
        tag.len() == 16 && tag.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid release build"
    );
    let install = format!(
        "set -eu; p=\"$HOME/.cargo/domyjob/versions/{tag}/bin\"; mkdir -p \"$p\"; chmod 755 \"$HOME/.domyjob-release-upload\"; mv \"$HOME/.domyjob-release-upload\" \"$p/domyjob\""
    );
    Cmd::new(["ssh", "-T", "-o", "BatchMode=yes", target, &install]).checked()?;
    let result = command(["doctor", target]).checked()?;
    json_write(
        &records.join("domyjob-release.json"),
        &json!({"release": release, "doctor": result}),
    )
}

#[allow(clippy::too_many_lines)]
pub fn install_personal() -> Result<()> {
    fetch_release()?;
    ensure!(
        sha(&mac())? == MAC_SHA,
        "Mac release binary checksum mismatch"
    );
    Cmd::new(["codesign", "--verify", "--strict", &mac().to_string_lossy()]).checked()?;
    for (name, hash) in [(LINUX, LINUX_SHA), (WINDOWS, WINDOWS_SHA)] {
        let archive = directory().join(format!("{name}.tar.gz"));
        ensure!(
            sha(&archive)? == hash,
            "release archive checksum mismatch: {name}"
        );
        if !directory().join(name).exists() {
            Cmd::new([
                "tar",
                "-xzf",
                &archive.to_string_lossy(),
                "-C",
                &directory().to_string_lossy(),
            ])
            .checked()?;
        }
    }
    let tag = hello(&mac())?;
    let previous = home()?.join(".cargo/bin/domyjob");
    let backup = home()?.join(".local/state/cipher-break/domyjob-before-release");
    fs::create_dir_all(backup.parent().context("backup directory")?)?;
    if !backup.exists() {
        fs::copy(&previous, &backup)?;
    }
    let legacy = |target: &str, argv: &[String]| {
        let mut command = Cmd::new([
            backup.to_string_lossy().into_owned(),
            "on".into(),
            target.into(),
            "--".into(),
        ]);
        command.argv.extend_from_slice(argv);
        command
    };
    let linux_script = format!(
        "set -eu; work=\"$HOME/.cache/domyjob/release-{RELEASE}\"; mkdir -p \"$work\"; curl -fLsS https://github.com/P4suta/domyjob/releases/download/{RELEASE}/{LINUX}.tar.gz -o \"$work/release.tar.gz\"; actual=$(sha256sum \"$work/release.tar.gz\"); test \"${{actual%% *}}\" = {LINUX_SHA}; tar -xzf \"$work/release.tar.gz\" -C \"$work\"; p=\"$HOME/.cargo/domyjob/versions/{tag}/bin\"; mkdir -p \"$p\" \"$HOME/.cargo/bin\"; install -m 755 \"$work/{LINUX}/domyjob\" \"$p/domyjob\"; if [ -f \"$HOME/.cargo/bin/domyjob\" ] && [ ! -f \"$work/domyjob.previous\" ]; then cp \"$HOME/.cargo/bin/domyjob\" \"$work/domyjob.previous\"; fi; install -m 755 \"$work/{LINUX}/domyjob\" \"$HOME/.cargo/bin/domyjob\"; sha256sum \"$HOME/.cargo/bin/domyjob\""
    );
    let linux = legacy("linux", &["/bin/bash".into(), "-lc".into(), linux_script])
        .live(Duration::from_secs(180))?;
    ensure!(
        linux.exit_code == 0,
        "Linux release installation failed: {}",
        linux.stderr
    );
    let windows_script = format!(
        "$ErrorActionPreference='Stop'; $work=Join-Path $env:LOCALAPPDATA 'domyjob\\release-{RELEASE}'; $null=New-Item -ItemType Directory -Force $work; $archive=Join-Path $work 'release.tar.gz'; Invoke-WebRequest 'https://github.com/P4suta/domyjob/releases/download/{RELEASE}/{WINDOWS}.tar.gz' -OutFile $archive; if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLower() -ne '{WINDOWS_SHA}') {{ throw 'archive checksum mismatch' }}; tar.exe -xzf $archive -C $work; if ($LASTEXITCODE -ne 0) {{ throw 'archive extraction failed' }}; $binary=Join-Path $work '{WINDOWS}\\domyjob.exe'; $signature=Get-AuthenticodeSignature $binary; if ($signature.Status -ne 'Valid') {{ throw 'Authenticode signature is not valid' }}; $node=Join-Path $env:USERPROFILE '.cargo\\domyjob\\versions\\{tag}\\bin'; $null=New-Item -ItemType Directory -Force $node; Copy-Item $binary (Join-Path $node 'domyjob.exe') -Force; $cli=Join-Path $env:USERPROFILE '.cargo\\bin\\domyjob.exe'; $old=Join-Path $work 'domyjob.previous.exe'; if ((Test-Path $cli) -and !(Test-Path $old)) {{ Move-Item $cli $old }}; Copy-Item $binary $cli -Force; (Get-FileHash $cli -Algorithm SHA256).Hash; $signature.SignerCertificate.Subject"
    );
    let windows = legacy(
        "win",
        &[
            "powershell.exe".into(),
            "-NoProfile".into(),
            "-Command".into(),
            windows_script,
        ],
    )
    .live(Duration::from_secs(180))?;
    ensure!(
        windows.exit_code == 0,
        "Windows release installation failed: {}",
        windows.stderr
    );
    let node = home()?
        .join(".cargo/domyjob/versions")
        .join(&tag)
        .join("bin");
    fs::create_dir_all(&node)?;
    fs::copy(mac(), node.join("domyjob"))?;
    let staged = previous.with_extension("release-new");
    fs::copy(mac(), &staged)?;
    fs::rename(staged, &previous)?;
    let mut doctors = Vec::new();
    for target in ["localhost", "linux", "win"] {
        doctors.push(json!({"machine": target, "result": command(["doctor", target]).checked()?}));
    }
    let manifest = json!({"status": "passed", "release": RELEASE, "source_sha": "ef8d23d75001f1104efe13828a5441149b35deb7", "build": tag, "finished_at": now()?, "mac_binary_sha256": MAC_SHA, "linux_binary_sha256": sha(&directory().join(LINUX).join("domyjob"))?, "windows_binary_sha256": sha(&directory().join(WINDOWS).join("domyjob.exe"))?, "linux_install": linux, "windows_install": windows, "doctors": doctors});
    json_write(&directory().join("installation.json"), &manifest)?;
    println!("domyjob release {RELEASE} verified on Mac, Linux, and Windows.");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn artifact_chunks_preserve_bytes_and_reject_truncation() {
        assert_eq!(
            super::hex_chunk(" e3 81 82 00 ff\n", 5).unwrap(),
            [0xe3, 0x81, 0x82, 0, 255]
        );
        assert!(super::hex_chunk("e3 81", 3).is_err());
        assert!(super::hex_chunk("earlier log bytes omitted", 4).is_err());
    }

    #[test]
    fn remote_output_requires_a_finished_job_header() {
        assert_eq!(
            super::output("vm:abcd\nvm:abcd finished succeeded\nLinux\n").unwrap(),
            "Linux\n"
        );
        assert!(super::output("vm:abcd\nvm:abcd running\n").is_err());
        assert!(super::output("vm:abcd\nother:abcd finished succeeded\n").is_err());
    }
}
