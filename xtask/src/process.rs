// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Debug, Serialize)]
pub struct Cmd {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Outcome {
    pub exit_code: i32,
    pub seconds: f64,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Cmd {
    pub fn new(args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            argv: args.into_iter().map(Into::into).collect(),
            cwd: crate::root(),
            env: BTreeMap::new(),
        }
    }

    pub fn env(mut self, key: &str, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn capture(&self) -> Result<Outcome> {
        self.execute(Duration::from_secs(300), false, None)
    }

    pub fn capture_to(&self, path: &Path) -> Result<Outcome> {
        self.execute(Duration::from_secs(300), false, Some(path))
    }

    pub fn checked(&self) -> Result<String> {
        let outcome = self.capture()?;
        outcome.require_success(self)?;
        Ok(outcome.stdout)
    }

    pub fn live(&self, limit: Duration) -> Result<Outcome> {
        eprintln!("+ {}", shell(&self.argv));
        self.execute(limit, true, None)
    }

    fn execute(&self, limit: Duration, live: bool, stdout_path: Option<&Path>) -> Result<Outcome> {
        let (program, args) = self.argv.split_first().context("empty command")?;
        let mut command = Command::new(program);
        command.args(args).current_dir(&self.cwd).envs(&self.env);
        command.stdin(Stdio::null()).stderr(Stdio::piped());
        if let Some(path) = stdout_path {
            command.stdout(fs::File::create(path)?);
        } else {
            command.stdout(Stdio::piped());
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let started = Instant::now();
        let mut child = command
            .spawn()
            .with_context(|| format!("start {program}"))?;
        let out = child.stdout.take().map(|pipe| reader(pipe, live, false));
        let err = reader(child.stderr.take().context("stderr pipe")?, live, true);
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= limit {
                timed_out = true;
                // Cargo's test binaries must terminate along with Cargo.
                #[cfg(unix)]
                {
                    let _ = Command::new("/bin/kill")
                        .args(["-KILL", "--", &format!("-{}", child.id())])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                let _ = child.kill();
                break child.wait()?;
            }
            thread::sleep(Duration::from_millis(20));
        };
        Ok(Outcome {
            exit_code: status.code().unwrap_or(-1),
            seconds: started.elapsed().as_secs_f64(),
            timed_out,
            stdout: if let Some(out) = out {
                out.join()
                    .map_err(|_| anyhow::anyhow!("stdout reader panicked"))??
            } else {
                String::from_utf8_lossy(&fs::read(stdout_path.context("stdout file")?)?)
                    .into_owned()
            },
            stderr: err
                .join()
                .map_err(|_| anyhow::anyhow!("stderr reader panicked"))??,
        })
    }
}

impl Outcome {
    pub fn require_success(&self, command: &Cmd) -> Result<()> {
        if self.timed_out {
            bail!("{} exceeded its time limit", shell(&command.argv));
        }
        if self.exit_code != 0 {
            bail!(
                "{} exited {}: {}",
                shell(&command.argv),
                self.exit_code,
                self.stderr.trim()
            );
        }
        Ok(())
    }
}

fn reader(
    mut input: impl Read + Send + 'static,
    live: bool,
    stderr: bool,
) -> thread::JoinHandle<Result<String>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let count = input.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
            if live {
                if stderr {
                    std::io::stderr().write_all(&chunk[..count])?;
                } else {
                    std::io::stdout().write_all(&chunk[..count])?;
                }
            }
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    })
}

pub fn shell(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            shlex::try_quote(arg).map_or_else(|_| format!("{arg:?}"), std::borrow::Cow::into_owned)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn sha(path: &Path) -> Result<String> {
    Ok(hash(
        &fs::read(path).with_context(|| format!("read {}", path.display()))?,
    ))
}

pub fn hash(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("write digest into String");
    }
    output
}

pub fn json_write(path: &Path, value: &impl Serialize) -> Result<()> {
    fs::create_dir_all(path.parent().context("output directory")?)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

pub fn json_read(path: &Path) -> Result<serde_json::Value> {
    serde_json::from_slice(&fs::read(path)?).with_context(|| format!("parse {}", path.display()))
}

pub fn now() -> Result<String> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

pub fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

pub fn option(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_never_shell_expressions() {
        let argument = "$(touch should-not-exist) `id` ; $HOME";
        if std::env::var_os("CB_ARGUMENT_PROBE").is_some() {
            println!("CB_ARGUMENT={}", std::env::args().next_back().unwrap());
            return;
        }
        let executable = std::env::current_exe().unwrap();
        let command = Cmd::new([
            executable.to_str().unwrap(),
            "--exact",
            "process::tests::arguments_are_never_shell_expressions",
            "--nocapture",
            "--skip",
            argument,
        ])
        .env("CB_ARGUMENT_PROBE", "1");
        let output = command.checked().unwrap();
        assert!(output.contains(&format!("CB_ARGUMENT={argument}\n")));
    }

    #[test]
    fn timeout_is_a_failure() {
        if std::env::var_os("CB_TIMEOUT_PROBE").is_some() {
            std::thread::sleep(Duration::from_secs(5));
            return;
        }
        let executable = std::env::current_exe().unwrap();
        let command = Cmd::new([
            executable.to_str().unwrap(),
            "--exact",
            "process::tests::timeout_is_a_failure",
        ])
        .env("CB_TIMEOUT_PROBE", "1");
        let result = command
            .execute(Duration::from_millis(30), false, None)
            .unwrap();
        assert!(result.timed_out);
        assert!(result.require_success(&command).is_err());
    }
}
