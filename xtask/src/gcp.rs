// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::process::{Cmd, home, json_read, json_write, now, sha};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;
use toml_edit::{Array, DocumentMut, Item, Table, value};

const VERSION: &str = "0.5.3";
const SKILL: &str = include_str!("../assets/gcp/SKILL.md");
const CLIENTS: &str = include_str!("../assets/gcp/references/clients.md");

struct Connection {
    node: PathBuf,
    bundle: PathBuf,
    env: BTreeMap<String, String>,
}

impl Connection {
    fn discover() -> Result<Self> {
        let node = executable("node")?;
        let gcloud = executable("gcloud")?;
        let bundle = home()?
            .join(".local/share/gcloud-mcp/node_modules/@google-cloud/gcloud-mcp/dist/bundle.js");
        let mut paths = vec![
            gcloud.parent().context("gcloud directory")?.to_path_buf(),
            node.parent().context("Node directory")?.to_path_buf(),
        ];
        for path in [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
        ] {
            let path = PathBuf::from(path);
            if path.is_dir() && !paths.contains(&path) {
                paths.push(path);
            }
        }
        Ok(Self {
            node,
            bundle,
            env: BTreeMap::from([
                (
                    "PATH".into(),
                    std::env::join_paths(paths)?.to_string_lossy().into_owned(),
                ),
                ("CLOUDSDK_CORE_DISABLE_PROMPTS".into(), "1".into()),
            ]),
        })
    }

    fn claude(&self) -> Value {
        json!({"type": "stdio", "command": self.node, "args": [self.bundle], "env": self.env})
    }

    fn opencode(&self) -> Value {
        json!({"type": "local", "command": [self.node, self.bundle], "environment": self.env, "enabled": true, "timeout": 30000})
    }
}

fn executable(name: &str) -> Result<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|path| path.join(name))
        .find(|path| path.is_file())
        .with_context(|| format!("{name} is not installed or not on PATH"))?
        .canonicalize()
        .with_context(|| format!("resolve {name}"))
}

pub fn dispatch(args: &[String]) -> Result<()> {
    match args {
        [action] if action == "setup" => setup(),
        [action] if action == "check" => check(None),
        [action, flag, project] if action == "check" && flag == "--project" => check(Some(project)),
        _ => bail!("use gcp setup or gcp check [--project ID]"),
    }
}

#[allow(clippy::too_many_lines)]
fn setup() -> Result<()> {
    let connection = Connection::discover()?;
    let home = home()?;
    let codex_path = home.join(".codex/config.toml");
    let claude_path = home.join(".claude.json");
    let opencode_path = home.join(".config/opencode/opencode.json");
    let codex_original = if codex_path.exists() {
        fs::read_to_string(&codex_path)?
    } else {
        String::new()
    };
    let codex = codex_config(&codex_original, &connection)?;
    let mut claude = read_config(&claude_path)?;
    let mut opencode = read_config(&opencode_path)?;
    ensure!(
        Cmd::new(["opencode", "--version"])
            .checked()?
            .trim()
            .starts_with("1."),
        "this setup supports the installed OpenCode 1.x schema; check major-version documentation before upgrading"
    );
    insert(&mut claude, "mcpServers", connection.claude())?;
    insert(&mut opencode, "mcp", connection.opencode())?;
    let shared = home.join(".agents/skills/gcp");
    let claude_skill = home.join(".claude/skills/gcp");
    if claude_skill.symlink_metadata().is_ok() {
        ensure!(
            fs::read_link(&claude_skill).is_ok_and(|target| target == shared),
            "Claude gcp skill exists at another location; preserve it before replacing the link"
        );
    }
    let install = home.join(".local/share/gcloud-mcp");
    let package = install.join("node_modules/@google-cloud/gcloud-mcp/package.json");
    if !package.exists() || json_read(&package)?["version"] != VERSION {
        let command = Cmd::new([
            "npm",
            "install",
            "--prefix",
            &install.to_string_lossy(),
            "--save-exact",
            "--omit=dev",
            "--no-audit",
            "--no-fund",
            &format!("@google-cloud/gcloud-mcp@{VERSION}"),
        ]);
        command
            .live(Duration::from_secs(600))?
            .require_success(&command)?;
    }
    ensure!(
        connection.bundle.is_file(),
        "MCP server bundle was not installed"
    );
    let backup = home.join(".local/state/gcp-setup").join(format!(
        "xtask-{}",
        time::OffsetDateTime::now_utc().unix_timestamp()
    ));
    for path in [&codex_path, &claude_path, &opencode_path] {
        if path.exists() {
            private_write(
                &backup.join(path.file_name().context("config name")?),
                &fs::read(path)?,
            )?;
        }
    }
    private_write(&codex_path, codex.as_bytes())?;
    private_write(&claude_path, &pretty(&claude)?)?;
    private_write(&opencode_path, &pretty(&opencode)?)?;
    fs::create_dir_all(shared.join("references"))?;
    fs::write(shared.join("SKILL.md"), SKILL)?;
    fs::write(shared.join("references/clients.md"), CLIENTS)?;
    if claude_skill.symlink_metadata().is_err() {
        fs::create_dir_all(claude_skill.parent().context("Claude skills directory")?)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&shared, &claude_skill)?;
        #[cfg(not(unix))]
        bail!("link the shared skill into Claude's skills directory on this platform");
    }
    // Remove only the shell launcher installed by this setup's earlier revision.
    let old = shared.join("scripts/gcloud-mcp.sh");
    let launcher = home.join(".local/bin/gcloud-mcp");
    if fs::read_link(&launcher).is_ok_and(|target| target == old) {
        fs::remove_file(&launcher)?;
    }
    if old.exists() {
        fs::remove_file(&old)?;
    }
    let _ = fs::remove_dir(shared.join("scripts"));
    println!(
        "Installed the generic shared GCP skill and direct Node MCP connections for Codex, Claude Code, and OpenCode.\nPrivate config backups: {}\nRestart existing agent sessions to load their new connections.",
        backup.display()
    );
    Ok(())
}

fn codex_config(original: &str, connection: &Connection) -> Result<String> {
    let mut document: DocumentMut = original.parse()?;
    if document.get("mcp_servers").is_none() {
        document["mcp_servers"] = Item::Table(Table::new());
    }
    ensure!(
        document["mcp_servers"].as_table().is_some(),
        "Codex mcp_servers is not a table"
    );
    let mut server = Table::new();
    server["command"] = value(connection.node.to_string_lossy().into_owned());
    let mut args = Array::new();
    args.push(connection.bundle.to_string_lossy().into_owned());
    server["args"] = value(args);
    let mut env = Table::new();
    for (key, val) in &connection.env {
        env[key] = value(val);
    }
    server["env"] = Item::Table(env);
    document["mcp_servers"]["gcloud"] = Item::Table(server);
    Ok(document.to_string())
}

fn read_config(path: &Path) -> Result<Value> {
    let value = if path.exists() {
        json_read(path)?
    } else {
        json!({})
    };
    ensure!(value.is_object(), "{} is not a JSON object", path.display());
    Ok(value)
}

fn insert(document: &mut Value, key: &str, entry: Value) -> Result<()> {
    let root = document.as_object_mut().context("config object")?;
    let map = root
        .entry(key.to_owned())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .with_context(|| format!("{key} is not a config object"))?;
    map.insert("gcloud".into(), entry);
    Ok(())
}

fn pretty(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let resolved = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::canonicalize(path)?,
        Ok(_) => path.to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => path.to_owned(),
        Err(error) => return Err(error.into()),
    };
    let path = resolved.as_path();
    fs::create_dir_all(path.parent().context("private file directory")?)?;
    let temporary = path.with_extension(format!("xtask-{}", std::process::id()));
    let mut options = File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn check(project: Option<&str>) -> Result<()> {
    let connection = Connection::discover()?;
    ensure!(
        connection.bundle.is_file(),
        "run cargo xtask gcp setup first"
    );
    let directory = crate::root().join("reports/gcp");
    fs::create_dir_all(&directory)?;
    let mut rpc = Rpc::start(&connection, &directory)?;
    let initialized = rpc.request("initialize", &json!({"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "cipher-break-xtask", "version": "0.1.0"}}))?;
    rpc.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
    let tools = rpc.request("tools/list", &json!({}))?;
    ensure!(
        tools["tools"]
            .as_array()
            .context("MCP tools")?
            .iter()
            .any(|t| t["name"] == "run_gcloud_command"
                && t["inputSchema"]["properties"]["args"]["type"] == "array"),
        "unexpected official gcloud MCP tool schema"
    );
    json_write(&directory.join("mcp-tools.json"), &tools)?;
    let call = if let Some(project) = project {
        let call = rpc.request("tools/call", &json!({"name": "run_gcloud_command", "arguments": {"args": ["projects", "describe", project, "--format=json"]}}))?;
        ensure!(
            call["isError"] != true,
            "read-only MCP project call failed: {call}"
        );
        let described: Value = serde_json::from_str(
            call["content"][0]["text"]
                .as_str()
                .context("MCP project description")?,
        )?;
        ensure!(
            described["projectId"] == project,
            "MCP described a different project"
        );
        json_write(&directory.join("mcp-project-check.json"), &call)?;
        Some(call)
    } else {
        None
    };
    let codex = Cmd::new(["codex", "mcp", "get", "gcloud", "--json"]).checked()?;
    let claude = Cmd::new(["claude", "mcp", "get", "gcloud"]).checked()?;
    ensure!(
        claude.contains("Connected"),
        "Claude did not report a connected gcloud server"
    );
    let opencode = Cmd::new(["opencode", "mcp", "list"]).checked()?;
    ensure!(
        opencode
            .lines()
            .any(|line| line.contains("gcloud") && line.contains("connected")),
        "OpenCode did not report a connected gcloud server"
    );
    // OpenCode's debug command can truncate large JSON when stdout is a pipe.
    let skill_list = directory.join("opencode-skills.json");
    let discovery = Cmd::new(["opencode", "debug", "skill"]);
    let skills = discovery.capture_to(&skill_list)?;
    skills.require_success(&discovery)?;
    let discovered: Value =
        serde_json::from_str(&skills.stdout).context("decode OpenCode skill discovery")?;
    ensure!(
        discovered
            .as_array()
            .context("OpenCode skills")?
            .iter()
            .any(|s| s["name"] == "gcp"),
        "OpenCode did not discover the shared GCP skill"
    );
    let codex: Value = serde_json::from_str(&codex).context("decode Codex MCP registration")?;
    let skill = home()?.join(".agents/skills/gcp/SKILL.md");
    ensure!(
        fs::read_to_string(&skill)? == SKILL,
        "shared GCP skill differs from this setup's generic skill"
    );
    json_write(
        &directory.join("tooling-check.json"),
        &json!({
            "at": now()?, "status": "passed", "server": initialized, "project_call": call,
            "codex_registration": codex, "claude_connected": true, "opencode_connected": true,
            "opencode_skill_discovered": true, "skill_sha256": sha(&skill)?,
            "launcher": "Node and bundle arguments directly; no custom shell or Python",
            "active_session_restart_required": true
        }),
    )?;
    println!(
        "Official MCP initialize/list/call and all three client registrations verified.\nGeneric shared GCP skill discovered; existing sessions need a restart."
    );
    Ok(())
}

struct Rpc {
    child: Child,
    input: ChildStdin,
    lines: Receiver<std::io::Result<String>>,
    id: u64,
}

impl Rpc {
    fn start(connection: &Connection, directory: &Path) -> Result<Self> {
        let mut child = Command::new(&connection.node)
            .arg(&connection.bundle)
            .envs(&connection.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(directory.join("mcp-stderr.log"))?)
            .spawn()?;
        let input = child.stdin.take().context("MCP stdin")?;
        let output = child.stdout.take().context("MCP stdout")?;
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            input,
            lines,
            id: 0,
        })
    }

    fn send(&mut self, value: &Value) -> Result<()> {
        serde_json::to_writer(&mut self.input, value)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        Ok(())
    }

    fn request(&mut self, method: &str, params: &Value) -> Result<Value> {
        self.id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params}))?;
        let start = std::time::Instant::now();
        loop {
            let timeout = Duration::from_secs(30)
                .checked_sub(start.elapsed())
                .context("MCP request timed out")?;
            let line = self
                .lines
                .recv_timeout(timeout)
                .context("MCP closed or timed out")??;
            let response: Value = serde_json::from_str(&line).context("invalid MCP stdio JSON")?;
            if response.get("method").is_some() {
                if let Some(id) = response.get("id") {
                    let answer = if response["method"] == "ping" {
                        json!({"jsonrpc":"2.0", "id":id, "result":{}})
                    } else {
                        json!({"jsonrpc":"2.0", "id":id, "error":{"code":-32601,"message":"Method not supported by this verification client"}})
                    };
                    self.send(&answer)?;
                }
                continue;
            }
            if response["id"] != self.id {
                continue;
            }
            ensure!(
                response.get("error").is_none(),
                "MCP {method} failed: {}",
                response["error"]
            );
            return response
                .get("result")
                .cloned()
                .context("MCP response lacks a result");
        }
    }
}

impl Drop for Rpc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> Connection {
        Connection {
            node: "/opt/tools/node".into(),
            bundle: "/home/test/mcp/bundle.js".into(),
            env: BTreeMap::from([("PATH".into(), "/opt/tools:/usr/bin:/bin".into())]),
        }
    }

    #[test]
    fn only_the_gcloud_server_changes_in_existing_client_configs() {
        let original = "# retained\nmodel = 'example'\n[mcp_servers.node_repl]\ncommand = 'node'\nargs = []\n[mcp_servers.gcloud]\ncommand = 'old-wrapper'\n";
        let changed = codex_config(original, &connection()).unwrap();
        assert!(changed.contains("# retained"));
        let document: DocumentMut = changed.parse().unwrap();
        assert_eq!(document["model"].as_str(), Some("example"));
        assert_eq!(
            document["mcp_servers"]["node_repl"]["args"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            document["mcp_servers"]["gcloud"]["command"].as_str(),
            Some("/opt/tools/node")
        );
        for (key, entry) in [
            ("mcpServers", connection().claude()),
            ("mcp", connection().opencode()),
        ] {
            let mut original = json!({"unrelated": [1, 2], key: {"other": {"command": "keep"}, "gcloud": {"command": "old"}}});
            insert(&mut original, key, entry).unwrap();
            assert_eq!(original["unrelated"], json!([1, 2]));
            assert_eq!(original[key]["other"]["command"], "keep");
        }
    }

    #[test]
    fn malformed_config_is_not_silently_replaced() {
        assert!(codex_config("invalid = [", &connection()).is_err());
        assert!(insert(&mut json!({"mcp": []}), "mcp", connection().opencode()).is_err());
    }

    fn directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cipher-break-{name}-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn symlink(target: &Path, link: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(target, link).unwrap();
    }

    #[test]
    fn private_writes_preserve_relative_chained_symlinks_and_reject_broken_links() {
        let directory = directory("private-links");
        let target = directory.join("target.toml");
        fs::write(&target, b"old").unwrap();
        let alias = directory.join("alias.toml");
        let config = directory.join("config.toml");
        symlink(Path::new("target.toml"), &alias);
        symlink(Path::new("alias.toml"), &config);
        private_write(&config, b"new configuration").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new configuration");
        assert_eq!(fs::read_link(&config).unwrap(), Path::new("alias.toml"));
        assert_eq!(fs::read_link(&alias).unwrap(), Path::new("target.toml"));
        let broken = directory.join("broken.toml");
        symlink(Path::new("missing.toml"), &broken);
        assert!(private_write(&broken, b"refused").is_err());
        assert_eq!(fs::read_link(&broken).unwrap(), Path::new("missing.toml"));
        assert!(!directory.join("missing.toml").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn private_write_removes_only_its_owned_failed_temporary_file() {
        let directory = directory("private-write");
        let path = directory.join("new/config.toml");
        private_write(&path, b"complete").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"complete");
        let temporary = path.with_extension(format!("xtask-{}", std::process::id()));
        fs::write(&temporary, b"another owner").unwrap();
        assert!(private_write(&path, b"refused").is_err());
        assert_eq!(fs::read(&temporary).unwrap(), b"another owner");
        assert_eq!(fs::read(&path).unwrap(), b"complete");
        fs::remove_file(&temporary).unwrap();
        let invalid = directory.join("directory.toml");
        fs::create_dir(&invalid).unwrap();
        assert!(private_write(&invalid, b"refused").is_err());
        assert!(invalid.is_dir());
        assert!(
            !invalid
                .with_extension(format!("xtask-{}", std::process::id()))
                .exists()
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
