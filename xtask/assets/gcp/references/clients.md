# Client configuration

The local server works with existing gcloud user authentication.
It does not require a new OAuth client, Application Default Credentials or a service-account key.
Check the current [Google server documentation](https://github.com/googleapis/gcloud-mcp) before installing or upgrading.
Version 0.5.3 was verified on 2 October 2026.

Install a reviewed version into a shared user directory with npm's exact-version option and retain its package lock:

```sh
npm install --prefix "$HOME/.local/share/gcloud-mcp" --save-exact --omit=dev --no-audit --no-fund @google-cloud/gcloud-mcp@0.5.3
```

Use the environment's tool manager when it pins Node.
Resolve the actual absolute Node executable and `node_modules/@google-cloud/gcloud-mcp/dist/bundle.js` path.
Launch Node directly with the bundle as its argument.
Set the client's server PATH to include gcloud and required system tools, because GUI clients may have a smaller PATH.
Set `CLOUDSDK_CORE_DISABLE_PROMPTS=1` for noninteractive resource operations.
Keep authentication outside MCP and preserve unrelated client settings when updating configuration.

## Codex

Register a user stdio server using `codex mcp add gcloud --env PATH=SERVER_PATH --env CLOUDSDK_CORE_DISABLE_PROMPTS=1 -- NODE_ABSOLUTE_PATH BUNDLE_ABSOLUTE_PATH`.
The connection is `[mcp_servers.gcloud]` in `~/.codex/config.toml`.
Check it with `codex mcp get gcloud` and restart the session to load changes.
Codex discovers the shared skill at `~/.agents/skills/gcp/SKILL.md`.

## Claude Code

Use `claude mcp add --scope user --transport stdio gcloud --env PATH=SERVER_PATH --env CLOUDSDK_CORE_DISABLE_PROMPTS=1 -- NODE_ABSOLUTE_PATH BUNDLE_ABSOLUTE_PATH`.
The connection is `mcpServers.gcloud` in `~/.claude.json` with `command`, `args` and `env`.
Check `claude mcp get gcloud` or `/mcp` in a new session.
Link `~/.claude/skills/gcp` to the shared skill directory if it is not already discovered.

## OpenCode 1.x

Add the server under `mcp.gcloud` in the user config at `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "gcloud": {
      "type": "local",
      "command": ["NODE_ABSOLUTE_PATH", "BUNDLE_ABSOLUTE_PATH"],
      "environment": {"PATH": "SERVER_PATH", "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"},
      "enabled": true,
      "timeout": 30000
    }
  }
}
```

Check `opencode mcp list` and skill discovery with `opencode debug skill`.
OpenCode 1.x supports the shared `~/.agents/skills` location.
Check version-specific documentation before applying this schema to a different major version.

## Verify transport and access

Verify MCP initialization, `tools/list`, and one read-only call through `run_gcloud_command`.
A connected transport does not establish resource-creation permission, GPU capacity or credit applicability.
Keep config backups private; they may contain unrelated credentials.

- [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) and [skills](https://learn.chatgpt.com/docs/build-skills)
- [Claude MCP](https://code.claude.com/docs/en/mcp) and [skills](https://code.claude.com/docs/en/skills)
- [OpenCode MCP](https://opencode.ai/docs/mcp-servers/) and [skills](https://opencode.ai/docs/skills/)
