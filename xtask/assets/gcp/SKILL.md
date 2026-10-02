---
name: gcp
description: Operate Google Cloud through the official gcloud CLI or Google's published gcloud MCP server, and configure or diagnose these tools in Codex, Claude Code, and OpenCode.
---

# Google Cloud

Use `gcloud` for reproducible commands and the `gcloud` MCP connection when a tool interface helps.
The local server is Google's published `@google-cloud/gcloud-mcp` preview solution.
It uses the active gcloud account and that account's IAM permissions.

## Establish context

Resolve the project and resource location from the request or repository configuration.
Pass `--project=PROJECT_ID` and applicable `--region` or `--zone` flags explicitly.
Keep global gcloud defaults unchanged unless changing them is part of the request.

Start with the relevant read-only checks:

```sh
gcloud version
gcloud auth list --filter=status:ACTIVE --format='value(account)'
gcloud projects describe PROJECT_ID --format=json
gcloud billing projects describe PROJECT_ID --format=json
```

Reuse existing authentication.
If user login is missing or expired, use interactive `gcloud auth login`.
Application Default Credentials are a separate SDK flow; they are not needed just to use this CLI or local MCP.
Do not print access tokens, copy credential databases, or create service-account keys for ordinary CLI/MCP use.
Apply the user's existing authorization to project restoration, billing changes and resource operations without asking again for an already authorized step.

## Choose the interface

Discover the actual MCP tool schema before calling it.
The verified local server accepts `run_gcloud_command` with an `args` array without the leading `gcloud`, for example `{"args": ["projects", "describe", "PROJECT_ID", "--format=json"]}`.
Use the same explicit resource flags as with the CLI.
Some interactive and SSH commands are intentionally denied; use the CLI or the applicable remote-machine workflow without weakening the server's restrictions.
Keep argument vectors and resource names when operations must be replayable.
Prefer structured arguments and payload files over generated shell expressions.

Read [references/clients.md](references/clients.md) for installation, client configuration, reconnection or upgrades.
Clients can launch Node and the server bundle directly; no custom shell launcher is required.

## Paid and temporary resources

Reuse the user's stated spending ceiling, runtime and concurrency limits.
Check current regional prices and quotas before starting paid work, including disks, external IP, storage and expected egress.
Select the machine and accelerator for the workload and available capacity rather than fixing a GPU model in this skill.
Quota availability does not establish zone capacity.
A billing-budget notification is not a hard spending cap.
When promotional credits matter, confirm status, expiry and applicable usage in Billing Credits; `billingEnabled` does not prove credit coverage.
Some credit details still require the console.

For temporary VMs, set deletion behavior and boot-disk auto-delete at creation.
`--termination-time=RFC3339_TIMESTAMP` sets an absolute deadline across restarts.
`--max-run-duration=DURATION` is relative to the last start; it is mutually exclusive with the absolute deadline.
After a failed create, check for the VM and its disk before retrying.
Remove the exact temporary resources at completion and verify deletion.
Report estimates separately from settled billing.

## Primary references

- [gcloud CLI](https://docs.cloud.google.com/sdk/docs)
- [Google's local gcloud MCP](https://github.com/googleapis/gcloud-mcp)
- [Remote Cloud CLI MCP](https://docs.cloud.google.com/sdk/use-gcloud-mcp), which has separate API, IAM and OAuth setup.
- [VM runtime limits](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime)
