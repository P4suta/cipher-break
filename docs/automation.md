<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Rust automation

Run `mise x -- cargo xtask help` from this checkout.
All maintained repository automation is in the Rust workspace's `xtask` crate.
The Cargo alias, local checks and worker commands build Rust in the release profile on every platform.
The mise tasks retain their names and delegate multi-step work to xtask.
Commands execute structured argument vectors.
The initial cross-platform domyjob installation uses explicit OS shell expressions inside Rust; there are no maintained shell or Python automation files.
The existing cipher CLI and externally supplied scoring functions remain unchanged.

## Local checks and audits

```sh
mise run check
mise x -- cargo xtask p1030680 sources
mise x -- cargo xtask p1030680 audit
```

`check` runs the full suite and hardware recovery on GCP through domyjob, with one VM and an absolute two-hour deletion deadline.
It includes xtask tests, formatting and Clippy alongside the cipher and Haskell checks.
Use `mise run check:quick` for local formatting, lint, xtask tests and CPU recovery; it caps the shared runtime at one minute and build/Rayon concurrency at two.
It requires current native admission proofs; missing, stale, skipped or failed admission evidence blocks the check and subsequent bounded launch.
Use `cargo xtask prove --case NAME` for bounded proof checkpoints and `--case bootstrap` for the required launch decisions.
`mise run check:proofs` verifies every required native result, the Lean theorems, the assessed boundaries and current controlled full hardware recovery.
`cargo xtask prove --verify-search` retains the separate stronger whole-search claim; scoped completion cannot satisfy it.
Use `cargo xtask cloud prove NAME` for longer proof work before complete search evidence exists.
Its fixed command accepts only a registered proof; current native bootstrap receipts and the same bounded local CPU checks are required before provisioning.
It cannot dispatch an arbitrary program, recovery job or ciphertext search.
The [proof record](proofs.md) describes the pinned tools, exact scopes and outstanding obligations.
The complete worker suite is `check:worker`, called on the VM by xtask.
`sources` downloads the cited plaintext pages; it sends no enquiries.
`audit` validates the transcription and literal cribs, repeats the same placement and graph procedure on every shuffle, records previous finishing limits and writes exact proposed job arguments with input and source hashes.
It does not start a rotor search or promote an ineligible hypothesis.
The larger archival source collection is documented separately in the research record.

For an attested conditional crib experiment:

```sh
mise x -- cargo xtask cloud run gpu --standard --hours 2 -- cargo xtask p1030680 campaign --candidate C06 --max-minutes 100
```

`campaign` validates current full recovery, profiles the selected target and shuffle menus on the hardware, and starts only a scope that fits its measured runtime estimate and remaining process window.
The cloud runner requires current full recovery and the exact bounded campaign command before provisioning, and enforces the absolute VM deadline.
The first menu is selected by descending closures and ascending offset separately for each input; every unvisited placement remains queued.
The search excludes the crib from language scoring and never declares a reading from this preliminary experiment.
If only the target fits, the result is `awaiting_control`; submit the same candidate with `--control-only --reuse-recovery` to finish its control.
Reused recovery must include a passing full check and exactly match the current source hashes.
The result preserves profiles, queues, commands and outcomes in `reports/p1030680/campaign-result.json`.
The controller retrieves the campaign report and its current recovery evidence before VM deletion.

`cargo xtask agree` requires both existing implementations to print the committed fixture's IC of `0.0438`.
`cargo xtask bench [--period N]` submits CPU and GPU runtime measurements to GCP through the same bounded runner; a runtime measurement does not declare plaintext.
The cloud controller retrieves the worker's `bench.json` alongside its log under `reports/cloud/RUN_ID/out/`.

## Cloud runs

```sh
mise x -- cargo xtask cloud preflight
mise x -- cargo xtask cloud prove settle-contract --dry-run
mise x -- cargo xtask cloud prove settle-contract
mise x -- cargo xtask cloud run gpu --standard --dry-run --recovery
mise x -- cargo xtask cloud run gpu --standard --recovery
```

The repository defaults to its authorized project, L4/g2-standard-8 and us-central1-a.
Choose T4 with `--machine n1-standard-8` and a reviewed zone with `--zone ZONE`.
CPU jobs use n1-standard-8, which fits the checked eight-CPU quota requirement.
Proof workers use on-demand CPU capacity, one Kani worker, a 300-second harness limit and a 3300-second shared proof-command limit.
The selected proof automatically includes missing contract prerequisites and retains failures in a fetched `proof-bundle.tar.gz` before cleanup.
That artifact keeps its remote model paths and provenance; it does not automatically satisfy the local complete-search gate.
The default provisioning model is Spot; `--standard` requests on-demand capacity.
Both use conservative on-demand prices for the estimate.
`--project ID`, `--hours 1|2`, `--price-file FILE`, and `--ssh-key PUBLIC_KEY` are explicit overrides.

`dry-run` performs no cloud calls, creates no resources, and prints the exact creation arguments and estimate.
The reviewed [regional price snapshot](../data/cloud-prices.json) expires after seven days; update its sources and timestamp before provisioning with stale evidence.
The separate [Northern Virginia snapshot](../data/cloud-prices-us-east4.json) supports `--zone us-east4-a --price-file data/cloud-prices-us-east4.json` when central-region GPU capacity is unavailable.
The owner authorizes use of promotional credits; the superseded initial USD 5/50 ceilings do not block these bounded runs.
Only one VM may run.
A local lock and checks for existing project instances and disks prevent concurrent launches.
Recorded maximum estimates and prior runtime bounds remain available; settled billing is a separate measurement.
Verified deletion permits shortening a VM's runtime bound; failed tests and startup attempts remain in the accounting.
Credit applicability still requires a current Billing Credits observation.

Each invocation makes one zonal creation attempt.
After a failed creation it checks resources and records the outcome before allowing another invocation.
An absolute deletion timestamp survives reboots, and the boot disk deletes with the VM.
The VM has no service account or cloud API scopes.
Its SSH metadata uses an existing public key; private keys remain in the user's SSH agent.
The temporary SSH host entry disables agent forwarding and is removed after cleanup.
Before transferring files, the runner requires an authenticated batch SSH command to succeed within a shared three-minute startup deadline.
The `ssh-ready.json` receipt preserves each probe's arguments, exit status and timeout result; an open port alone does not satisfy this gate.

The runner verifies its pinned domyjob release before creating a VM.
It runs the one-minute local quick check before any paid VM creation, so formatting or lint failures do not consume cloud time.
SSH transfers and installs the checksum-verified prebuilt node on a fresh VM; all subsequent setup, builds, tests and remote commands go through domyjob from this checkout.
Ubuntu packages, a prebuilt NVIDIA kernel module, mise and Rust follow.
Vendor executables are checksum-checked and launched directly; there is no maintained startup script or downloaded shell installer.
The current checkout, including uncommitted files, is sent using domyjob's normal ignore rules.
Full recovery installs the pinned native verifiers as well as project tools and completes the `native` proof group before hardware execution.
The recovery command checks that all four named GPU tests exist and actually execute, then runs `mise run check` on the cloud worker.
Its final source-bound attestation requires the checked boundary assessment, all required proof results and actual controlled hardware recovery.
The controller retrieves the raw proof bundle alongside the recovery record, including after failures.
The wider gate uses six rotor orders, 104 composite reflectors, all middle/right rings, a 64-stop finishing limit and eight identical searches on shuffled input.
It enforces a shared time limit across compilation and test stages.
It stages every requested artifact outside the finished workspace before reading any of them: helper commands admit jobs, and domyjob automatically removes finished jobs older than its newest 32.
The source-bound staging proof covers both files and every staging or reading failure; the native regression also removes the original workspace after the first read.
Artifact bytes use OpenSSH's file transfer rather than domyjob's bounded log tail, with remote byte-count and end-to-end SHA-256 checks before atomic publication.
The existing native SSH configuration and agent supply authentication; remote setup and execution still use domyjob.
The transfer admits files up to 256 MiB, removes failed partial copies and cannot replace a verified result with unverified bytes.
It deletes the VM and checks that its boot disk is gone even after a failed test or fetch.
The provider deadline remains effective if the local controller disconnects.

The final recovery run completed its full source-bound assurance check, all four GPU tests and the complete Rust/Haskell suite.
Both required artifacts were retrieved successfully with the batch-staging implementation before verified VM and disk deletion; [the retained proof record](proofs.md) gives the actual hashes and timing.

`--recovery --gpu-only` reruns the four hardware gates and a large UTF-8 transfer probe without repeating the full Rust/Haskell suite.
Its result is labelled `gpu_passed`, with `full_check_in_this_run: false`; keep the separate full-check evidence.
The transfer probe checks UTF-8 byte preservation and end-to-end verification; finished-workspace eviction is checked separately by the source-bound ordering proof and the native two-artifact regression.

For another authorized job:

```sh
mise x -- cargo xtask cloud run cpu -- cargo test --locked --release
mise x -- cargo xtask cloud run gpu -- cargo xtask cribs LIST MODEL_PATH_OR_GS_URI
mise x -- cargo xtask cloud fetch
mise x -- cargo xtask cloud fetch RUN_ID
mise x -- cargo xtask cloud cleanup RUN_ID
```

The cloud runner waits for the job and saves exact arguments and results in `reports/cloud/RUN_ID/`.
Recovery, campaign, benchmark and crib-batch result JSON files are retrieved with byte-count and SHA-256 verification before deletion.
`fetch RUN_ID --legacy` retrieves an older GCS run without creating a new bucket or VM.
The old crib lists are retained as historical inputs; their presence does not make them evidence-supported candidates.
The `cribs` task preserves per-line arguments, accepts a local or GCS scoring model, and records failed jobs rather than treating them as completed negative searches.
For the documented `cargo xtask cribs LIST gs://...` command, the controller downloads the model, records its URI and SHA-256, and stages it in the snapshot without sending cloud credentials to the VM.

## Generic GCP tooling

```sh
mise x -- cargo xtask gcp setup
mise x -- cargo xtask gcp check --project PROJECT_ID
mise x -- cargo xtask gcp runners
```

`setup` installs Google's version-pinned local gcloud MCP server and backs up the three user configs before changing only their `gcloud` entry.
The clients invoke the absolute Node executable and server bundle directly with a suitable PATH.
The generic skill lives in `~/.agents/skills/gcp`, with a Claude discovery link.
Its instructions contain no repository dependency, fixed project, cryptanalysis procedure or GPU choice.
The skill's CLI/MCP instructions work independently of this checkout.

`check` exercises MCP initialization, tool discovery and an optional read-only project call, then verifies the three client connections and shared skill discovery.
It creates no cloud resources and never prints an access token.
Restart existing Codex, Claude or OpenCode sessions after changing their MCP registration.

`runners` switches the three personal machines to the pinned published domyjob release, preserving previous binaries.
It verifies published checksums, Apple installer notarization and code signing, Windows Authenticode, and the matching node fingerprint on all three machines.
The installed release is v0.0.0 from source revision ef8d23d75001f1104efe13828a5441149b35deb7.
It uses that release's current CLI and prevents automatic source builds on the Mac or cloud worker.
