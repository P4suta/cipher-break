<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Rust automation

Run `mise x -- cargo xtask help` from this checkout.
All maintained repository automation is in the Rust workspace's `xtask` crate.
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

`check` runs the full suite and hardware recovery on GCP through domyjob, within the same single-VM pilot limits.
It includes xtask tests, formatting and Clippy alongside the cipher and Haskell checks.
Use `mise run check:quick` for local formatting, lint, xtask tests and CPU recovery; it caps the shared runtime at one minute and build/Rayon concurrency at two.
The complete worker suite is `check:worker`, called on the VM by xtask.
`sources` downloads the four cited plaintext pages; it sends no enquiries.
`audit` validates the transcription and literal cribs, repeats the same placement and graph procedure on every shuffle, records previous finishing limits and writes exact proposed job arguments with input and source hashes.
It does not start a rotor search or promote an ineligible hypothesis.
The larger archival source collection is documented separately in the research record.

`cargo xtask agree` compares the IC printed by the two existing implementations.
`cargo xtask bench [--period N]` submits CPU and GPU runtime measurements to GCP through the same bounded runner; a runtime measurement does not declare plaintext.
The cloud controller retrieves the worker's `bench.json` alongside its log under `reports/cloud/RUN_ID/out/`.

## Cloud runs

```sh
mise x -- cargo xtask cloud preflight
mise x -- cargo xtask cloud run gpu --standard --dry-run --recovery
mise x -- cargo xtask cloud run gpu --standard --recovery
```

The repository defaults to its authorized project, L4/g2-standard-8 and us-central1-a.
Choose T4 with `--machine n1-standard-8` and a reviewed zone with `--zone ZONE`.
CPU jobs use n1-standard-8, which fits the checked eight-CPU quota requirement.
The default provisioning model is Spot; `--standard` requests on-demand capacity.
Both use conservative on-demand prices for the estimate.
`--project ID`, `--hours 1|2`, `--price-file FILE`, and `--ssh-key PUBLIC_KEY` are explicit overrides.

`dry-run` performs no cloud calls, creates no resources, and prints the exact creation arguments and estimate.
The reviewed [regional price snapshot](../data/cloud-prices.json) expires after seven days; update its sources and timestamp before provisioning with stale evidence.
The current pilot ceiling is USD 5, the campaign ceiling is USD 50, and only one VM may run.
A local lock and checks for existing project instances and disks prevent concurrent launches.
Recorded maximum estimates reserve campaign capacity conservatively; settled billing is a separate measurement.
For the USD 5 recovery pilot, the runner adds every previous VM runtime bound to the proposed run and reserves USD 1.25 once for the entire pilot's transfer and tax costs.
Verified deletion permits shortening a VM's runtime bound; a failed test or startup is still charged to the pilot.
Credit applicability still requires a current Billing Credits observation.

Each invocation makes one zonal creation attempt.
After a failed creation it checks resources and records the outcome before allowing another invocation.
An absolute deletion timestamp survives reboots, and the boot disk deletes with the VM.
The VM has no service account or cloud API scopes.
Its SSH metadata uses an existing public key; private keys remain in the user's SSH agent.
The temporary SSH host entry disables agent forwarding and is removed after cleanup.

The runner verifies its pinned domyjob release before creating a VM.
It runs the one-minute local quick check before any paid VM creation, so formatting or lint failures do not consume cloud time.
SSH transfers and installs the checksum-verified prebuilt node on a fresh VM; all subsequent setup, builds, tests and remote commands go through domyjob from this checkout.
Ubuntu packages, a prebuilt NVIDIA kernel module, mise and Rust follow.
Vendor executables are checksum-checked and launched directly; there is no maintained startup script or downloaded shell installer.
The current checkout, including uncommitted files, is sent using domyjob's normal ignore rules.
The recovery command installs the pinned project tools, checks that all three named GPU tests exist and actually execute, then runs `mise run check` on the cloud worker.
It enforces a shared time limit across compilation and test stages.
It fetches the result in small byte chunks with an end-to-end SHA-256 check, so domyjob's bounded log tail cannot silently truncate an artifact.
It first copies the artifact outside the finished workspace: each remote read is a new job, and domyjob automatically removes finished jobs older than its newest 32.
Failed transfers retain a local `.partial` file and cannot replace a verified result.
It deletes the VM and checks that its boot disk is gone even after a failed test or fetch.
The provider deadline remains effective if the local controller disconnects.

`--recovery --gpu-only` reruns the three hardware gates and a large UTF-8 transfer probe without repeating the full Rust/Haskell suite.
Its result is labelled `gpu_passed`, with `full_check_in_this_run: false`; keep the separate full-check evidence.
The transfer probe requires more than 32 read jobs, so it exercises finished-workspace eviction as well as byte-count and SHA-256 verification.

For another authorized job:

```sh
mise x -- cargo xtask cloud run cpu -- cargo test --locked --release
mise x -- cargo xtask cloud run gpu -- cargo xtask cribs LIST MODEL_PATH_OR_GS_URI
mise x -- cargo xtask cloud fetch
mise x -- cargo xtask cloud fetch RUN_ID
mise x -- cargo xtask cloud cleanup RUN_ID
```

The cloud runner waits for the job and saves exact arguments and results in `reports/cloud/RUN_ID/`.
Recovery, benchmark and crib-batch result JSON files are retrieved with byte-count and SHA-256 verification before deletion.
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
