<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Required proofs and remaining obligations

Every implementation change requires a checked assurance assessment.
Source-bound machine-checked proofs are required wherever the verifier can establish the affected deterministic property.
Genuine semantic or empirical boundaries require justified, current alternatives with explicit limits and reconsideration conditions; a timeout does not create an exception.
The shared `formal-assurance` skill selects a suitable language-native verifier, or Lean with an explicit implementation refinement.

## Commands and evidence

```sh
mise x -- cargo xtask prove --list
mise x -- cargo xtask prove --case coordinates
mise x -- cargo xtask prove --case lean
mise x -- cargo xtask prove --case bootstrap
mise x -- cargo xtask cloud prove settle-contract --dry-run
mise x -- cargo xtask cloud prove settle-contract
mise run check:proofs
mise x -- cargo xtask prove --verify-search
```

Kani is pinned to 0.68.0 with its own Rust compiler and CBMC 6.11.0.
Lean is pinned by [lean-toolchain](../proofs/lean/lean-toolchain) to `leanprover/lean4:v4.34.1`.
Z3's native archive names and publisher SHA-256 digests are pinned per platform in [mise.toml](../mise.toml), using the [official release assets](https://github.com/Z3Prover/z3/releases/tag/z3-5.1.0).
The cloud bootstrap reads that same configuration and requires the installed executable to report the expected version before submitting a proof job.
Install the official verifier distributions before invoking these commands.
The default proof command has a shared 60-second local limit and one Kani worker; individual harnesses have a 30-second verifier limit.
Select individual cases to retain verified checkpoints within that limit.
Longer proof commands are restricted to a cloud or hosted CI worker.
Hosted harnesses have a 300-second verifier limit.
`cloud prove CASE` submits only the fixed registered proof command, with a 3300-second shared job limit on an automatically deleted CPU VM.
It validates the narrower verification bootstrap receipts before provisioning; those receipts cannot authorize ciphertext search.
Individual reciprocal proofs automatically include the queue prerequisite, and propagation includes the queue, partition and every reciprocal proof.
Current prerequisite receipts may be reused after revalidation; explicitly requested cases are rerun.

Receipts in `reports/proofs/` bind the production sources, harness, verifier versions, 64-bit native target and exact verification command.
Each run atomically reserves a new model directory, forces compilation and retains the generated model with its hash.
The validator rejects old receipts without isolated models, models outside their reserved directory, changed model bytes and changed command settings.
The current validator rechecks the retained raw report; a validator-only refactor does not pretend to rerun an unchanged mathematical proof.
Attestations record that validator's current hash separately.
The driver requires every declared harness, successful unwinding and safety checks, reachable contract assertions and satisfied cover witnesses.
Timeouts, empty results, missing witnesses, unexpected failures, different settings and source drift reject the gate.
The negative control requires the specific false coordinate assertion to fail; a compiler error is rejected.
An owned operating-system file lock gives one proof operation ownership of the output directory.
The shared lease guard explicitly unlocks on drop, including when a duplicated handle remains alive; closing only the original handle does not establish release.
The native regressions pass on Mac, Linux and Windows against the same production module, including actual competing processes.
Test fixtures reserve their files atomically; repeated wall-clock readings cannot make parallel tests share a fixture.
The retained [native adapter results](../reports/proofs/lease-native.json) record the source hash, release compilation and durable remote job identities.
The source tree must remain unchanged during verification; hashes are checked before and after each run.
Filesystem, process and verifier implementations remain explicit trusted boundaries.

`check:quick` validates current bounded-workload admission receipts after its CPU checks.
The cloud controller invokes the corresponding check before creating a VM and retains its attestation in the manifest.
CI runs the required Kani cases and the Lean build before its ordinary checks.
The scoped completion gate requires 31 Kani outcomes, including two expected false-claim controls, six Lean theorems and the checked boundary assessment in [assurance.json](../proofs/assurance.json).
Every listed supported core remains mandatory, and every boundary requires a current full hardware recovery record with eight matched shuffles.
The `native` proof group verifies the required mathematical results before the cloud recovery worker tests hardware; it does not claim the empirical checks already ran.
The stronger `--verify-search` gate additionally requires the exploratory propagation theorem and registered, source-bound full-search contracts.
It remains incomplete for menu propagation, complete ring traces, candidate retention, GPU equivalence, worker scheduling, controller lifecycle and input validation.
Passing scoped completion cannot authorize an unrestricted search through that stronger gate.
The [bounded experiment decision](adr/0004-keep-assurance-directed-at-decryption.md) admits known-key recovery and fixed sourced candidate experiments without claiming that the incomplete complete-search gate has passed.
Candidate experiments additionally require current full hardware recovery and matched recovery controls.
Hosted runs bundle raw results, receipts and isolated models in `reports/proof-bundle.tar.gz`, including after a proof failure.
Fetched artifacts retain their original provenance; they are not automatically accepted as local receipts.

## Native Rust obligations

The harnesses import production Rust rather than a copied algorithm.
Successful cases establish only the following scopes.

| Contract | Harness | Domain and boundary |
| --- | --- | --- |
| Ring coordinates round trip and stay in the alphabet | [coordinates.rs](../proofs/coordinates.rs) | Every pair of raw `u8` inputs |
| Stepping reads notches before motion | [stepping.rs](../proofs/stepping.rs) | All positions and independently arbitrary middle/right notch sets; transformation wiring is not used |
| The middle rotor can step on consecutive presses | [stepping.rs](../proofs/stepping.rs) | A right carry reaches a middle notch; explicit witnesses check those preconditions |
| Left-ring normalization preserves initial offsets and one step | [stepping.rs](../proofs/stepping.rs) | All three rings, positions and admitted notch sets |
| Published rotor permutations invert | [wiring.rs](../proofs/wiring.rs) | Eight published rotors, every letter and offset |
| Naval composite reflectors are involutions without fixed points | [wiring.rs](../proofs/wiring.rs) | All 104 composites and every letter |
| Connecting leads preserves a valid plugboard involution | [plugboard.rs](../proofs/plugboard.rs) | Every valid 26-letter mapping, including existing partners and self connections |
| Crib bounds reject overflowing or out-of-range offsets | [menu.rs](../proofs/menu.rs) | Every 64-bit length/offset triple; a concrete menu also checks maximum offsets |
| A one-letter crib rejects exactly self encipherment | [menu.rs](../proofs/menu.rs) | Every pair of valid letters |
| Starting a scratch run forgets mappings and preserves stored bytes | [scratch.rs](../proofs/scratch.rs) | Every assignment bitmask and stored value/queue array; the current implementation resets a 26-letter bitset |
| A queued assignment checks existing partners and preserves unmodified entries | [queue-contract.rs](../proofs/queue-contract.rs) | Every valid letter, arbitrary scratch state and admitted queue capacity; successful native proof of the production contract |
| Reciprocal settlement preserves exact state and partial-failure behavior | [settle-contract.rs](../proofs/settle-contract.rs) | Five exhaustive assignment-state cases call the actual body and quantify an arbitrary array index for exact updates and framing |
| Proof acceptance excludes missing, failed or vacuous evidence | [gate.rs](../proofs/gate.rs) | Arbitrary completion counters, check classifications and assurance dispositions; empirical alternatives require controls, and JSON validation has separate boundary tests |
| Local lemmas cannot replace a required search contract | [search-scope.rs](../proofs/search-scope.rs) | Every scope list of length zero through 32 and every required scope; the production bitset preserves required membership, with acceptance and rejection witnesses; a compile-time assertion keeps the registry within that proved bound |
| Every artifact is staged before any read and failures stop transfer | [artifacts.rs](../proofs/artifacts.rs) | Zero through two artifact entries and every staging/reading outcome; the production adapter bounds batches to two, while filesystem and SSH behavior remain external assumptions |
| Bootstrap evidence admits verification, known-key recovery and runtime-only measurement | [work.rs](../proofs/work.rs) | Every workload, evidence state and completion result; experiments require recovery evidence, while full-search assurance requires its complete evidence |
| Bounded dispatch requires the registered fixed command | [work.rs](../proofs/work.rs) | Arbitrary argument count and optional byte slices of arbitrary valid length; proof commands require registration, experiments require a named candidate and fixed runtime, and measurements accept only the benchmark with an optional period from one through six |
| Cleanup records are attempted before propagating the first failure | [completion.rs](../proofs/completion.rs) | Every operation, VM deletion, SSH cleanup, cost-bound and record-write result; native fault-injection checks bind the ordering to the actual manifest adapter, while filesystem persistence and provider semantics remain external boundaries |
| Explicit placements stay in bounds without fallback | [work.rs](../proofs/work.rs) | Every `usize` length, crib length and requested/actual offset; the production selector accepts exactly the requested fitting interval and preserves default placement selection |
| Selected reciprocal and propagation proofs include prerequisites | [work.rs](../proofs/work.rs) | Every typed selection, obligation and requested/current state; the registry-order regression checks the actual case mapping |
| The CLI comparison retains the known fixture guard | [gate.rs](../proofs/gate.rs) | Every optional six-byte result; both implementations must report `0.0438` |
| Successful lock ownership releases exactly once; failed acquisition never releases | [lease.rs](../proofs/lease.rs) | Every initial lock state and backend acquisition/release outcome; the native file-lock adapter assumes the operating system implements its documented lock semantics |
| A deliberately false coordinate claim is refuted | [coordinate-counterexample.rs](../proofs/coordinate-counterexample.rs) | An expected counterexample, never a positive correctness proof |

The [reciprocal contract](../proofs/settle-contract.rs) partitions same-letter, two-new-letter, first-new, second-new and both-known states.
The partition lemma and all five direct-body cases are required results.
Earlier whole-array compositional attempts timed out; decomposition proves exact success, queue count, assignment bits, pointwise values and pending entries, including partial failure, without replacing the production body.
All five initial local direct-body cases passed in 6–13 seconds; this does not claim the separate compositional settlement annotation was verified.
The [propagation harness](../proofs/propagation.rs) remains an exploratory, incomplete obligation outside the scoped completion promise.
It no longer uses an unverified settlement stub.
It quantifies valid plugboards, arbitrary scratch state and four-edge adjacency tables consistent with arbitrary crib endpoints.
This adjacency domain includes the tables produced by a four-edge menu and also permits duplicate incidences.
Unused menu fields do not participate in the private propagation core.
The provider agrees with the proposed true board at each crib endpoint and is otherwise nondeterministic.
Verification-only loop invariants express consistency, queue capacity and a decreasing work measure in the actual Rust body.
No successful result has been inferred from a failed or timed-out prerequisite.
This four-edge obligation would not by itself establish the 25- and 30-letter target menus or all 72-letter inputs.

## Lean scope

[CipherProofs.lean](../proofs/lean/CipherProofs.lean) checks six theorems: trace length, preservation of reflector involution and absence of fixed points under conjugation, preservation of traces under a commuting normalization, preservation of each key by deduplication, and a counterexample to unconditional retention under a finishing cap.
The axiom audit rejects `sorryAx`, missing theorems and unproved project axioms.
The proofs use only the reported Lean foundational axioms, where needed.
These are mathematical theorems with stated premises, not a verified translation of the complete Rust solver.

## Search readiness

The solver is not yet formally verified as a complete pipeline.
Remaining obligations include production-size menu propagation and construction, the Rust ring-trace/HashSet deduplication refinement, finishing and candidate retention, WGSL equivalence and GPU scheduling, and the orchestration adapters' failure and cleanup contracts.
In particular, a language-ranked finishing cap cannot guarantee retaining every true candidate.
The planted 72-letter, ten-lead recovery and its identical-search shuffled controls remain required empirical evidence.
The recovery receipt with SHA-256 `340ada4e2ea7097357d14d2470e5ab5ecab4ffa8779776a12c516ff6a956880a` passed on 3 October 2026 before the subsequent explicit-placement orchestration change.
All four named hardware tests ran, including the known 72-letter ten-lead fixture, wider ring alternatives and eight matched shuffle searches.
The complete project check passed in 1,423.88 seconds; recovery and setup took 1,984.77 seconds in the worker.
Those results are empirical validation of the stated fixtures and scopes, not a proof of complete pipeline coverage.
P1030680 remains unresolved.
C03's full matched control completed with zero stops in 1566.57 seconds; its VM and boot disk were deleted.
The C06 offset-42 experiment reused the subsequent source-bound recovery receipt `ba8a14c30b61b6270b6a05cb6af1d352c3c4a4843aa34ad7cbd3521edff05cad`.
All four hardware tests and the full project check passed; the latter took 1,414.81 seconds.
The offset-42 target and its identical-placement control both completed with zero raw stops.
The investigation subsequently ended without decryption; [the experiment record](p1030680.md) preserves all completed and untested conditions.

The final closeout verification ran on GCP worker `cb-1791093254-319540000-gpu` on 4 October 2026 after the review fixes.
All 31 required Kani outcomes, the six Lean theorems and seven checked boundary assessments passed; the [scoped attestation](../data/p1030680/assurance-result.json) retains their exact receipt hashes and explicitly leaves whole-search completeness unproved.
The current [hardware recovery record](../data/p1030680/recovery-result.json), SHA-256 `1326cca84cce97e86b92a6c6311ca7cf879e82598c1ebb211f0f7d6988f6cc25`, records all four actual GPU tests and eight matched shuffled recovery searches.
The complete Rust/Haskell check passed in 1,495.52 seconds, within a 2,460.32-second worker run.
The controller retrieved both the recovery record and the 14,944,169-byte raw proof bundle with verified hashes, then verified VM and boot-disk deletion at 06:43 UTC.
The bundle's SHA-256 is `a97d77410977eb556b56e35f58839adb06fb8c9bc7aec1a7d3694ce1814d0e50` and it is retained with the [private execution evidence](archive.md).
The native release regressions separately executed all 49 xtask tests successfully on Mac, Linux and Windows, including workspace eviction, cleanup failures, preserved symlinks and native process arguments and timeouts.
The earlier 30-outcome closeout receipts remain available at [commit 96d6b3e](https://github.com/P4suta/cipher-break/tree/96d6b3e60d578606e74ea09d2525c165d96c06b2/data/p1030680) and in the original execution archive.
