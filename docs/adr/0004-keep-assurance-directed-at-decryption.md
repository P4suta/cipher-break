<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Admit bounded decryption experiments after known-key recovery

## Status

Accepted.
Partially supersedes [0002](0002-mandatory-source-bound-proofs.md) and [0003](0003-permit-proof-only-cloud-bootstrap.md) for bounded experimental admission.

## Context

The objective is to decrypt P1030680.
Formal assurance supports that objective by finding incorrect search behavior and preventing wasted computation.
Requiring complete proofs of every pipeline and controller property before running even known-key recovery prevents the evidence needed to improve the search.
The owner explicitly directs proof work toward useful decryption experiments and authorizes promotional-credit use.

## Decision

Keep machine-checked proofs of changed decision logic, source binding, explicit proof gaps and the strict complete-search assurance command.
Admit the fixed known-key GPU recovery workload after the current narrow controller admission proofs and bounded local checks.
Admit only the fixed candidate-campaign command, with C01, C03, C04 or C06 and a 90- or 100-minute limit, after current full known-key recovery and its controls pass.
The worker still validates the source rationale, estimates runtime on the GPU, excludes the crib from scoring and runs the same procedure on a shuffled input.
Retain one VM, an absolute two-hour deletion deadline, cleanup verification and artifact integrity checks.
Continue reporting estimates separately from settled billing; superseded initial USD 5/50 ceilings no longer block owner-authorized credit use.

## Consequences

These workloads are bounded experiments, not a claim that the entire solver is formally complete.
An unproved pipeline property remains recorded and constrains interpretation of a negative search result.
A reading still requires the complete key and exact re-encryption, with matched control evidence.
The [production admission predicates](../../xtask/src/proof_work.rs) and their [native harnesses](../../proofs/work.rs) enforce the narrow workload boundary.
