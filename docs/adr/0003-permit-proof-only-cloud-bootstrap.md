<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Permit a constrained cloud worker to establish missing search proofs

## Status

Accepted; full controller and search assurance remain incomplete.
Partially superseded by [0004](0004-keep-assurance-directed-at-decryption.md) for known-key recovery and bounded candidate experiments.
Partially supersedes [0002](0002-mandatory-source-bound-proofs.md) for verification-only VM admission.

## Context

The complete search gate rejects missing production contracts, while local proof runs are limited to one minute.
Requiring that complete gate before every verification VM creates a circular prerequisite for proofs that exceed the local limit.
The owner authorizes bounded GCP verification and requires proof work before another large ciphertext search.

## Decision

Expose `cloud prove CASE` as a separate typed verification workload.
Its only admitted command invokes a registered proof with the fixed 3300-second shared limit on a CPU worker.
Require current native proofs for command admission, workload separation, prerequisite selection, proof acceptance, scope completeness and lock ownership before creating that worker.
Retain the existing resource, billing, estimate, single-VM, absolute deletion and artifact-transfer checks.
Select missing contract prerequisites before a requested proof; only current revalidated prerequisite receipts may be reused.
Ciphertext search continues to require all full search contracts and current recovery evidence.

## Consequences

The native [decision core](../../xtask/src/proof_work.rs) and [harnesses](../../proofs/work.rs) establish the stated admission and planning properties.
These local lemmas do not prove the complete controller lifecycle, external tools or cloud service.
The existing controller boundary regressions remain necessary, and full controller assurance remains a required search obligation.
A verification worker retains failures and generated models in an artifact; fetching that artifact alone does not validate foreign absolute paths or authorize a search.
Each hosted harness has a 300-second limit, with one verifier worker and a shared job deadline.
This path resolves the prerequisite cycle without assigning a full search scope to a bounded lemma.
