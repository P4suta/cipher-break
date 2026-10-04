<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Require proofs tied to production source before further search

## Status

Accepted; implementation and proof coverage remain incomplete.
Partially superseded by [0003](0003-permit-proof-only-cloud-bootstrap.md) and [0004](0004-keep-assurance-directed-at-decryption.md) for bounded workload admission.

## Context

Passing planted recovery exposed a real loss of compatible ring alternatives, while later source changes made previously passing evidence stale.
Longer differential campaigns cannot establish that every valid execution preserves a true key.
The owner requires correctness proofs for implementation changes and proof work before another large ciphertext search.

## Decision

Use standalone Kani harnesses importing the production Rust core, plus pinned Lean theorems for mathematical properties that require induction.
Keep the model-to-implementation connection explicit and reject claims that a detached model proves the solver.
Make complete, reachable, current-source proof receipts part of the local and cloud-launch gates and run them in CI.
Require the expected false-claim counterexample to exercise the acceptance mechanism.
Retain failed obligations in the registry rather than omitting them to obtain a green gate.
Require proofs for each full search contract as well as the local lemmas, so a completed bounded lemma cannot silently stand in for an unproved pipeline stage.
Bound local verification and preserve checkpoints; larger workloads belong on an authorized remote worker.

## Consequences

The declared gate currently rejects the incomplete propagation proof and prevents another VM launch.
The shared skill and agent policies require appropriate proofs in every language rather than mandating Kani for unsupported semantics.
The [proof record](../proofs.md) distinguishes native bounded results, conditional mathematical theorems and the remaining solver obligations.
Hardware recovery, independent references, matched statistical controls and exact re-encryption remain necessary for guarantees outside the established proof domains.
