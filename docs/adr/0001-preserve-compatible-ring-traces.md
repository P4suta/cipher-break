<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Preserve compatible ring traces through Bombe finishing

## Status

Accepted.

## Context

A short crib can constrain a rotor trace without identifying turnover timing in the remaining message.
The language judge can prefer a near-correct reading to the complete planted plaintext.
Selecting one ring variant before final ranking therefore removed a recoverable key, even with all ten plugboard leads already known.

## Decision

`complete_boards` retains one representative of every distinct full-message trace compatible with the crib trace.
Bombe finishing ranks all completed alternatives and reserves final output slots for distinct plaintexts.
The existing singular `complete_board` API remains available to callers explicitly requesting one language-ranked completion.
The externally supplied judge remains unchanged; tuning it against the failing fixture would conceal the loss of alternatives.

## Consequences

Finishing uses more CPU work and memory per shortlisted stop, bounded by the configured stop limit and the finite ring space.
The [CPU regression](../../tests/enigma.rs) preserves the exact planted reading even when a wrong reading has a higher held-out score.
The GPU gate exercises the actual 64-stop and five-reading limits, checks the complete recovered key by re-encryption, and applies the same wider search to eight shuffled controls.
An exact alternative retained below first place is recovered evidence for the planted fixture; a language score alone cannot identify the original text of an unknown message.
Heuristic stop pruning and the final output limit still prevent a negative result from excluding the entire key space.
