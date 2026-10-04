<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Retained investigation evidence

The investigation ended without decryption on 4 October 2026.
The repository retains the source ledger, exact completed search conditions, small verification receipts and implementation.
Downloaded scans, OCR, isolated proof models, operational logs and billing observations belong in the owner's private archive.

The existing Synology Drive root resolves from `~/SynologyDrive/home` to `~/Library/CloudStorage/SynologyDrive-home` on the owner's Mac.
The task archive is `home/Archives/cipher-break/2026-10-04` within that Drive share.
Archive identifiers, byte counts, SHA-256 digests and verification boundaries are recorded in [archive.json](../data/p1030680/archive.json).
The provider reported all four task archives uploaded, unpaused, unexcluded and without conflicts.
Local archive hashes and extraction of representative members were checked.
Execution evidence and both supplements were compressed on Windows, and the actual Synology Drive client copies were sent back to Windows for hash verification and restoration.
An independent read and restore from the NAS server have not been performed; the original downloads and independent local evidence remain available.
Deleting a synchronized local file can propagate deletion, so provider acknowledgement alone does not authorize removing the last independent copy.

Research members preserve their original `reports/p1030680/sources/` paths.
The execution archive preserves the operational `reports/` paths referenced throughout the investigation record, including historical failures and incomplete proof attempts.
The closeout supplement retains older root reports, historical model inputs and final cleanup receipts under their original paths.
The post-review supplement retains the final 31-outcome proof bundle, all three native 49-test records, review and failure evidence, and the complete original Git history before the final public record commit.
Its recovery-record and Git-history members were restored from the actual client copy on Windows and matched their source hashes.
The original execution archive's recovery record is pinned to commit `96d6b3e60d578606e74ea09d2525c165d96c06b2`; it must not be substituted for the current post-review record.
Restore a required member into an isolated directory and compare its recorded hash before treating it as evidence.
Restored remote proof receipts retain remote model paths and source provenance; copying them does not make them current local verification results.

The final worker's VM and boot disk were deleted and empty resource listings were verified.
The task-owned GCS bucket was removed after all 53 retained objects matched the provider's recorded byte counts and MD5 hashes.
Its existing seven-day soft-delete policy can retain provider-managed copies after active deletion; project billing and authentication were preserved.

The generic shared [NAS skill](https://github.com/P4suta/dotfiles/pull/52) covers existing transports, immutable archival records, upload acknowledgement and restore checks.
The [proof-first assurance update](https://github.com/P4suta/dotfiles/pull/51) requires applicable source-bound proofs and checked alternatives at genuine boundaries.
Both changes were checked and installed through the native Mac, Linux and Windows skill profiles.
