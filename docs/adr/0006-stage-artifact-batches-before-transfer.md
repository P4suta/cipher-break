<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# 0006: Stage artifact batches before transfer

Status: Accepted

The full cloud recovery worker completed successfully, but reading its recovery record admitted enough helper jobs to evict the finished workspace before the second fetch could read the proof bundle.
Per-file staging protected the first artifact and left later artifacts unprotected.
The controller recorded the failure and verified VM and boot-disk deletion; the successful hardware record was retained, but the raw proof bundle was lost.

Collect the required recovery and proof artifacts in one batch, stage all members outside the managed workspace before reading any, and collect job logs only once.
Use native OpenSSH file transfer for bytes, retaining domyjob for remote command execution.
Verify remote byte counts and SHA-256 before publishing each local artifact and preserve the existing result on a failed transfer.

The generic production ordering core has a required source-importing Kani proof over both admitted entries and every failure outcome.
The native regression removes the original workspace during the first read and verifies the second staged artifact survives; the previous interleaving fails on the same fixture.
SSH, file copying and remote workspace retention remain external service assumptions, with actual end-to-end transfer and cleanup recorded by the cloud controller.
This repairs evidence retrieval and does not resume ciphertext searches or establish a complete solver proof.
