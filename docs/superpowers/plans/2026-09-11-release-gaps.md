# FalconPro Release Completion Plan

Goal: finish the approved Windows 11 x64/ARM64 install, upgrade, notification and
consent-based statistics release path for the four assistant clients.

Use the existing unified-lifecycle design. Keep normal kernel Code Integrity,
signed policy, final artifact hashes, local endpoint binding, protected staging,
explicit installation consent, and uncertain-delivery reconciliation intact.
The ordinary-service release remains distinct from a PPL upgrade admission.

## Work And Evidence

- [x] Fix metrics preview so it does not reserve pending records; verify a real
  supported Lark CLI upload and readback contract before acknowledging records.
- [x] Bind Windows CPU architecture from endpoint facts through release discovery,
  per-platform filenames, installer, snapshot, upgrade and rollback.
- [x] Preserve x64 compatibility and reject architecture switches before mutation;
  add cross-architecture, tamper, native path and recovery regressions.
- [x] Inspect the actual four client/scheduler capabilities and reuse prior valid
  evidence; implement only documented host operations.
- [ ] Build and sign the final onboarding scripts and release descriptors, using
  the existing signed production driver/DLL and snapshot-capable signed hosts.
- [ ] Validate the same signed install/upgrade/reboot/rollback candidate on admitted
  physical Windows hosts; preserve policy, event and metrics data.
- [x] Verify opt-in table upload and exact readback with clearly marked simulation
  records; uncertain initial receipt reconciled without resend.
- [ ] Verify notification delivery, deduplication and advice with clearly marked
  benign records and native receipts.
- [ ] Submit reviewed changes and publish only the platform releases whose gates
  have passed; synchronize the affected integration and release documentation.

Publication, source merge, binary signing and native acceptance are separate
results. A missing host API cannot be replaced by a fabricated receipt. PPL
services keep their supported self-uninstall boundary; external forced stop is
not an upgrade implementation.
