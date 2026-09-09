# Controlled physical validation, 2026-09-09

This is a bounded canary result, not a general-availability release or a full
driver compatibility/performance matrix. No malicious payload was executed.

## Verified boundary

- Native Windows 11 x64, OS build 26200; test signing off.
- Production Microsoft/product-signed driver 1.2.0.267 and product-signed DLL
  1.2.0.234, with a newly built F1/Artifact/product-signed service.
- GitHub policy run `34319393624`, source
  `423a21c358f5d91304a9fb5b511966055d6c9428`, approved through the protected
  signing environment. The driver accepted the maximum profile with
  `policyFlags=5`, `decisionMode=3`, `protectedObjectCount=0` and policy version
  `1788936078479`. The envelope is 204 bytes, including the required empty v1
  extension header. Signing keys were not distributed.
- Service installation called the DLL lifecycle interface, not an INF installer.
  No ELAM driver was installed. The tested signed runtime configuration does not
  require PPL, so this test does not establish PPL protection.
- An ordinary control file remained writable. Modification of a controlled bait
  file was denied and its hash was unchanged, both before and after normal reboot.
- The auto-start service and driver recovered after reboot, with a new service
  PID and a fresh successful collector receipt.
- Product-authorized uninstall succeeded; both test services and the installed
  system driver file were absent afterward. A fresh cleanup receipt showed no
  pending reboot. Private test evidence was retained. No other product was changed.

## Actual event evidence

The two benign probes generated four real driver records: Type 0 and Type 4
before reboot, and Type 0 and Type 4 after reboot. `operation=290` is the bitmask
`CREATE | TRUNCATE | WRITE`, not rename or delete. Type 0 reports denial. Type 4
carried the critical-process termination-skip flag: **do not claim a process was
terminated** from that event type alone.

These records were imported into the local durable store. Four sanitized summaries
were written to Feishu and read back through the actual Codex `feishu_alerts`
tool. Raw paths and command lines remained local. A second synchronization made
no additional send. Collector drops and uncertain deliveries were zero for this
bounded run; this is not a zero-loss guarantee.

The cloud rows use a `SIMULATED-` identifier and a controlled-validation device
marker to exclude them from production incident statistics. They are real events
from a benign test, distinct from the earlier fabricated transport fixtures.
Missing outcome counts are unknown, not zero.

## Remaining release gates

- The canary used a dedicated test script, not the public installer. Its native
  `sc.exe create` invocation lost quotes around a path containing spaces. The
  public installer now uses `New-Service` in Manual mode and checks the exact
  quoted SCM path/account before enabling auto-start. A readback failure leaves
  an inert Manual service for diagnosis, not an auto-start entry. Windows
  PowerShell mocked-SCM tests pass; the changed public
  installer still needs real end-to-end installation and recovery testing.
- Signed public release manifests/attestations and complete rollback/upgrade.
- Background delivery under an ordinary user's identity and storage-pressure tests.
- Current-code loading and notification acceptance in all three AI applications.
- Approval-bound remediation receipts and full user-facing install guidance.

No private endpoint identity, raw event evidence, credentials, private signing
material or binary candidate is included in this source document.
