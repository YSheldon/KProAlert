# Candidate Native Validation

This developer-only path tests the common native lifecycle without declaring an
unverified release production-ready. It is not exposed by stable discovery or
the Codex, Grok Bot, WorkBuddy and Cursor install tools.

## Authority

Start `plugins/kpro-alerts/scripts/candidate_validation.py` from the already
trusted/installed plugin, not from the downloaded candidate tree. This outer
launcher pins its verifier module and checks the permit and every candidate
PS1 hash/publisher while holding read locks BEFORE executing the candidate entry.
Running a downloaded PS1 directly is not this admission path: self-checks cannot
authenticate code that already ran. The plugin checkout itself is the bootstrap
trust anchor, as in the normal installer.

`Invoke-FalconProCandidateValidation.ps1` requires explicit
`-ApproveCandidateValidation`, administrator consent and a signed
`FalconProCandidatePermit/v1` data file. Pass its independently confirmed final
SHA-256 through `-CandidatePermitSha256`. The permit is verified as data; it is
never executed or dot-sourced.

The permit binds one device digest, native x64/ARM64 architecture, transaction,
install/upgrade operation, and a UTC validity window no longer than 24 hours.
It pins the SHA-256 of `FalconProCandidateSource/v1`, which lists every executed
onboarding script and the pinned trust module. Every PS1 source must have an
approved timestamped signature. Changing any signed source requires regenerating
the source manifest and signing a new permit.

Each authorized package lists its manifest hash, signed-attestation hash and
all five payload filenames, lengths and SHA-256 values. Upgrade permits contain
the target first and the exact previous package second. The signed policy and
runtime configuration are payloads, not locally editable exceptions.

Only `releaseStatus=candidate` with `endToEnd=false` is admitted as a new test
target. All other cryptographic/evidence gates must be boolean true. An exact
previous verified package may be restored with all of its original gates.
Publishers, signatures, architecture, file capture locks, ACLs, policy preservation
and ordinary-service/PPL upgrade restrictions remain enforced.

## Preparation

1. Review the source, run Python/native tests, sign all seven PS1 entry/helper
   files, and stage them with the exact pinned `tools/KProReleaseTrust.psm1`.
2. Prepare signed candidate manifests/attestations and payloads. Do not change
   `endToEnd` to true to get past admission.
3. Run `tools/build_candidate_permit.py` with explicit source/package roots,
   device digest, transaction, architecture and operation. Its output is
   **unsigned preparation**, not authorization. For upgrades, give the target
   package first, then the exact previous package.
4. Put the generated source manifest next to the signed onboarding sources.
   Sign the generated candidate permit through the approved signing service.
   Record its final hash and review all device/file bindings before execution.
5. Claim the physical-host queue and collect fresh preflight evidence. Normal
   Code Integrity stays enabled; no test roots, TestSigning or ELAM are installed.

## Execution And Results

The dedicated entry calls `Invoke-FalconProLifecycle.ps1`; it does not implement
an alternate service installer. Its candidate path uses the same file staging,
service startup, health query, snapshot, upgrade and recovery functions. The
lower-level `ValidateCandidate` switch alone is no longer sufficient. The
installer also requires a matching protected lifecycle intent in install_pending
or recovery_install_pending and the signed operation/package role. The target
must be candidate; only an exact previous package may be verified.

Results use `FalconProCandidateLifecycleResult/v1`, `validationOnly=true` and
`productionEligible=false`. Post-reboot completion is `validation_complete`, not
the production `complete` state. The permit hash is persisted in the protected
transaction and must match during resume/rollback. Expiry fails closed, including
resume: after expiry, inspect the installation and obtain a reviewed recovery
plan instead of editing protected state or replaying a transaction.

Verify benign events, policy digest across reboot, interrupted-step recovery,
preservation of user data, and product-authorized cleanup independently. Never
upload these results as real installation counts. A passed candidate does not
publish a Release or prove native notification delivery in any assistant.

## Current Evidence

Local parser, Python and native boundary tests are implemented. Physical-host
execution and newly signed entry/permit acceptance must be recorded separately;
this document does not claim they passed.
