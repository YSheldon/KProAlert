# FalconPro Bootstrap And Managed Upgrade

Approved scope: one repository entry, automatic signed-release acquisition,
explicit first-install/upgrade consent, ordinary UAC, preserved state and
recoverable upgrades. No running binary overwrite and no candidate gate bypass.

1. Implement a strict signed descriptor, fixed GitHub release discovery, bounded
   anonymous downloads and allowlisted ZIP extraction. Verify descriptor through
   the existing Windows publisher trust helper before trusting asset hashes.
2. Derive package/source digests from that descriptor instead of user input.
   Bind target identity and SID locally, preserving the existing installation gates.
3. Implement durable managed-upgrade planning and transitions with monotonic
   versions, old-package provenance, unchanged signed policy/runtime config,
   explicit confirmation, one writer, and unknown-outcome recovery boundaries.
   Unsupported/custom policy changes stop before uninstall.
4. Wire verified native lifecycle operations only where their receipts establish
   the required outcomes. Never mark an interrupted step successful or blindly
   retry it. Data remains in place or the authorized-uninstall evidence archive.
5. Unit tests, independent review, signing/package updates and private docs.
   Native upgrade/reboot/rollback acceptance remains a separate release gate.
