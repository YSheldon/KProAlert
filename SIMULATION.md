# Synthetic record verification

The Feishu reader also projects an allowlisted alert identity: 64 lowercase hex
characters, optionally prefixed with `SIMULATED-`. This prefix derives the
`simulated` boolean. It is a test label, not cryptographic provenance.

The prefix alone is not authority to suppress security handling. Only exclude IDs
explicitly registered by the operator in KPRO_SIMULATED_ALERT_IDS from real-threat
statistics. The guidance tool otherwise reports an unverified simulation claim.
Never interpret
this synthetic record as a real driver detection, block or termination.
No paths or command lines are exposed. An invalid nonempty identity fails the read.
