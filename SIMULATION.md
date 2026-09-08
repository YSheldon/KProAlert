# Synthetic record verification

The Feishu reader also projects an allowlisted alert identity: 64 lowercase hex
characters, optionally prefixed with `SIMULATED-`. This prefix derives the
`simulated` boolean. It is a test label, not cryptographic provenance.

Exclude IDs beginning with SIMULATED- from production statistics. Never interpret
this synthetic record as a real driver detection, block or termination.
No paths or command lines are exposed. An invalid nonempty identity fails the read.
