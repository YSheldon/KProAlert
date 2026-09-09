# Background delivery without administrator privileges

Protection and delivery have separate lifetimes. The signed Windows service keeps
protecting offline. A current-user scheduled task imports committed batches and,
only when explicitly configured, sends sanitized summaries to Feishu. It runs at
user logon with Limited privileges, not as SYSTEM, and stores no password. Logout
pauses cloud delivery; the service's bounded spool remains.

## Configure

After verified protection installation, run as the actual delivery user. Pass that
same user's SID to the protection installer for spool read/delete and archive
permissions. Never borrow a different account's cloud credentials.

```powershell
.\Configure-KProDelivery.ps1 -Python "$PWD\.venv\Scripts\pythonw.exe"
.\Configure-KProDelivery.ps1 -Python "$PWD\.venv\Scripts\pythonw.exe" -Apply
```

The first command is a plan. The second registers and starts the task. Default
state is `%LOCALAPPDATA%\KProAlert`: fixed `delivery.json`, `events.db`,
`delivery-health.json`, and a worker lock. Existing tasks/configurations are not
overwritten. Keep the checkout and venv at stable paths; updating source does not
replace a running interpreter.

To publish, add `-Publish -LarkCli <absolute-exe> -Base <authorized-base>
-Table <authorized-table>`. Authenticate the CLI independently as this Windows
user. The CLI is trusted, user-selected executable code, not input from an event
or cloud record. No credentials belong in delivery.json.

## Verify and monitor

Require a recent `KProDeliveryHealth/v1` receipt, advancing cycle and `status=ready`.
Match its PID to the task interpreter. This proves delivery only: independently
check KProSvc, KProFilter and collector health for protection.

Polling defaults to ten seconds and at most 256 batches per cycle. Idle cycles do
not reparse/export the entire event store. Each cycle makes at most one remote
write; networking can extend the cycle by the CLI's timeout. One worker locks each database. Sources
are archived only after SQLite commit; errors retain the source. Limits are
512 MiB/10,000 archived files and 512 MiB/100,000 database events. Capacity errors
need operator archival/reconciliation; there is no automatic evidence pruning.
Service events not yet committed can still be lost on power or storage failure.

Loss-only batches update local reportedDropped. They are not fabricated as driver
events in Feishu; cloud-only queries currently do not expose that health counter.
Uncertain remote writes remain pending and are not automatically re-sent.

## Remove

```powershell
.\Configure-KProDelivery.ps1 -Python "$PWD\.venv\Scripts\pythonw.exe" -Remove
.\Configure-KProDelivery.ps1 -Python "$PWD\.venv\Scripts\pythonw.exe" -Remove -Apply
```

Removal checks action, SID, Interactive/Limited principal and logon trigger, stops
only this task and unregisters it. Data stays. Remove delivery before product
uninstall. `Uninstall-KProAlert.ps1 -ManifestSha256 <trusted-hash>` is a plan;
`-Apply` requires administrator consent and product-authorized uninstall. It
archives installation evidence and never forces filter unload or clears unknown
crash records.

Neither worker nor MCP performs AI remediation or guarantees an AI app wakes up.
An app-native analysis routine needs separate consent, deduplication and a bound
notification destination.
