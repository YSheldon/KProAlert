# ZCode Connector

Use the same repository address and START-HERE.md as the other clients.
The signed native EXE installs Windows protection; this adapter only configures MCP.

```powershell
.\.venv\Scripts\python.exe falconpro.py setup --client zcode
.\.venv\Scripts\python.exe falconpro.py setup --client zcode --apply
```

The native user file is `~/.zcode/cli/config.json`, under `mcp.servers`.
Workspace `.zcode/config.json` takes precedence. ZCode also supports
`.agents/mcp.json` with `mcpServers` as a fallback, but a nonempty native server
collection hides the fallback at that scope. FalconPro refuses to introduce
that change when it would hide existing fallback connectors. Import them with
ZCode first; do not reset the configuration.

The adapter preserves other settings and servers, reuses an identical connector,
rejects differing or disabled entries, backs up changed user settings, and reads
back the exact entry. It never enables auto-run or bypasses native tool approval.

After applying, use ZCode's MCP UI to load the server and invoke
`integration_status`, followed by an authorized source query. Native connection
and event handling must be verified in ZCode; file tests are not that evidence.
These paths follow [ZCode's official MCP documentation](https://zcode.z.ai/cn/docs/mcp-services).

Optional source-bound AI analysis uses `--database` and a separate
`--operations-database`; see AI-OPERATIONS.md. Do not supply a workstation's paths
or credentials to a cloud execution host.
