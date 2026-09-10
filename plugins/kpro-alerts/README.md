# FalconPro alert plugin (public preview)

Skill-based Codex plugin with a read-only SQLite query tool. This is not yet the
complete signed KProSvc installer or a published Git marketplace.

Requires Python 3 and an explicitly configured event database produced by
tools/kpro_alert_bridge.py in the source repository. Query output omits file paths
and command lines. Keep the raw database under a restrictive Windows ACL.

Test: `python scripts/test_query.py`.

Before release: implement and verify the resident KProSvc exporter, queue limits,
retention and installer rollback; package signed artifacts with an immutable hash
manifest; publish the approved plugin marketplace; verify install from a clean
machine. Installing this plugin alone does not enable protection or notifications.
