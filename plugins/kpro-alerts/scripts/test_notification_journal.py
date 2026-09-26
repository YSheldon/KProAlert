import concurrent.futures
from contextlib import closing
import json
import sqlite3
import tempfile
from pathlib import Path
import unittest

from notification_journal import (
    MAX_BASELINE_INPUTS,
    MAX_INPUTS,
    NotificationJournal,
)


def alert(alert_id="ALERT-1", sequence=1, **extra):
    value = dict(alertId=alert_id, eventType=7, operation=8, sequence=sequence,
                 processId=42, processCreateTime=123, reportOnly=False)
    value.update(extra)
    return value


class NotificationJournalTests(unittest.TestCase):
    def test_native_result_is_deduplicated_and_ack_is_not_delivery(self):
        journal = NotificationJournal(self.path)
        journal.baseline([], [])
        journal.baseline_results([])
        result = dict(recordId="a" * 64, schema="FalconProNativeActionResult/v1",
                      eventId="b" * 64, evidenceSha256="c" * 64,
                      requestId="d" * 64, decisionId="e" * 64,
                      action="switch_to_enforce", executionState="executed_verified",
                      reportedOutcome="executed_verified",
                      verificationProvenance="verified_locally_not_device_signed",
                      beforePolicyVersion="100", targetPolicyVersion="101",
                      afterPolicyVersion="101", simulated=False)
        first = journal.prepare_results([result])
        self.assertEqual(first["drafts"][0]["kind"], "result")
        self.assertEqual(first["drafts"][0]["recordId"], result["recordId"])
        self.assertEqual(NotificationJournal(self.path).prepare_results([result])["drafts"], [])
        acknowledged = journal.ack(first["token"], "claimed-client-receipt")
        self.assertTrue(acknowledged["acknowledged"])
        self.assertFalse(acknowledged["deliveryConfirmed"])
        self.assertFalse(acknowledged["entries"][0]["delivered"])
        simulated = dict(result, recordId="f" * 64, simulated=True)
        self.assertEqual(journal.prepare_results([simulated])["drafts"], [])

    def test_old_alert_table_migrates_without_losing_its_baseline(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.executescript("""
                CREATE TABLE batches(token TEXT PRIMARY KEY, canonical TEXT NOT NULL, created_ns INTEGER NOT NULL);
                CREATE TABLE entries(entry_key TEXT PRIMARY KEY, token TEXT NOT NULL REFERENCES batches(token),
                    kind TEXT NOT NULL CHECK(kind IN ('alert', 'fault')), alert_id TEXT,
                    payload TEXT NOT NULL, state TEXT NOT NULL
                    CHECK(state IN ('prepared', 'acknowledged', 'uncertain', 'baseline')),
                    receipt TEXT, created_ns INTEGER NOT NULL);
                CREATE TABLE journal_meta(id INTEGER PRIMARY KEY CHECK(id = 1), baseline_token TEXT NOT NULL);
                INSERT INTO batches VALUES('n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','old',1);
                INSERT INTO entries VALUES('alert:OLD','n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'alert','OLD','{"eventType":7}','baseline',NULL,1);
                INSERT INTO journal_meta VALUES(1,'n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
            """)
        journal = NotificationJournal(self.path)
        self.assertEqual(journal.status()["stateCounts"]["baseline"], 1)
        journal.baseline_results([])
        result = dict(recordId="a" * 64, schema="FalconProNativeActionResult/v1",
                      eventId="b" * 64, evidenceSha256="c" * 64,
                      requestId="d" * 64, decisionId="e" * 64,
                      action="switch_to_enforce", executionState="executed_verified",
                      reportedOutcome="executed_verified",
                      verificationProvenance="verified_locally_not_device_signed",
                      beforePolicyVersion="100", targetPolicyVersion="101",
                      afterPolicyVersion="101", simulated=False)
        self.assertEqual(journal.prepare_results([result])["newDraftCount"], 1)
        self.assertEqual(journal.status()["stateCounts"]["baseline"], 1)

    def test_concurrent_open_of_old_alert_table_preserves_its_rows(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.executescript("""
                CREATE TABLE batches(token TEXT PRIMARY KEY, canonical TEXT NOT NULL, created_ns INTEGER NOT NULL);
                CREATE TABLE entries(entry_key TEXT PRIMARY KEY, token TEXT NOT NULL REFERENCES batches(token),
                    kind TEXT NOT NULL CHECK(kind IN ('alert', 'fault')), alert_id TEXT,
                    payload TEXT NOT NULL, state TEXT NOT NULL
                    CHECK(state IN ('prepared', 'acknowledged', 'uncertain', 'baseline')),
                    receipt TEXT, created_ns INTEGER NOT NULL);
                CREATE TABLE journal_meta(id INTEGER PRIMARY KEY CHECK(id = 1), baseline_token TEXT NOT NULL);
                INSERT INTO batches VALUES('n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','old',1);
                INSERT INTO entries VALUES('alert:OLD','n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'alert','OLD','{"eventType":7}','baseline',NULL,1);
                INSERT INTO journal_meta VALUES(1,'n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
            """)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            values=list(pool.map(lambda _:NotificationJournal(self.path).status(),range(4)))
        self.assertTrue(all(value["stateCounts"]["baseline"]==1 for value in values))

    def test_legacy_fault_epoch_and_result_kind_migrate_together(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.executescript("""
                CREATE TABLE batches(token TEXT PRIMARY KEY, canonical TEXT NOT NULL, created_ns INTEGER NOT NULL);
                CREATE TABLE entries(entry_key TEXT PRIMARY KEY, token TEXT NOT NULL REFERENCES batches(token),
                    kind TEXT NOT NULL CHECK(kind IN ('alert', 'fault')), alert_id TEXT,
                    payload TEXT NOT NULL, state TEXT NOT NULL
                    CHECK(state IN ('prepared', 'acknowledged', 'uncertain', 'baseline')),
                    receipt TEXT, created_ns INTEGER NOT NULL);
                CREATE TABLE fault_state(id INTEGER PRIMARY KEY CHECK(id = 1), active INTEGER NOT NULL, code INTEGER);
                CREATE TABLE journal_meta(id INTEGER PRIMARY KEY CHECK(id = 1), baseline_token TEXT NOT NULL);
                INSERT INTO batches VALUES('n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','old',1);
                INSERT INTO entries VALUES('alert:OLD','n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'alert','OLD','{"eventType":7}','baseline',NULL,1);
                INSERT INTO journal_meta VALUES(1,'n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
            """)
        journal = NotificationJournal(self.path)
        self.assertEqual(journal.status()["stateCounts"]["baseline"], 1)
        self.assertEqual(journal.status()["faultState"]["epoch"], 0)
        journal.baseline_results([])
        self.assertTrue(journal.status()["resultsInitialized"])

    def test_result_source_requires_explicit_historical_baseline(self):
        journal = NotificationJournal(self.path)
        journal.baseline([], [])
        old = dict(recordId="a" * 64, schema="FalconProNativeActionResult/v1",
                   eventId="b" * 64, evidenceSha256="c" * 64,
                   requestId="d" * 64, decisionId="e" * 64,
                   action="switch_to_enforce", executionState="executed_verified",
                   reportedOutcome="executed_verified",
                   verificationProvenance="verified_locally_not_device_signed",
                   beforePolicyVersion="100", targetPolicyVersion="101",
                   afterPolicyVersion="101", simulated=False)
        with self.assertRaises(ValueError):
            journal.prepare_results([old])
        initial = journal.baseline_results([old])
        self.assertEqual(initial["baselineCount"], 1)
        self.assertEqual(initial["drafts"], [])
        self.assertEqual(journal.prepare_results([old])["drafts"], [])
        new = dict(old, recordId="f" * 64)
        self.assertEqual(journal.prepare_results([new])["newDraftCount"], 1)
        with self.assertRaises(ValueError):
            journal.baseline_results([])

    def test_result_projection_rejects_private_or_malformed_fields(self):
        journal = NotificationJournal(self.path)
        journal.baseline([], [])
        journal.baseline_results([])
        good = dict(recordId="a" * 64, schema="FalconProNativeActionResult/v1",
                    eventId="b" * 64, evidenceSha256="c" * 64,
                    requestId="d" * 64, decisionId="e" * 64,
                    action="switch_to_enforce", executionState="executed_verified",
                    reportedOutcome="executed_verified",
                    verificationProvenance="verified_locally_not_device_signed",
                    beforePolicyVersion="100", targetPolicyVersion="101",
                    afterPolicyVersion="101", simulated=False)
        for change in (dict(path="C:\\Users\\Private"), dict(cmdline="powershell"),
                       dict(simulated="false"), dict(executionState=[]),
                       dict(verificationProvenance="device_attested")):
            with self.subTest(change=change), self.assertRaises(ValueError):
                journal.prepare_results([dict(good, **change)])
        self.assertEqual(journal.status()["entryCount"], 0)

    def test_simulated_result_pages_do_not_accumulate_empty_batches(self):
        journal = NotificationJournal(self.path)
        journal.baseline([], [])
        journal.baseline_results([])
        before = journal.status()["batchCount"]
        for index in range(20):
            result = dict(recordId=f"{index + 1:064x}", schema="FalconProNativeActionResult/v1",
                          eventId="b" * 64, evidenceSha256="c" * 64,
                          requestId="d" * 64, decisionId="e" * 64,
                          action="switch_to_enforce", executionState="executed_verified",
                          reportedOutcome="executed_verified",
                          verificationProvenance="verified_locally_not_device_signed",
                          beforePolicyVersion="100", targetPolicyVersion="101",
                          afterPolicyVersion="101", simulated=True)
            self.assertEqual(journal.prepare_results([result])["drafts"], [])
        self.assertEqual(journal.status()["batchCount"], before)

    def test_caller_supplied_ack_does_not_prove_native_delivery(self):
        journal = NotificationJournal(self.path)
        journal.baseline([], [])
        prepared = journal.prepare([alert("ACK-IS-NOT-DELIVERY")], [])
        receipt = journal.ack(prepared["token"], "caller-claimed-native")
        self.assertEqual(receipt["stateCounts"], {"acknowledged": 1})
        self.assertTrue(receipt["acknowledged"])
        self.assertFalse(receipt["delivered"])
        self.assertFalse(receipt["deliveryConfirmed"])
        self.assertFalse(receipt["entries"][0]["delivered"])

    def test_pending_token_is_recoverable_after_prepare_output_loss(self):
        journal=NotificationJournal(self.path)
        result=journal.prepare([alert('LOST-OUTPUT')],[])
        pending=NotificationJournal(self.path).status()
        self.assertIn(result['token'],pending['pendingTokens'])
        self.assertFalse(pending['pendingHasMore'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "notifications.db"

    def tearDown(self):
        self.temp.cleanup()

    def test_deterministic_prepare_dedup_and_restart(self):
        first = NotificationJournal(self.path).prepare(
            [alert("ALERT-B", 2), alert("ALERT-A", 1)], [])
        second = NotificationJournal(self.path).prepare(
            [alert("ALERT-A", 1), alert("ALERT-B", 2)], [])
        self.assertEqual(first["token"], second["token"])
        self.assertEqual(len(first["drafts"]), 2)
        self.assertEqual(second["drafts"], [])
        updated = NotificationJournal(self.path).prepare(
            [alert("ALERT-A", 1, eventCount=99), alert("ALERT-B", 2, eventCount=100)], [])
        self.assertEqual(updated["drafts"], [])
        self.assertEqual(updated["token"], first["token"])
        NotificationJournal(self.path).ack(first["token"], "native-1")
        restarted = NotificationJournal(self.path).prepare(
            [alert("ALERT-A", 1), alert("ALERT-B", 2)], [])
        self.assertEqual(restarted["drafts"], [])
        self.assertEqual(NotificationJournal(self.path).status(first["token"])["stateCounts"],
                         {"acknowledged": 2})

    def test_summary_without_sequence_is_accepted(self):
        summary = dict(alertId="SUMMARY", eventType=7, operation=8,
                       eventCount=2, blockedCount=0, terminatedCount=0)
        result = NotificationJournal(self.path).prepare([summary], [])
        self.assertEqual(len(result["drafts"]), 1)
        self.assertEqual(result["drafts"][0]["fields"]["eventCount"], 2)

    def test_baseline_is_distinct_from_ack_and_only_allowed_when_empty(self):
        journal = NotificationJournal(self.path)
        result = journal.baseline([alert("HISTORICAL")], [])
        self.assertTrue(result["initialized"])
        self.assertEqual(result["drafts"], [])
        self.assertFalse(result["delivered"])
        self.assertEqual(journal.status(result["token"])["stateCounts"], {"baseline": 1})
        with self.assertRaises(ValueError):
            journal.ack(result["token"], "native-baseline")
        with self.assertRaises(ValueError):
            journal.baseline([alert("RESET")], [])
        self.assertEqual(journal.prepare([alert("HISTORICAL")], [])["drafts"], [])

    def test_baseline_has_single_2000_record_bound(self):
        self.assertEqual(MAX_BASELINE_INPUTS, 2000)
        historical = [alert("H-%04d" % index, sequence=index + 1)
                      for index in range(MAX_BASELINE_INPUTS)]
        result = NotificationJournal(self.path).baseline(historical, [])
        self.assertEqual(result["baselineCount"], MAX_BASELINE_INPUTS)
        overflow_path = Path(self.temp.name) / "baseline-overflow.db"
        with self.assertRaises(ValueError):
            NotificationJournal(overflow_path).baseline(
                [alert("O-%04d" % index, sequence=index + 1)
                 for index in range(MAX_BASELINE_INPUTS + 1)], [])

    def test_concurrent_prepare_has_one_winner(self):
        def run():
            return NotificationJournal(self.path).prepare([alert("CONCURRENT")], [])

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: run(), range(8)))
        self.assertEqual(len({result["token"] for result in results}), 1)
        self.assertEqual(sum(len(result["drafts"]) for result in results), 1)

    def test_exact_simulation_allowlist_only(self):
        spoof = NotificationJournal(self.path).prepare(
            [alert("SIM-UNTRUSTED", simulated=True, simulationVerified=True)], [])
        self.assertEqual(len(spoof["drafts"]), 1)
        self.assertTrue(spoof["drafts"][0]["fields"]["simulated"])
        self.assertTrue(spoof["drafts"][0]["fields"]["simulationVerified"])
        skipped = NotificationJournal(self.path).prepare(
            [alert("SIM-EXACT", simulated=True, simulationVerified=True)], ["SIM-EXACT"])
        self.assertEqual(skipped["drafts"], [])
        self.assertEqual(skipped["skippedSimulationCount"], 1)
        case_spoof = NotificationJournal(self.path).prepare(
            [alert("sim-exact", simulated=True)], ["SIM-EXACT"])
        self.assertEqual(len(case_spoof["drafts"]), 1)

    def test_fault_state_changes_and_recovery_are_not_flooded(self):
        journal = NotificationJournal(self.path)
        active = journal.prepare([], [], {"active": True, "code": 5})
        self.assertEqual(len(active["drafts"]), 1)
        self.assertEqual(journal.prepare([], [], {"active": True, "code": 5})["drafts"], [])
        self.assertEqual(journal.prepare([], [], None)["drafts"], [])
        self.assertEqual(journal.status()["faultState"], {"active": True, "code": 5, "epoch": 1})
        changed = journal.prepare([], [], {"active": True, "code": 6})
        self.assertEqual(len(changed["drafts"]), 1)
        recovered = journal.prepare([], [], {"active": False})
        self.assertEqual(len(recovered["drafts"]), 1)
        self.assertEqual(journal.prepare([], [], {"active": False})["drafts"], [])
        recurring = journal.prepare([], [], {"active": True, "code": 6})
        self.assertEqual(len(recurring["drafts"]), 1)
        self.assertNotEqual(recurring["token"], changed["token"])

    def test_unknown_outcome_is_retained_and_not_retried(self):
        journal = NotificationJournal(self.path)
        prepared = journal.prepare([alert("UNCERTAIN")], [])
        journal.mark_uncertain(prepared["token"])
        repeated = NotificationJournal(self.path).prepare([alert("UNCERTAIN")], [])
        self.assertEqual(repeated["drafts"], [])
        self.assertEqual(journal.status(prepared["token"])["stateCounts"], {"uncertain": 1})

    def test_ack_requires_receipt_and_token_binding(self):
        journal = NotificationJournal(self.path)
        prepared = journal.prepare([alert("ACK")], [])
        with self.assertRaises(ValueError):
            journal.ack(prepared["token"], "")
        with self.assertRaises(ValueError):
            journal.ack("n-" + "0" * 64, "native-1")
        journal.mark_uncertain(prepared["token"])
        journal.ack(prepared["token"], "native-1")
        journal.ack(prepared["token"], "native-1")
        with self.assertRaises(ValueError):
            journal.ack(prepared["token"], "native-2")
        other = journal.prepare([alert("ACK-OTHER", sequence=2)], [])
        with self.assertRaises(ValueError):
            journal.ack(other["token"], "native-1")
        self.assertEqual(journal.status(prepared["token"])["stateCounts"], {"acknowledged": 1})

    def test_quota_and_id_validation(self):
        journal = NotificationJournal(self.path)
        with self.assertRaises(ValueError):
            journal.prepare([alert("bad id")], [])
        with self.assertRaises(ValueError):
            journal.prepare([alert("OK", eventType=True)], [])
        with self.assertRaises(ValueError):
            journal.prepare([alert("DUP"), alert("DUP", sequence=2)], [])
        with self.assertRaises(ValueError):
            journal.prepare([alert(str(index)) for index in range(MAX_INPUTS + 1)], [])
        with self.assertRaises(ValueError):
            journal.prepare([], [], {"active": True, "code": 5, "message": "do not persist"})
        with self.assertRaises(ValueError):
            journal.prepare([], [], {"active": True, "code": "5"})

    def test_only_safe_numeric_boolean_fields_are_stored_or_returned(self):
        journal = NotificationJournal(self.path)
        with self.assertRaises(ValueError):
            journal.prepare([alert("RAW", path="C:/secret", cmdline="--token=secret")], [])
        result = journal.prepare([alert("SAFE", flags=3, cmdlineTrusted=True)], [])
        status = journal.status(result["token"])
        serialized = json.dumps((result, status), sort_keys=True)
        self.assertNotIn("secret", serialized)
        for draft in result["drafts"]:
            self.assertTrue(all(type(value) in (int, bool) for value in draft["fields"].values()))
        db = sqlite3.connect(self.path)
        try:
            payloads = [row[0] for row in db.execute("SELECT payload FROM entries")]
        finally:
            db.close()
        payload_text = " ".join(payloads)
        self.assertNotIn('"path":', payload_text)
        self.assertNotIn('"cmdline":', payload_text)

    def test_prepare_result_is_not_delivery_receipt(self):
        result = NotificationJournal(self.path).prepare([alert("DRAFT")], [])
        self.assertTrue(result["drafts"])
        self.assertFalse(result["delivered"])
        self.assertEqual(NotificationJournal(self.path).status(result["token"])["stateCounts"],
                         {"prepared": 1})


if __name__ == "__main__":
    unittest.main()
