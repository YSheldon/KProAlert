import concurrent.futures
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
