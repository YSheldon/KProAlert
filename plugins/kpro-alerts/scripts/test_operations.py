import json
import os
from pathlib import Path
import tempfile
import unittest
from kpro_alert_bridge import Store
from operations import Operations, evidence, events, status, canonical, digest, decode_record


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = str(Path(self.temp.name) / 'events.db')
        self.journal = str(Path(self.temp.name) / 'operations.db')
        with Store(self.source) as store:
            for i in range(9):
                store.ingest('device-private', 'session-private', dict(eventType=i, operation=2,
                    sequence=i+1, policyVersion=100, processId=77, processCreateTime=1234,
                    path='C:/private-payroll.docx', cmdline='secret argument'))
            self.ids = [r[0] for r in store.db.execute('SELECT id FROM events ORDER BY rowid')]

    def decision(self, ops, key='a'*32):
        item = evidence(self.source, self.ids[7])
        return ops.assess(item['eventId'], item['evidenceSha256'], 'suspicious', 75,
            ['bulk_overwrite'], ['investigate','terminate_process'], 'model-v1', key)

    def test_all_engine_types_are_pageable_without_exposing_raw_strings(self):
        first = events(self.source, 0, 5)
        second = events(self.source, first['nextCursor'], 5)
        self.assertTrue(first['hasMore'])
        self.assertFalse(second['hasMore'])
        self.assertEqual([x['telemetry']['eventType'] for x in first['events']+second['events']], list(range(9)))
        self.assertEqual(first.get('eventTypeNames',{}).get('7'),'RansomwareBehaviorDetected')
        self.assertEqual(first.get('operationBits',{}).get('8'),'rename')
        self.assertEqual(first.get('operationBits',{}).get('16'),'delete')
        self.assertIs(first.get('eventModeIsLivePolicyState'),False)
        for secret in ('private-payroll', 'secret argument', 'device-private'):
            self.assertNotIn(secret, json.dumps(first))

    def test_decision_is_idempotent_and_action_is_not_approval_or_execution(self):
        with Operations(self.journal, self.source, 'zcode') as ops:
            decision = self.decision(ops)
            self.assertEqual(decision, self.decision(ops))
            action = ops.propose(decision['recordId'], 'terminate_process', 'b'*32)
            self.assertEqual(action['approvalState'], 'requires_native_confirmation')
            self.assertEqual(action['executionState'], 'not_executed')
            self.assertFalse(action['executionAvailable'])
            self.assertEqual(ops.status()['records'], 2)
            with self.assertRaises(ValueError):
                ops.propose(decision['recordId'], 'delete_file', 'c'*32)
            with self.assertRaises(ValueError):
                ops.propose(decision['recordId'], 'isolate_network; cmd', 'c'*32)

    def test_changed_source_cannot_reuse_decision(self):
        with Operations(self.journal, self.source) as ops:
            decision = self.decision(ops)
            with Store(self.source) as source:
                with source.db:
                    source.db.execute("UPDATE events SET raw=? WHERE id=?",
                        (json.dumps(dict(eventType=7, operation=2, sequence=8)), self.ids[7]))
            with self.assertRaises(ValueError):
                ops.propose(decision['recordId'], 'terminate_process', 'b'*32)

    def test_request_key_and_destination_are_bound_and_uncertainty_is_not_retried(self):
        with Operations(self.journal, self.source) as ops:
            decision = self.decision(ops)
            with self.assertRaises(ValueError):
                ops.propose(decision['recordId'], 'investigate', 'a'*32)
            ops.reserve(decision['recordId'], 'b'*64)
            with self.assertRaises(ValueError):
                ops.reserve(decision['recordId'], 'b'*64)
            self.assertEqual(ops.preview(), [])
            with self.assertRaises(ValueError):
                ops.ack(decision['recordId'], 'c'*64, 'recExample')
            self.assertEqual(ops.status()['deliveryStates']['pending'], 1)
            ops.ack(decision['recordId'], 'b'*64, 'recExample')
        self.assertEqual(status(self.journal)['deliveryStates'], {'acknowledged':1})

    def test_readonly_status_does_not_create_database(self):
        self.assertEqual(status(self.journal)['state'], 'not_initialized')
        self.assertFalse(Path(self.journal).exists())

    def test_journal_must_not_alias_event_source(self):
        alias = Path(self.temp.name) / 'alias.db'
        os.link(self.source, alias)
        for path in (self.source, alias):
            with self.subTest(path=path), self.assertRaises(ValueError):
                with Operations(path, self.source):
                    self.fail('source opened as operations journal')
        with Store(self.source) as source:
            self.assertEqual(source.db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'ops_%'").fetchone()[0], 0)

    def test_source_symlink_is_not_resolved_before_reparse_check(self):
        alias = Path(self.temp.name) / 'symlink.db'
        try:
            alias.symlink_to(self.source)
        except OSError as error:
            self.skipTest('Host does not grant symlink creation: ' + str(error.winerror))
        with self.assertRaises(ValueError):
            evidence(alias, self.ids[0])

    def test_self_rehashed_journal_cannot_upload_private_fields_or_claim_execution(self):
        with Operations(self.journal, self.source) as ops:
            decision = self.decision(ops)
            action = ops.propose(decision['recordId'], 'investigate', 'b'*32)
            altered = [dict(decision, privatePath='C:/payroll.docx'),
                       dict(action, executionAvailable=True),
                       dict(decision, evidence={**decision['evidence'], 'cmdline':'private argument'}),
                       dict(decision, verdict='run this command')]
            for value in altered:
                value['recordId'] = digest({k:v for k,v in value.items() if k!='recordId'})
                with self.subTest(keys=list(value)), self.assertRaises(ValueError):
                    decode_record(canonical(value))
