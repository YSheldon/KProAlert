import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest

from kpro_alert_bridge import Store
from spool import consume


def encoded(kind, payload, *, generation=4, created=1790000000, device=b'\x01' * 32):
    return struct.pack('<8sIIIIQQ32sQ32s16s', b'FPRTN1\0\0', 128, 1, kind, 0,
                       generation, created, device, len(payload), hashlib.sha256(payload).digest(), b'\0' * 16) + payload


def replica(*, batch='batch', records=None, dropped=2, projected=0, helper=b'\x02' * 32,
            generation=4, raw_hash=b'\x03' * 32, created=1790000000):
    if records is None:
        records = [dict(eventType=7, operation=8, sequence=1)]
    safe = dict(schema='KProSafeEventBatch/v1', redacted=True, session='session', batchId=batch,
                dropped=dropped, projectionDropped=projected, records=records,
                nativeSources=[dict(schema='FalconProCollectorSource/v1', batchSha256=raw_hash.hex(),
                                    recordIndex=i) for i in range(len(records))])
    safe_bytes = json.dumps(safe, separators=(',', ':')).encode()
    safe_hash = hashlib.sha256(safe_bytes).digest()
    payload = raw_hash + safe_hash + struct.pack('<QQQQII', 100, len(safe_bytes), len(records) + projected,
                                               dropped, 7, len(batch)) + b'session'.ljust(128, b'\0') + batch.encode().ljust(128, b'\0')
    prepared = encoded(4, payload, generation=generation, created=created)
    commit = encoded(6, hashlib.sha256(prepared).digest() + safe_hash + helper,
                     generation=generation, created=created)
    accepted = encoded(7, hashlib.sha256(commit).digest(), generation=generation, created=created)
    return dict(schema='FalconProSafeReplica/v1', preparedHex=prepared.hex(), commitHex=commit.hex(),
                acceptedHex=accepted.hex(), safeBase64=base64.b64encode(safe_bytes).decode())


def replace_safe(document, transform):
    safe = json.loads(base64.b64decode(document['safeBase64']))
    transform(safe)
    content = json.dumps(safe, separators=(',', ':')).encode()
    return bind_safe_bytes(document, content)


def bind_safe_bytes(document, content):
    result = copy.deepcopy(document)
    prepared = bytearray.fromhex(result['preparedHex'])
    prepared[160:192] = hashlib.sha256(content).digest()
    struct.pack_into('<Q', prepared, 200, len(content))
    prepared[80:112] = hashlib.sha256(prepared[128:]).digest()
    old_commit = bytes.fromhex(result['commitHex'])
    commit = encoded(6, hashlib.sha256(prepared).digest() + prepared[160:192] + old_commit[192:224])
    result.update(preparedHex=prepared.hex(), commitHex=commit.hex(),
                  acceptedHex=encoded(7, hashlib.sha256(commit).digest()).hex(),
                  safeBase64=base64.b64encode(content).decode())
    return result


class SafeReplicaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.queue = self.root / 'spool'
        self.queue.mkdir()
        self.database = self.root / 'events.db'

    def tearDown(self):
        self.temp.cleanup()

    def put(self, value, name='one.json'):
        path = self.queue / name
        path.write_text(json.dumps(value), encoding='utf-8')
        return path

    def test_new_replica_imports_once_without_attesting_public_metadata(self):
        self.put(replica())
        with Store(self.database) as store:
            result = consume(store, self.queue, 'host')
            self.assertEqual(result['importedFiles'], 1)
            self.assertEqual(result['importedEvents'], 1)
            self.assertEqual(result['sourceState'], 'analysis_only')
            self.assertFalse(result['nativeSourceVerified'])
            self.assertEqual(store.health()['reportedDropped'], 2)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM batch_sources').fetchone()[0], 1)

    def test_retired_safe_republication_is_idempotent_and_cannot_resurrect(self):
        from operations import events
        original = replica()
        retired = dict(original, reportedSourceState='retired')
        with Store(self.database) as store:
            self.assertEqual(store.ingest_replica('host', original), 1)
            uid = store.db.execute('SELECT id FROM events').fetchone()[0]
            before = events(self.database)['events'][0]
            self.assertEqual(store.ingest_replica('host', retired), 0)
            self.assertEqual(store.ingest_replica('host', original), 0)
            self.assertEqual(store.health()['reportedDropped'], 2)
        with Store(self.database) as reopened:
            self.assertEqual(reopened.ingest_replica('host', retired), 0)
        page = events(self.database)
        self.assertEqual(page.get('reportedSourceStates'), {uid: 'retired'})
        self.assertEqual(page.get('sourceStateProvenance'), 'unverified_public_metadata')
        self.assertFalse(page['nativeSourceVerified'])
        self.assertEqual(page['events'][0], before)

    def test_retirement_claim_has_one_bounded_non_authorizing_value(self):
        from safe_replica import parse_replica
        for state in ('active', 'executed', True, None, {'retired': True}):
            with self.subTest(state=state), self.assertRaises(ValueError):
                parse_replica(dict(replica(), reportedSourceState=state))

    def test_retiring_unselected_source_does_not_label_selected_source(self):
        from operations import events
        first = replica()
        second = replica(batch='second', raw_hash=b'\x05' * 32)
        with Store(self.database) as store:
            store.ingest_replica('host', first)
            store.ingest_replica('host', dict(second, reportedSourceState='retired'))
        page = events(self.database)
        self.assertEqual(page['reportedSourceStates'], {})
        self.assertEqual(page['events'][0]['nativeSource']['batchSha256'], (b'\x03' * 32).hex())
        with Store(self.database) as store:
            store.ingest_replica('host', dict(first, reportedSourceState='retired'))
        updated = events(self.database)
        self.assertEqual(updated['reportedSourceStates'], {page['events'][0]['eventId']: 'retired'})
        self.assertEqual(updated['events'], page['events'])

    def test_retirement_follows_preserved_inline_locator_not_first_replica(self):
        from operations import events
        locator = dict(schema='FalconProCollectorSource/v1', batchSha256=(b'\x05' * 32).hex(), recordIndex=0)
        with Store(self.database) as store:
            store.ingest('host', 'session', dict(eventType=7, operation=8, sequence=1, _nativeSource=locator))
            store.ingest_replica('host', dict(replica(), reportedSourceState='retired'))
            store.ingest_replica('host', replica(batch='second', raw_hash=b'\x05' * 32))
        page = events(self.database)
        self.assertEqual(page['reportedSourceStates'], {})
        self.assertEqual(page['events'][0]['nativeSource'], locator)
        with Store(self.database) as store:
            store.ingest_replica('host', dict(replica(batch='second', raw_hash=b'\x05' * 32),
                                              reportedSourceState='retired'))
        updated = events(self.database)
        self.assertEqual(updated['reportedSourceStates'], {page['events'][0]['eventId']: 'retired'})
        self.assertEqual(updated['events'], page['events'])

    def test_independent_cpp_and_rust_fixture_binds_original_safe_bytes(self):
        from safe_replica import loads_replica
        content = (Path(__file__).parent / 'fixtures' / 'safe-replica-v1.json').read_bytes()
        parsed = loads_replica(content)
        self.assertEqual(parsed.commit_id, 'd28ccc23ae9baacaff31aa3e27f5cdecf2e9d3d0ecbc33abfdeb8a84c41654e6')
        self.assertEqual(parsed.raw_hash, '2883af47ec413b55d8268c64878d7ecf642c7cd1c0e340ba625c2d0dbd573aa5')
        self.assertEqual((parsed.session, parsed.batch, parsed.records, parsed.collector_dropped),
                         ('session', '9', ({'eventType': 7, 'operation': 8, 'sequence': 12},), 3))
        with Store(self.database) as store:
            self.assertEqual(store.ingest_replica('synthetic', content), 1)
            self.assertEqual(store.ingest_replica('synthetic', content), 0)
            self.assertEqual(store.health()['reportedDropped'], 3)
        corrupted = json.loads(content)
        corrupted['acceptedHex'] = corrupted['acceptedHex'][:-2] + '00'
        with self.assertRaises(ValueError):
            loads_replica(json.dumps(corrupted).encode())

    def test_renamed_and_new_helper_replicas_share_one_source_and_loss(self):
        self.put(replica(), 'one.json')
        with Store(self.database) as store:
            self.assertEqual(consume(store, self.queue, 'host')['importedEvents'], 1)
        self.put(replica(helper=b'\x04' * 32), 'renamed.json')
        with Store(self.database) as store:
            self.assertEqual(consume(store, self.queue, 'host')['importedEvents'], 0)
            self.assertEqual(store.health()['reportedDropped'], 2)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM batch_sources').fetchone()[0], 1)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM batch_commits').fetchone()[0], 2)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM batches').fetchone()[0], 1)

    def test_same_producer_changed_content_or_created_time_rejected(self):
        with Store(self.database) as store:
            self.assertEqual(store.ingest_replica('host', replica()), 1)
            for changed in (replica(raw_hash=b'\x05' * 32), replica(dropped=3), replica(created=1790000001)):
                with self.assertRaises(ValueError):
                    store.ingest_replica('host', changed)
            self.assertEqual(store.health()['reportedDropped'], 2)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM batch_sources').fetchone()[0], 1)

    def test_multiple_batches_link_same_event_without_changing_raw(self):
        with Store(self.database) as store:
            self.assertEqual(store.ingest_replica('host', replica()), 1)
            original = store.db.execute('SELECT id,raw FROM events').fetchone()
            self.assertEqual(store.ingest_replica('host', replica(batch='second', raw_hash=b'\x05' * 32)), 0)
            self.assertEqual(store.db.execute('SELECT id,raw FROM events').fetchone(), original)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM event_batches').fetchone()[0], 2)
            self.assertEqual(store.health()['reportedDropped'], 4)
            self.assertEqual(store.source_for_event(original[0]),
                             dict(schema='FalconProCollectorSource/v1', batchSha256='03' * 32, recordIndex=0))
            self.assertNotIn('_nativeSource', json.loads(original[1]))
        from operations import evidence, events
        current = evidence(self.database, original[0])
        self.assertEqual(current['nativeSource']['batchSha256'], '03' * 32)
        self.assertEqual(current['sourceAttestation'], 'not_verified_by_native_broker')
        page = events(self.database)
        self.assertFalse(page['nativeSourceVerified'])
        self.assertEqual(page['reportedDropped'], 4)

    def test_existing_valid_legacy_locator_is_preserved_when_content_matches(self):
        legacy = dict(eventType=7, operation=8, sequence=1,
                      _nativeSource=dict(schema='FalconProCollectorSource/v1', batchSha256='aa' * 32, recordIndex=2))
        with Store(self.database) as store:
            store.ingest('host', 'session', legacy)
            original = store.db.execute('SELECT id,raw FROM events').fetchone()
            self.assertEqual(store.ingest_replica('host', replica()), 0)
            self.assertEqual(store.db.execute('SELECT id,raw FROM events').fetchone(), original)
            self.assertEqual(store.source_for_event(original[0]), legacy['_nativeSource'])
        from operations import evidence
        self.assertEqual(evidence(self.database, original[0])['nativeSource'], legacy['_nativeSource'])

    def test_query_time_locator_is_bound_to_decision_without_rewriting_event(self):
        from operations import Operations, evidence
        from native_actions import submission
        with Store(self.database) as store:
            store.ingest_replica('host', replica())
            original = store.db.execute('SELECT id,raw FROM events').fetchone()
        event = evidence(self.database, original[0])
        with Operations(self.root / 'synthetic-ops.db', self.database, 'codex') as ops:
            decision = ops.assess(event['eventId'], event['evidenceSha256'], 'suspicious', 75,
                                  ['bulk_overwrite'], ['switch_to_enforce'], 'test', '1' * 32)
            request = ops.propose(decision['recordId'], 'switch_to_enforce', '2' * 32)
            self.assertEqual(submission(ops, request['recordId'])['nativeSource']['batchSha256'], '03' * 32)
            with Store(self.database) as store:
                store.ingest_replica('host', replica(batch='second', raw_hash=b'\x05' * 32))
            self.assertEqual(evidence(self.database, original[0])['evidenceSha256'], event['evidenceSha256'])
            with Store(self.database) as store:
                with store.db:
                    store.db.execute('UPDATE batch_sources SET raw_hash=? WHERE raw_hash=?', ('aa' * 32, '03' * 32))
                self.assertEqual(store.db.execute('SELECT id,raw FROM events').fetchone(), original)
            with self.assertRaisesRegex(ValueError, 'evidence changed'):
                submission(ops, request['recordId'])

    def test_conflicting_sequence_rolls_back_events_sources_loss_and_links(self):
        with Store(self.database) as store:
            store.ingest_replica('host', replica())
            changed = replica(batch='second', records=[dict(eventType=7, operation=8, sequence=2),
                                                       dict(eventType=7, operation=16, sequence=1)])
            with self.assertRaises(ValueError):
                store.ingest_replica('host', changed)
            for table in ('events', 'batches', 'batch_sources', 'batch_commits', 'event_batches'):
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 1)

    def test_database_failure_rolls_back_complete_native_transaction(self):
        with Store(self.database) as store:
            store.db.execute("CREATE TRIGGER fail_links BEFORE INSERT ON event_batches BEGIN SELECT RAISE(ABORT,'test failure'); END")
            with self.assertRaises(sqlite3.Error):
                store.ingest_replica('host', replica())
            for table in ('events', 'batches', 'batch_sources', 'batch_commits', 'event_batches'):
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0)

    def test_capacity_failure_never_archives_or_partially_commits(self):
        path = self.put(replica(records=[dict(eventType=7, operation=8, sequence=i) for i in (1, 2)]))
        with Store(self.database, max_events=1) as store:
            self.assertEqual(consume(store, self.queue, 'host', archive=True)['failedFiles'], 1)
            self.assertTrue(path.exists())
            for table in ('events', 'batches', 'batch_sources', 'batch_commits', 'event_batches'):
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0)

    def test_health_reports_actual_database_wal_and_shm_file_lengths(self):
        with Store(self.database) as store:
            store.ingest_replica('host', replica())
            state = store.health()
            sizes = [path.stat().st_size if path.exists() else 0 for path in
                     (self.database, Path(str(self.database) + '-wal'), Path(str(self.database) + '-shm'))]
            self.assertEqual([state['databaseFileBytes'], state['databaseWalBytes'], state['databaseShmBytes']], sizes)
            self.assertEqual(state['databaseTotalFileBytes'], sum(sizes))
            self.assertGreater(state['databaseWalBytes'], 0)
            self.assertGreater(state['databaseShmBytes'], 0)
            self.assertEqual(state['storageBudgetState'], 'within_observed_limit')
            self.assertEqual(state['storageBudgetEnforcement'], 'observed_before_ingest_not_transaction_hard_cap')
            self.assertEqual(state['storageByteLimit'], 512 * 1024 * 1024)

    def test_observed_physical_budget_blocks_native_and_legacy_imports_without_cleanup(self):
        from kpro_alert_bridge import ingest_document
        with Store(self.database, max_storage_bytes=1) as store:
            before = store.health()
            self.assertEqual(before['storageBudgetState'], 'at_or_over_observed_limit')
            with self.assertRaisesRegex(RuntimeError, 'storage budget'):
                store.ingest_replica('host', replica())
            with self.assertRaisesRegex(RuntimeError, 'storage budget'):
                store.ingest('host', 'old', dict(eventType=7, operation=8, sequence=1))
            with self.assertRaisesRegex(RuntimeError, 'storage budget'):
                ingest_document(store, 'host', dict(session='old', dropped=2, records=[]))
            for table in ('events', 'batches', 'batch_sources', 'batch_commits', 'event_batches', 'deliveries'):
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0)
            self.assertEqual(store.health()['databaseTotalFileBytes'], before['databaseTotalFileBytes'])
            self.assertFalse(store.db.in_transaction)

    def test_storage_budget_rejects_invalid_limits(self):
        for limit in (0, -1, True, 512 * 1024 * 1024 + 1, 1.0):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                Store(self.database, max_storage_bytes=limit)

    def test_u64_losses_and_projection_remain_exact_across_sources(self):
        with Store(self.database) as store:
            maximum = 2**64 - 1
            store.ingest_replica('host', replica(records=[], dropped=maximum, projected=1024))
            store.ingest_replica('host', replica(records=[], dropped=maximum, projected=1024, helper=b'\x04' * 32))
            store.ingest_replica('host', replica(batch='second', records=[], dropped=maximum))
            self.assertEqual(store.health()['reportedDropped'], maximum * 2 + 1024)
            self.assertEqual(store.db.execute('SELECT SUM(dropped) FROM batches').fetchone()[0], 0)
        from operations import events
        self.assertEqual(events(self.database)['reportedDropped'], maximum * 2 + 1024)

    def test_migration_keeps_old_four_column_batches_events_and_deliveries(self):
        db = sqlite3.connect(self.database)
        db.executescript('CREATE TABLE events(id TEXT PRIMARY KEY,device TEXT,session TEXT,received TEXT,raw TEXT NOT NULL);'
                         'CREATE TABLE batches(id TEXT PRIMARY KEY,device TEXT,session TEXT,dropped INTEGER);'
                         'CREATE TABLE deliveries(id TEXT PRIMARY KEY,state TEXT,record_id TEXT,payload TEXT);')
        db.execute('INSERT INTO events VALUES (?,?,?,?,?)', ('a' * 64, 'host', 'old', '2026-09-26T00:00:00+00:00',
                                                           '{"eventType":7,"operation":8,"sequence":9}'))
        db.execute('INSERT INTO batches VALUES (?,?,?,?)', ('old', 'host', 'old', 9))
        db.execute('INSERT INTO deliveries VALUES (?,?,?,?)', ('old', 'pending', None, 'unchanged'))
        db.commit(); db.close()
        with Store(self.database) as store:
            store.db.execute('INSERT INTO batches VALUES (?,?,?,?)', ('positional', 'host', 'old', 1))
            store.db.commit()
            self.assertIsNone(store.source_for_event('a' * 64))
            self.assertEqual(store.ingest_replica('host', replica()), 1)
            self.assertEqual(store.health()['reportedDropped'], 12)
            self.assertEqual(store.db.execute('SELECT * FROM deliveries').fetchone(), ('old', 'pending', None, 'unchanged'))
            self.assertEqual(len(store.db.execute('PRAGMA table_info(batches)').fetchall()), 4)
            self.assertEqual(store.db.execute('PRAGMA synchronous').fetchone()[0], 2)
            self.assertEqual(store.db.execute('PRAGMA journal_mode').fetchone()[0], 'wal')

    def test_invalid_shapes_hashes_counts_and_private_fields_are_rejected(self):
        from safe_replica import parse_replica
        original = replica()
        cases = []
        for field in ('preparedHex', 'commitHex', 'acceptedHex'):
            bad = dict(original); bad[field] = bad[field][:-2]; cases.append(bad)
            bad = dict(original); bad[field] = bad[field].upper(); cases.append(bad)
            bad = dict(original); bad[field] = '00' + bad[field][2:]; cases.append(bad)
        for mutation in (lambda d: d.update(path='private'), lambda d: d.update(redacted=True),
                         lambda d: d.update(safeBase64=d['safeBase64'] + '\n'),
                         lambda d: d.update(safeBase64=True)):
            bad = dict(original); mutation(bad); cases.append(bad)
        for mutation in (lambda s: s['records'][0].update(path='private'),
                         lambda s: s['records'][0].update(newField=1),
                         lambda s: s['records'][0].update(sequence=True),
                         lambda s: s['records'][0].update(reportOnly=1),
                         lambda s: s.update(dropped=True), lambda s: s.update(session='other'),
                         lambda s: s.update(projectionDropped=1), lambda s: s.update(nativeSources=[]),
                         lambda s: s['nativeSources'][0].update(recordIndex=1),
                         lambda s: s['nativeSources'][0].update(batchSha256='04' * 32)):
            cases.append(replace_safe(original, mutation))
        for bad in cases:
            with self.subTest(case=cases.index(bad)), self.assertRaises(ValueError):
                parse_replica(bad)

    def test_duplicate_json_keys_and_noncanonical_base64_are_rejected(self):
        from safe_replica import loads_replica
        raw = json.dumps(replica())
        with self.assertRaises(ValueError):
            loads_replica(raw.replace('{', '{"schema":"FalconProSafeReplica/v1",', 1).encode())
        doc = replica()
        safe = base64.b64decode(doc['safeBase64']).replace(b'{', b'{"schema":"KProSafeEventBatch/v1",', 1)
        doc = bind_safe_bytes(doc, safe)
        with self.assertRaises(ValueError):
            loads_replica(json.dumps(doc).encode())
        doc = replica(); doc['safeBase64'] += '='
        with self.assertRaises(ValueError):
            loads_replica(json.dumps(doc).encode())

    def test_records_and_replica_decoded_size_are_bounded(self):
        from safe_replica import loads_replica, parse_replica
        valid = replica(records=[dict(eventType=7, operation=8, sequence=i) for i in range(1024)])
        self.assertEqual(len(parse_replica(valid).records), 1024)
        with self.assertRaises(ValueError):
            parse_replica(replica(records=[dict(eventType=7, operation=8, sequence=i) for i in range(1025)]))
        with self.assertRaises(ValueError):
            loads_replica(b' ' * (12 * 1024 * 1024 + 1))
        bad = replica(); bad['safeBase64'] = base64.b64encode(b' ' * (8 * 1024 * 1024 + 1)).decode()
        with self.assertRaises(ValueError):
            parse_replica(bad)

    def test_full_eight_mib_safe_replica_is_not_limited_by_legacy_five_mib_limit(self):
        document = replica()
        safe = base64.b64decode(document['safeBase64'])
        document = bind_safe_bytes(document, safe + b' ' * (8 * 1024 * 1024 - len(safe)))
        self.put(document)
        with Store(self.database) as store:
            result = consume(store, self.queue, 'host')
            self.assertEqual(result['importedEvents'], 1)
            self.assertEqual(result['failedFiles'], 0)

    def test_deeply_nested_invalid_file_cannot_prevent_next_valid_import(self):
        path = self.queue / 'bad.json'
        path.write_text('[' * 2000 + '0' + ']' * 2000)
        self.put(replica(), 'valid.json')
        with Store(self.database) as store:
            result = consume(store, self.queue, 'host')
            self.assertEqual((result['importedFiles'], result['failedFiles']), (1, 1))
            self.assertTrue(path.exists())

    def test_hardlinked_inputs_are_rejected_without_import(self):
        original = self.put(replica(), 'source.data')
        os.link(original, self.queue / 'hard.json')
        with Store(self.database) as store:
            result = consume(store, self.queue, 'host')
            self.assertEqual(result['failedFiles'], 1)
            self.assertEqual(store.health()['storedEvents'], 0)

    def test_symlinked_inputs_are_rejected_without_import(self):
        original = self.put(replica(), 'source.data')
        try:
            (self.queue / 'symbolic.json').symlink_to(original)
        except OSError as exc:
            self.skipTest('Host does not grant symlink creation: ' + str(getattr(exc, 'winerror', exc.errno)))
        with Store(self.database) as store:
            self.assertEqual(consume(store, self.queue, 'host')['failedFiles'], 1)
            self.assertEqual(store.health()['storedEvents'], 0)

    def test_replicas_archive_only_after_commit_and_reimport_by_identity(self):
        path = self.put(replica())
        with Store(self.database) as store:
            self.assertEqual(consume(store, self.queue, 'host', archive=True)['importedEvents'], 1)
            self.assertFalse(path.exists())
            self.put(replica(), 'again.json')
            self.assertEqual(consume(store, self.queue, 'host', archive=True)['importedEvents'], 0)
            self.assertEqual(store.health()['reportedDropped'], 2)


if __name__ == '__main__':
    unittest.main()
