import sqlite3
import tempfile
import unittest
from pathlib import Path
from query import recent, by_id


class QueryTests(unittest.TestCase):
    def test_exact_guidance_lookup_does_not_leak_raw_fields(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE events(id,raw)')
                db.execute('INSERT INTO events VALUES(?,?)',('a'*64,'{"eventType":7,"path":"SECRET","reportOnly":true}'))
            db.close()
            result=by_id(path,'a'*64)
            self.assertEqual(result['eventType'],7)
            self.assertNotIn('SECRET',str(result))
            with self.assertRaises(ValueError): by_id(path,'b'*64)

    def test_missing_database_not_created(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'missing.db'
            with self.assertRaises(FileNotFoundError):
                recent(p, 10)
            self.assertFalse(p.exists())

    def test_safe_projection(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'events.db'
            with sqlite3.connect(p) as db:
                db.execute('CREATE TABLE events(id,device,session,received,raw)')
                db.execute('INSERT INTO events VALUES(?,?,?,?,?)',
                           ('a'*64,'SECRET-DEVICE','SECRET-SESSION','2026-09-08', '{"eventType":7,"operation":8,"cmdline":"SECRET"}'))
            db.close()
            result = recent(p, 1)
            self.assertEqual(result[0]['eventType'], 7)
            self.assertNotIn('SECRET', str(result))


if __name__ == '__main__':
    unittest.main()
