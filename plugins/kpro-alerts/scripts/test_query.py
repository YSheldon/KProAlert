import sqlite3
import tempfile
import unittest
from pathlib import Path
from query import recent


class QueryTests(unittest.TestCase):
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
                           ('1','h','b','2026-09-08', '{"eventType":7,"operation":8,"cmdline":"SECRET"}'))
            db.close()
            result = recent(p, 1)
            self.assertEqual(result[0]['eventType'], 7)
            self.assertNotIn('SECRET', str(result))


if __name__ == '__main__':
    unittest.main()
