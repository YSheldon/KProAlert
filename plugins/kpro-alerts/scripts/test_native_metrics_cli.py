import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]


class NativeMetricsCliTests(unittest.TestCase):
    def test_disabled_metrics_never_opens_native_entry(self):
        with tempfile.TemporaryDirectory() as folder:
            database=Path(folder)/'metrics.db'
            result=subprocess.run([sys.executable,str(ROOT/'falconpro.py'),'metrics-native',
                '--database',str(database),'--entry','C:\\missing\\FalconProSetup.exe',
                '--entry-sha256','a'*64,'--device-id','b'*64,'--transaction','c'*32],
                capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['state'],'metrics_disabled')
            self.assertFalse(database.exists())


if __name__=='__main__':
    unittest.main()
