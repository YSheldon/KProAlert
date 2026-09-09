from pathlib import Path
import unittest


class PrivateSpoolTests(unittest.TestCase):
    def test_raw_acl_and_manifest_gate(self):
        source=(Path(__file__).resolve().parents[3]/'Install-KProAlert.ps1').read_text(encoding='utf-8-sig')
        for text in ('privateRawEventSpool','private-event-spool','SetOwner',
                     'AreAccessRulesProtected','Win32_Processor','windows11-x64',
                     "@('private-event-spool', 'logs')"):
            self.assertTrue(text in source, 'Missing installer gate: '+text)
        self.assertLess(source.index("'private-event-spool'"),source.index('New-KProProtectionService $serviceExe'))


if __name__=='__main__': unittest.main()
