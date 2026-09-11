from pathlib import Path
import unittest


class PrivateSpoolTests(unittest.TestCase):
    def test_privileged_paths_do_not_come_from_environment(self):
        root=Path(__file__).resolve().parents[3]
        for name in ('Install-KProAlert.ps1','Uninstall-KProAlert.ps1'):
            source=(root/name).read_text(encoding='utf-8-sig')
            self.assertNotIn('$env:ProgramFiles', source)
            self.assertNotIn('$env:SystemRoot', source)
            self.assertIn('Get-KProNativeProgramFiles', source)
            self.assertIn('Assert-KProProgramFilesRoot', source)

    def test_raw_acl_and_manifest_gate(self):
        source=(Path(__file__).resolve().parents[3]/'Install-KProAlert.ps1').read_text(encoding='utf-8-sig')
        for text in ('privateRawEventSpool','private-event-spool','SetOwner',
                     'AreAccessRulesProtected','Win32_Processor','Get-KProPackageLayout',
                     '$processorArchitectures[0] -notin @(9,12)',
                     "@('private-event-spool', 'logs')"):
            self.assertTrue(text in source, 'Missing installer gate: '+text)
        self.assertLess(source.index("'private-event-spool'"),source.index('New-KProProtectionService $serviceExe'))


if __name__=='__main__': unittest.main()
