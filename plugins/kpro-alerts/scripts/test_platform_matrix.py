import unittest

from release_platforms import layout_for_platform, platform_for_os


class PlatformMatrixTests(unittest.TestCase):
    def test_win7_sp1_and_win8_select_legacy_native_images(self):
        self.assertEqual(platform_for_os('6.1', 7601, 'x64'), 'windows7-x64')
        self.assertEqual(platform_for_os('6.1', 7601, 'x86'), 'windows7-x86')
        self.assertEqual(platform_for_os('6.2', 9200, 'x64'), 'windows7-x64')
        self.assertEqual(platform_for_os('6.2', 9200, 'x86'), 'windows7-x86')
        self.assertTrue(layout_for_platform('windows7-x64')['legacy'])
        self.assertTrue(layout_for_platform('windows7-x86')['legacy'])

    def test_win7_without_sp1_is_rejected(self):
        with self.assertRaises(ValueError):
            platform_for_os('6.1', 7600, 'x64')

    def test_modern_platforms_keep_native_architecture(self):
        for version, build, expected in (
                ('6.3', 9600, 'windows81-x64'),
                ('10.0', 19045, 'windows10-x64'),
                ('10.0', 19045, 'windows10-x86'),
                ('10.0', 22000, 'windows11-x64')):
            architecture = 'x86' if expected.endswith('x86') else 'x64'
            self.assertEqual(platform_for_os(version, build, architecture), expected)
        self.assertEqual(platform_for_os('10.0', 22000, 'arm64'), 'windows11-arm64')

    def test_invalid_server_and_arm64_downlevel(self):
        for version, build, architecture in (('10.0', 20348, 'x64'), ('6.1', 7601, 'arm64')):
            with self.assertRaises(ValueError):
                platform_for_os(version, build, architecture, product_type=3)
        with self.assertRaises(ValueError):
            platform_for_os('6.3', 9600, 'arm64')

    def test_x86_layout_names_are_distinct(self):
        legacy = layout_for_platform('windows7-x86')
        modern = layout_for_platform('windows10-x86')
        self.assertEqual((legacy['service'], legacy['dll'], legacy['driver']),
                         ('KProSvc32.exe', 'KProProtect32.dll', 'KProFilter32.sys'))
        self.assertEqual((modern['service'], modern['dll'], modern['driver']),
                         ('KProSvc32.exe', 'KProProtect32.dll', 'KProFilter32.sys'))
        self.assertFalse(modern['legacy'])


if __name__ == '__main__':
    unittest.main()
