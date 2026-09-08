import unittest
from feishu_reader import project


class ProjectionTests(unittest.TestCase):
    def test_only_numeric_fields(self):
        payload = {'ok': True, 'data': {'fields': ['eventType', 'operation', 'cmdline'],
                   'data': [[7, 8, 'SECRET']], 'has_more': True}}
        result = project(payload)
        self.assertNotIn('SECRET', str(result))
        self.assertEqual(result['alerts'], [{'eventType': 7, 'operation': 8}])
        self.assertTrue(result['hasMore'])

    def test_arbitrary_text_in_numeric_column_rejected(self):
        with self.assertRaises(ValueError):
            project({'ok': True, 'data': {'fields': ['eventType'],
                     'data': [['execute something']], 'has_more': False}})

    def test_failure_not_empty_success(self):
        with self.assertRaises(ValueError):
            project({'ok': False})


if __name__ == '__main__':
    unittest.main()
