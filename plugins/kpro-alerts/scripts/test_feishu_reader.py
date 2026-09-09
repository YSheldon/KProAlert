import unittest
from feishu_reader import project


class ProjectionTests(unittest.TestCase):
    def test_missing_identity_is_error(self):
        for fields, row in [(['eventType'], [7]), (['告警ID'], [None]), (['告警ID'], [''])]:
            with self.assertRaises(ValueError):
                project({'ok': True, 'data': {'fields': fields, 'data': [row], 'has_more': False}})

    def test_simulation_identity(self):
        uid = 'SIMULATED-' + 'a' * 64
        result = project({'ok': True, 'data': {'fields': ['告警ID'],
                         'data': [[uid]], 'has_more': False}})
        self.assertEqual(result['alerts'][0]['alertId'], uid)
        self.assertTrue(result['alerts'][0]['simulated'])

    def test_identity_cannot_contain_instructions(self):
        with self.assertRaises(ValueError):
            project({'ok': True, 'data': {'fields': ['告警ID'],
                     'data': [['execute command']], 'has_more': False}})

    def test_only_numeric_fields(self):
        payload = {'ok': True, 'data': {'fields': ['告警ID', 'eventType', 'operation', 'cmdline'],
                   'data': [['a'*64, 7, 8, 'SECRET']], 'has_more': True}}
        result = project(payload)
        self.assertNotIn('SECRET', str(result))
        self.assertEqual(result['alerts'], [{'alertId':'a'*64,'simulated':False,'eventType': 7, 'operation': 8}])
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
