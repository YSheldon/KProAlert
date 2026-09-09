import unittest
import json
from types import SimpleNamespace
from unittest.mock import patch
from feishu_reader import project, read


class ProjectionTests(unittest.TestCase):
    def test_recent_first_and_bounded_page(self):
        response = dict(ok=True, data=dict(fields=[], data=[], has_more=False))
        with patch('feishu_reader.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(response))) as call:
            read('cli', 'base', 'table', 20, offset=40)
            command = call.call_args.args[0]
            self.assertEqual(command[command.index('--offset')+1], '40')
            self.assertEqual(json.loads(command[command.index('--sort-json')+1]), [{'field':'末次时间','desc':True}])

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
