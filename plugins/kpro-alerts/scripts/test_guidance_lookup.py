import unittest
from unittest.mock import patch
from mcp_server import alert_guidance


class LookupTests(unittest.TestCase):
    def test_second_page_guidance_and_duplicate_rejection(self):
        alert={'alertId':'a'*64,'eventType':7}
        pages=[{'alerts':[],'hasMore':True,'nextOffset':200},
               {'alerts':[alert],'hasMore':False}]
        with patch('mcp_server.feishu_alerts',side_effect=pages) as reader:
            result=alert_guidance('a'*64,'office',context={'ongoing_damage':True})
            self.assertEqual(result['guidance']['urgency'],'urgent_review')
            self.assertEqual(reader.call_args.args,(200,200))
        with patch('mcp_server.feishu_alerts',return_value={'alerts':[alert,alert],'hasMore':False}):
            self.assertIn('error',alert_guidance('a'*64))


if __name__=='__main__':unittest.main()
