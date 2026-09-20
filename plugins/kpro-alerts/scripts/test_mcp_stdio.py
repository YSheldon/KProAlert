import asyncio
import os
import sys
import unittest
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    env = {k: v for k, v in os.environ.items() if not k.startswith('KPRO_')}
    params = StdioServerParameters(command=sys.executable,
        args=[str(Path(__file__).with_name('mcp_server.py'))], env=env)
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            initialized = await session.initialize()
            assert initialized.serverInfo.name == 'FalconPro'
            result = await session.list_tools()
            tools={t.name:t for t in result.tools}
            assert set(tools) == {'local_alerts', 'feishu_alerts', 'integration_status', 'alert_guidance', 'collector_status', 'endpoint_status', 'operations_events', 'operations_status', 'assess_event', 'propose_action', 'request_native_action', 'native_action_result', 'collect_native_action_result', 'diagnose_native_action'}
            writes={'assess_event','propose_action','request_native_action','collect_native_action_result'}
            assert all(t.annotations.readOnlyHint == (t.name not in writes) for t in result.tools)
            assert tools['request_native_action'].annotations.destructiveHint is True
            for name in ('native_action_result','diagnose_native_action'):
                assert tools[name].annotations.destructiveHint is False
            for name in ('local_alerts', 'feishu_alerts'):
                reply = await session.call_tool(name, {'limit': 1})
                assert 'not configured' in str(reply)
            status = await session.call_tool('integration_status', {})
            assert 'codeSha256' in str(status)
            guidance = await session.call_tool('alert_guidance', {'alert_id': 'a'*64})
            assert 'not configured' in str(guidance)
    print('PASS: stdio initialize, exact tool/permission contract, missing-configuration handling')


class McpStdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_stdio_contract(self):
        await main()


if __name__ == '__main__':
    asyncio.run(main())
