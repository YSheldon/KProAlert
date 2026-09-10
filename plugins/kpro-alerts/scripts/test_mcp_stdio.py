import asyncio
import os
import sys
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
            assert {t.name for t in result.tools} == {'local_alerts', 'feishu_alerts', 'integration_status', 'alert_guidance', 'collector_status', 'endpoint_status'}
            assert all(t.annotations.readOnlyHint for t in result.tools)
            for name in ('local_alerts', 'feishu_alerts'):
                reply = await session.call_tool(name, {'limit': 1})
                assert 'not configured' in str(reply)
            status = await session.call_tool('integration_status', {})
            assert 'codeSha256' in str(status)
            guidance = await session.call_tool('alert_guidance', {'alert_id': 'a'*64})
            assert 'not configured' in str(guidance)
    print('PASS: stdio initialize, read-only tools, missing-configuration handling')


if __name__ == '__main__':
    asyncio.run(main())
