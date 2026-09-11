"""Plan/register the query component; never installs Windows protection."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from setup_config import build_config


def discover_client(client):
    if client == 'codex':
        command = shutil.which('codex')
        if command:
            path = Path(command)
            if os.name == 'nt' and path.suffix.lower() in ('.cmd', '.ps1'):
                entry = path.parent/'node_modules/@openai/codex/bin/codex.js'
                node = shutil.which('node')
                if node and entry.is_file():
                    return [node, str(entry)]
                raise ValueError('Supply a native Codex executable; shell shims are not invoked.')
            return [command]
    if client == 'workbuddy' and os.name == 'nt':
        entry = Path(os.environ.get('LOCALAPPDATA', ''))/'Programs/WorkBuddy/resources/app.asar.unpacked/cli/bin/codebuddy'
        node = shutil.which('node')
        if node and entry.is_file():
            return [node, str(entry)]
    raise ValueError('Client command was not found; use the application native MCP interface.')


def make_plan(client, database=None, cli=None, base=None, table=None,
              client_command=None, workbuddy_config=None, collector_health=None, endpoint_device_id=None):
    if client not in ('codex', 'workbuddy', 'cursor', 'grok', 'generic'):
        raise ValueError('Unsupported assistant')
    onboarding_only = not any((database, cli, base, table))
    server = build_config(database, cli, base, table, collector_health, endpoint_device_id,
                          onboarding_only=onboarding_only)['mcpServers']['kpro-alerts']
    command = []
    if client in ('codex', 'workbuddy'):
        command = client_command or discover_client(client)
        if not command or any(not isinstance(s, str) for s in command):
            raise ValueError('Invalid native client command')
        if not Path(command[0]).is_file():
            raise ValueError('Client executable does not exist')
    return dict(schema='KProAssistantSetup/v1', client=client, server=server,
                onboardingOnly=onboarding_only, dataSourcesConfigured=not onboarding_only,
                clientCommand=command, workbuddyConfig=str(Path(workbuddy_config or Path.home()/'.workbuddy').absolute()),
                installsDriver=False, registersBackgroundTask=False,
                requiresAdministrator=False, automaticRemediation=False)


def equivalent(actual, desired):
    return (isinstance(actual, dict) and actual.get('command') == desired['command'] and
            actual.get('args', []) == desired['args'] and
            actual.get('env', {}) == desired['env'])


def register(plan, runner=subprocess.run):
    client, server, prefix = plan['client'], plan['server'], plan['clientCommand']
    if client == 'cursor':
        return dict(registration='host_tool_required', hostTool='Cursor MCP settings',
                    serverName='kpro-alerts', configuration={'mcpServers':{'kpro-alerts':server}},
                    configPath=str(Path.home()/'.cursor'/'mcp.json'),
                    preserveExistingServers=True, clientRuntimeVerified=False,
                    protectionInstalled=False)
    if client in ('grok', 'generic'):
        return dict(registration='host_tool_required', hostTool='AddMcpServer' if client == 'grok' else 'native MCP configuration',
                    serverName='kpro-alerts', server=server, clientRuntimeVerified=False, protectionInstalled=False)
    inherited = {'PATH','PATHEXT','SYSTEMROOT','WINDIR','COMSPEC','TEMP','TMP','TMPDIR',
                 'HOME','USERPROFILE','APPDATA','LOCALAPPDATA','PROGRAMDATA','PROGRAMFILES','PROGRAMFILES(X86)',
                 'HOMEDRIVE','HOMEPATH','USERNAME','USERDOMAIN','LANG','LC_ALL','CODEX_HOME',
                 'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','SSL_CERT_FILE','REQUESTS_CA_BUNDLE'}
    env = {key:value for key,value in os.environ.items() if key.upper() in inherited}
    config_path = None
    if client == 'workbuddy':
        folder = Path(plan['workbuddyConfig'])
        env['CODEBUDDY_CONFIG_DIR'] = str(folder)
        config_path = next((folder/n for n in ('.mcp.json', 'mcp.json') if (folder/n).is_file()), folder/'.mcp.json')
        existing = json.loads(config_path.read_text(encoding='utf-8-sig')) if config_path.exists() else {}
        servers = existing.get('mcpServers') or {}
        if not isinstance(servers, dict):
            raise RuntimeError('Unsupported existing MCP configuration; no change made')
        actual = servers.get('kpro-alerts')
        if 'kpro-alerts' in servers and not isinstance(actual,dict):
            raise RuntimeError('Existing connector schema is invalid; no change made')
    else:
        result = runner(prefix+['mcp','get','kpro-alerts','--json'], capture_output=True, text=True, timeout=30, env=env)
        if result.returncode == 0:
            existing = json.loads(result.stdout)
            if existing.get('enabled') is False:
                raise RuntimeError('Existing connector is disabled; no change made')
            actual = existing.get('transport')
            if not isinstance(actual,dict):
                raise RuntimeError('Existing connector schema is invalid; no change made')
        elif "No MCP server named 'kpro-alerts' found" in getattr(result,'stderr',''):
            actual = None
        else:
            raise RuntimeError('Cannot establish connector absence; no change made')
    if actual is not None:
        if not equivalent(actual, server):
            raise RuntimeError('Existing kpro-alerts differs; preserve it and review before updating')
        return dict(registration='unchanged', clientRuntimeVerified=False, protectionInstalled=False)
    if client == 'codex':
        args = prefix+['mcp','add','kpro-alerts']
        for key, value in server['env'].items():
            args += ['--env',key+'='+value]
        args += ['--',server['command'],*server['args']]
    else:
        args = prefix+['mcp','add-json','--scope','user','kpro-alerts',json.dumps(dict(type='stdio',**server))]
    result = runner(args, capture_output=True, text=True, timeout=30, env=env)
    if result.returncode:
        raise RuntimeError('Registration failed; inspect client locally, do not blindly retry')
    if client == 'codex':
        result = runner(prefix+['mcp','get','kpro-alerts','--json'], capture_output=True, text=True, timeout=30, env=env)
        if result.returncode:
            raise RuntimeError('Registration readback failed')
        actual = json.loads(result.stdout).get('transport')
    else:
        folder = Path(plan['workbuddyConfig'])
        config_path = next((folder/n for n in ('.mcp.json','mcp.json') if (folder/n).is_file()), config_path)
        actual = json.loads(config_path.read_text(encoding='utf-8-sig')).get('mcpServers',{}).get('kpro-alerts')
    if not equivalent(actual, server):
        raise RuntimeError('Registration readback differs; no automatic overwrite')
    return dict(registration='configured', clientRuntimeVerified=False, protectionInstalled=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', choices=['codex','workbuddy','cursor','grok','generic'], required=True)
    parser.add_argument('--database')
    parser.add_argument('--cli')
    parser.add_argument('--base')
    parser.add_argument('--table')
    parser.add_argument('--workbuddy-config')
    parser.add_argument('--collector-health')
    parser.add_argument('--endpoint-device-id')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    plan = make_plan(args.client,args.database,args.cli,args.base,args.table,
                     workbuddy_config=args.workbuddy_config,collector_health=args.collector_health,
                     endpoint_device_id=args.endpoint_device_id)
    if args.apply:
        # Probe this interpreter, not a different PATH Python. No package download here.
        probe = subprocess.run([plan['server']['command'],'-I','-c',
            "import importlib.metadata; assert importlib.metadata.version('mcp') == '1.30.0'"],
            capture_output=True, text=True, timeout=15)
        if probe.returncode:
            raise RuntimeError('Run the repository venv setup first; MCP 1.30.0 is required')
        print(json.dumps(register(plan),ensure_ascii=True))
    else:
        print(json.dumps(plan,ensure_ascii=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'error':str(exc),'registration':'not_confirmed','protectionInstalled':False},ensure_ascii=True))
        raise SystemExit(1)
