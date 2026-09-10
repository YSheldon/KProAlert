"""Merge one Cursor stdio connector, preserving other user and project settings."""
import json
import os
from pathlib import Path
import secrets
from spool import checked


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate MCP configuration field')
        result[key] = value
    return result


def read(path):
    if not path.exists():
        return {}, None
    checked(path)
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError('MCP configuration exceeds limit')
    value = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique)
    if not isinstance(value, dict) or not isinstance(value.get('mcpServers', {}), dict):
        raise ValueError('Invalid existing MCP configuration')
    return value, raw


def configure(server, *, config_path=None, project_root=None):
    from assistant_setup import equivalent
    target = Path(config_path) if config_path else Path.home() / '.cursor/mcp.json'
    project = Path(project_root or Path.cwd()) / '.cursor/mcp.json'
    if project.absolute() != target.absolute():
        settings, _ = read(project)
        if 'kpro-alerts' in settings.get('mcpServers', {}):
            actual = settings['mcpServers']['kpro-alerts']
            if not equivalent(actual, server) or actual.get('disabled') is True:
                raise ValueError('Project connector overrides the requested global configuration')
            return dict(registration='unchanged', scope='project', clientRuntimeVerified=False)
    # Existing user state stays intact on conflicts or concurrent cooperating setup.
    checked(target.parent if target.parent.exists() else target.parent.parent)
    target.parent.mkdir(exist_ok=True)
    checked(target.parent)
    lock = target.with_name(target.name + '.falconpro.lock')
    with lock.open('x', encoding='ascii') as stream:
        stream.write(str(os.getpid()))
    temporary = None
    try:
        settings, before = read(target)
        servers = settings.get('mcpServers', {})
        if 'kpro-alerts' in servers:
            actual = servers['kpro-alerts']
            if not equivalent(actual, server) or actual.get('disabled') is True:
                raise ValueError('Existing connector differs or is disabled; no settings changed')
            return dict(registration='unchanged', clientRuntimeVerified=False)
        settings['mcpServers'] = {**servers, 'kpro-alerts': server}
        if before is not None:
            backup = target.with_name(target.name + '.falconpro-' + secrets.token_hex(8) + '.bak')
            with backup.open('xb') as stream:
                stream.write(before)
        temporary = target.with_name(target.name + '.' + secrets.token_hex(8) + '.tmp')
        with temporary.open('x', encoding='utf-8') as stream:
            json.dump(settings, stream, ensure_ascii=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        _, current = read(target)
        if current != before:
            raise ValueError('MCP configuration changed concurrently; preserve user changes')
        os.replace(temporary, target)
        actual, _ = read(target)
        if not equivalent(actual['mcpServers']['kpro-alerts'], server):
            raise ValueError('Cursor configuration readback failed')
        return dict(registration='configured', clientRuntimeVerified=False,
                    protectionInstalled=False, preservedExistingServers=True)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
        lock.unlink()
