"""Register one ZCode MCP, preserving native settings and effective workspace entries."""
import json
import os
from pathlib import Path
import secrets
from assistant_setup import equivalent
from cursor_setup import unique
from spool import checked


def _read(path):
    if not path.exists():
        return {}, None
    checked(path)
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError('ZCode configuration exceeds limit')
    value = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('Invalid ZCode configuration')
    return value, raw


def _servers(value, native):
    if native:
        mcp = value.get('mcp', {})
        if not isinstance(mcp, dict):
            raise ValueError('Invalid ZCode mcp settings')
        result = mcp.get('servers', {})
    else:
        result = value.get('mcpServers', {})
    if not isinstance(result, dict):
        raise ValueError('Invalid ZCode server collection')
    return result


def _same(actual, server):
    return (equivalent(actual, server) and actual.get('enable') is not False
            and actual.get('disabled') is not True)


def configure(server, *, user_root=None, project_root=None, upgrade=False):
    user = Path(user_root) if user_root else Path.home()
    project = Path(project_root or Path.cwd())
    native, _ = _read(project / '.zcode/config.json')
    compatibility, _ = _read(project / '.agents/mcp.json')
    workspace = _servers(native, True) or _servers(compatibility, False)
    if 'kpro-alerts' in workspace:
        if not _same(workspace['kpro-alerts'], server):
            raise ValueError('Workspace FalconPro connector differs or is disabled')
        return dict(registration='unchanged', scope='workspace', clientRuntimeVerified=False)
    target = user / '.zcode/cli/config.json'
    for folder in [user, user / '.zcode', target.parent]:
        if folder.exists():
            checked(folder)
        else:
            folder.mkdir()
            checked(folder)
    lock = target.with_name('config.json.falconpro.lock')
    temporary = None
    with lock.open('x', encoding='ascii') as handle:
        handle.write(str(os.getpid()))
    try:
        value, before = _read(target)
        servers = _servers(value, True)
        fallback, _ = _read(user / '.agents/mcp.json')
        fallback_servers = _servers(fallback, False)
        effective = servers or fallback_servers
        if 'kpro-alerts' in effective:
            actual = effective['kpro-alerts']
            if _same(actual, server):
                return dict(registration='unchanged', scope='user', clientRuntimeVerified=False)
            if not upgrade or actual.get('enable') is False or actual.get('disabled') is True:
                raise ValueError('Existing FalconPro connector differs or is disabled')
            old_env = actual.get('env', {})
            if not isinstance(old_env, dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in old_env.items()):
                raise ValueError('Existing FalconPro connector environment is invalid')
            server = {**server, 'env':dict(old_env)}
            registration = 'migrated'
        else:
            registration = 'configured'
        if not servers and fallback_servers:
            raise ValueError('Import existing .agents servers in ZCode before creating native settings')
        value['mcp'] = {**value.get('mcp', {}), 'servers': {**servers, 'kpro-alerts': server}}
        if before is not None:
            backup = target.with_name('config.json.falconpro-' + secrets.token_hex(8) + '.bak')
            with backup.open('xb') as handle:
                handle.write(before)
        temporary = target.with_name('config.json.' + secrets.token_hex(8) + '.tmp')
        with temporary.open('x', encoding='utf-8') as handle:
            json.dump(value, handle, ensure_ascii=True, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        if _read(target)[1] != before:
            raise ValueError('ZCode configuration changed concurrently')
        os.replace(temporary, target)
        if not _same(_servers(_read(target)[0], True)['kpro-alerts'], server):
            raise ValueError('ZCode configuration readback failed')
        return dict(registration=registration, scope='user', clientRuntimeVerified=False,
                    protectionInstalled=False, preservedExistingServers=True,
                    preservedExistingEnvironment=registration == 'migrated')
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
        lock.unlink()
