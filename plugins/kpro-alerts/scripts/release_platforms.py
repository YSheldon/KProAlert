"""Fixed release layouts selected from authenticated OS and architecture facts."""
import re


def _entry(platform, architecture, legacy, descriptor, archive):
    suffix = '32' if architecture == 'x86' else ''
    if architecture == 'arm64':
        service, dll, driver = 'KProSvcArm.exe', 'KProProtectArm.dll', 'KProFilterArm.sys'
    else:
        service, dll, driver = f'KProSvc{suffix}.exe', f'KProProtect{suffix}.dll', f'KProFilter{suffix}.sys'
    return dict(platform=platform, architecture=architecture, legacy=legacy,
                service=service, dll=dll, driver=driver,
                descriptor=descriptor, archive=archive)


PLATFORM_LAYOUTS = {
    # The legacy label covers Windows 7 SP1 and Windows 8. It deliberately uses
    # no-Force-Integrity user-mode images while retaining the same driver ABI.
    'windows7-x64': _entry('windows7-x64', 'x64', True,
                            'FalconPro-release-windows7-x64.ps1', 'FalconPro-Windows7-x64.zip'),
    'windows7-x86': _entry('windows7-x86', 'x86', True,
                           'FalconPro-release-windows7-x86.ps1', 'FalconPro-Windows7-x86.zip'),
    'windows81-x64': _entry('windows81-x64', 'x64', False,
                            'FalconPro-release-windows81-x64.ps1', 'FalconPro-Windows81-x64.zip'),
    'windows81-x86': _entry('windows81-x86', 'x86', False,
                            'FalconPro-release-windows81-x86.ps1', 'FalconPro-Windows81-x86.zip'),
    'windows10-x64': _entry('windows10-x64', 'x64', False,
                            'FalconPro-release-windows10-x64.ps1', 'FalconPro-Windows10-x64.zip'),
    'windows10-x86': _entry('windows10-x86', 'x86', False,
                            'FalconPro-release-windows10-x86.ps1', 'FalconPro-Windows10-x86.zip'),
    'windows11-x64': _entry('windows11-x64', 'x64', False,
                            'FalconPro-release.ps1', 'FalconPro-Windows11-x64.zip'),
    'windows11-arm64': _entry('windows11-arm64', 'arm64', False,
                              'FalconPro-release-arm64.ps1', 'FalconPro-Windows11-arm64.zip'),
}


# `LAYOUTS` remains an architecture-only compatibility view for callers that
# operate on the current Windows 11 package without endpoint OS facts.
LAYOUTS = {
    'x86': PLATFORM_LAYOUTS['windows10-x86'],
    'x64': PLATFORM_LAYOUTS['windows11-x64'],
    'arm64': PLATFORM_LAYOUTS['windows11-arm64'],
}


def layout(architecture, platform=None):
    if not isinstance(architecture, str) or architecture not in LAYOUTS:
        raise ValueError('Unsupported release architecture')
    if platform is None:
        return dict(LAYOUTS[architecture])
    value = layout_for_platform(platform)
    if value['architecture'] != architecture:
        raise ValueError('Release architecture/platform mismatch')
    return value


def layout_for_platform(platform):
    if not isinstance(platform, str) or platform not in PLATFORM_LAYOUTS:
        raise ValueError('Unsupported release platform')
    return dict(PLATFORM_LAYOUTS[platform])


def architecture_for(platform):
    return layout_for_platform(platform)['architecture']


def os_family_for(platform):
    value = layout_for_platform(platform)
    return 'windows7' if value['legacy'] else platform.split('-', 1)[0]


def platform_for_os(version, build, architecture, product_type=1):
    """Return the exact package platform for sanitized Win32_OperatingSystem facts."""
    if type(product_type) is not int or product_type != 1 or architecture not in ('x86', 'x64', 'arm64'):
        raise ValueError('Unsupported Windows product or architecture')
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+(?:\.[0-9]+){0,2}', version) or type(build) is not int:
        raise ValueError('Invalid Windows version facts')
    parts = tuple(map(int, version.split('.')))
    major, minor = parts[:2]
    if len(parts) >= 3 and parts[2] != build:
        raise ValueError('Inconsistent Windows build facts')
    if major == 6 and minor == 1:
        if build != 7601:
            raise ValueError('Windows 7 SP1 is required')
        if architecture == 'arm64':
            raise ValueError('ARM64 is not supported on Windows 7')
        return f'windows7-{architecture}'
    if major == 6 and minor == 2 and build == 9200:
        if architecture == 'arm64':
            raise ValueError('ARM64 is not supported on Windows 8')
        return f'windows7-{architecture}'
    if major == 6 and minor == 3 and build == 9600:
        if architecture == 'arm64':
            raise ValueError('ARM64 Windows 8.1 is not admitted')
        return f'windows81-{architecture}'
    if major == 10 and minor == 0 and 10240 <= build <= 65535:
        if architecture == 'arm64':
            if build < 22000:
                raise ValueError('ARM64 Windows 11 is required')
            return 'windows11-arm64'
        if build >= 22000:
            if architecture == 'x86':
                raise ValueError('Windows 11 x86 is not supported')
            return 'windows11-x64'
        return f'windows10-{architecture}'
    raise ValueError('Unsupported Windows version')


def required_files(architecture, platform=None):
    value = layout(architecture, platform)
    return {value['service'], value['dll'], value['driver'], 'DrvCfg2.dat', 'default-policy.hex'}
