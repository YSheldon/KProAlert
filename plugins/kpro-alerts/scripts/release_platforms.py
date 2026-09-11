"""Fixed release layouts; architecture is selected from bound endpoint facts."""
LAYOUTS = {
    'x64': dict(platform='windows11-x64', service='KProSvc.exe',
                dll='KProProtect.dll', driver='KProFilter.sys',
                descriptor='FalconPro-release.ps1', archive='FalconPro-Windows11-x64.zip'),
    'arm64': dict(platform='windows11-arm64', service='KProSvcArm.exe',
                  dll='KProProtectArm.dll', driver='KProFilterArm.sys',
                  descriptor='FalconPro-release-arm64.ps1', archive='FalconPro-Windows11-arm64.zip'),
}


def layout(architecture):
    if not isinstance(architecture, str) or architecture not in LAYOUTS:
        raise ValueError('Unsupported release architecture')
    return dict(LAYOUTS[architecture])


def architecture_for(platform):
    for architecture, value in LAYOUTS.items():
        if value['platform'] == platform:
            return architecture
    raise ValueError('Unsupported release platform')


def required_files(architecture):
    value = layout(architecture)
    return {value['service'], value['dll'], value['driver'], 'DrvCfg2.dat', 'default-policy.hex'}
