"""Fixed release layouts; architecture is selected from bound endpoint facts."""
LAYOUTS = {
    'x64': dict(platform='windows11-x64', service='KProSvc.exe',
                dll='KProProtect.dll', driver='KProFilter.sys',
                descriptor='FalconPro-release.ps1', archive='FalconPro-Windows11-x64.zip'),
    'arm64': dict(platform='windows11-arm64', service='KProSvcArm.exe',
                  dll='KProProtectArm.dll', driver='KProFilterArm.sys',
                  descriptor='FalconPro-release-arm64.ps1', archive='FalconPro-Windows11-arm64.zip'),
}

CERTIFICATE_ONLY = {
    'x64': {'FalconPplBootstrap.exe', 'FalconElamControl.dll', 'FalconElam.sys'},
    'arm64': {'FalconPplBootstrapArm.exe', 'FalconElamControlArm.dll', 'FalconElamArm.sys'},
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


def certificate_only_files(architecture):
    layout(architecture)
    return set(CERTIFICATE_ONLY[architecture])


def required_files(architecture, service_protection=None):
    value = layout(architecture)
    files = {value['service'], value['dll'], value['driver'], 'DrvCfg2.dat', 'default-policy.hex'}
    if service_protection is None:
        return files
    if service_protection != 'certificate-only':
        raise ValueError('Unsupported service protection mode')
    return files | certificate_only_files(architecture)
