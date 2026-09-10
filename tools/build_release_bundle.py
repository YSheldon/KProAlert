"""Assemble exact signed release inputs. Does not sign, approve, or publish releases."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'plugins/kpro-alerts/scripts'))
from build_onboarding_manifest import build, NAMES
from lifecycle import read_json, verify_entry, validate_sources
from release_download import PACKAGE, LIFECYCLE_ONBOARDING, validate_descriptor
from release_manifest import validate


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive(root,names,path,extras=None):
    extras=extras or {}
    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_DEFLATED) as output:
        for name in sorted(names):
            data=extras[name] if name in extras else (root/name).read_bytes()
            output.writestr(name,data)


def assemble(package,sources,destination,tag):
    if not re.fullmatch('[A-Za-z0-9_-][A-Za-z0-9._-]*',tag):raise ValueError('Invalid release tag')
    package=Path(package);sources=Path(sources);destination=Path(destination)
    manifest=read_json(package/'release-manifest.json')
    validate(manifest,package,'x64')
    # Native publisher trust is evaluated on final signed inputs, before packaging.
    verify_entry(package/'release-attestation.ps1')
    for name in NAMES:
        if name.endswith('.ps1'):verify_entry(sources/name)
    source_manifest=(json.dumps(build(sources),sort_keys=True,indent=2)+'\n').encode()
    destination.mkdir(exist_ok=False)
    package_zip=destination/'FalconPro-Windows11-x64.zip'
    source_zip=destination/'FalconPro-Onboarding.zip'
    archive(package,PACKAGE,package_zip)
    archive(sources,LIFECYCLE_ONBOARDING,source_zip,{'onboarding-source.json':source_manifest})
    prefix='https://github.com/YSheldon/KProAlert/releases/download/'+tag+'/'
    assets={}
    for name,path in (('package',package_zip),('onboarding',source_zip)):
        assets[name]=dict(url=prefix+path.name,sha256=digest(path),size=path.stat().st_size)
    descriptor=validate_descriptor(dict(schema='FalconProReleaseDescriptor/v1',version=manifest['version'],
        platform='windows11-x64',releaseStatus='verified',packageManifestSha256=digest(package/'release-manifest.json'),
        sourceManifestSha256=hashlib.sha256(source_manifest).hexdigest(),assets=assets))
    payload=base64.b64encode(json.dumps(descriptor,separators=(',',':')).encode()).decode()
    entry=destination/'FalconPro-release.ps1'
    with entry.open('x',encoding='utf-8',newline='\n') as stream:
        stream.write('# FALCONPRO-RELEASE-JSON: '+payload+'\n')
    return dict(state='descriptor_requires_signing',descriptor=str(entry),published=False,
                packageSha256=assets['package']['sha256'],onboardingSha256=assets['onboarding']['sha256'])


def verify_bundle(destination):
    from bootstrap import verify_descriptor
    from release_download import unpack
    import tempfile
    root=Path(destination)
    descriptor=validate_descriptor(verify_descriptor((root/'FalconPro-release.ps1').read_bytes()))
    # Explicitly validate extracted bytes and the signed source manifest before publication.
    with tempfile.TemporaryDirectory(prefix='FalconPro-publish-check-') as folder:
        for kind,names,filename in (('package',PACKAGE,'FalconPro-Windows11-x64.zip'),
                                   ('onboarding',LIFECYCLE_ONBOARDING,'FalconPro-Onboarding.zip')):
            asset=descriptor['assets'][kind]
            path=root/filename
            if not asset['url'].endswith('/'+filename) or path.stat().st_size!=asset['size'] or digest(path)!=asset['sha256']:
                raise ValueError('Signed descriptor does not bind final archives')
            unpack(path,Path(folder)/kind,names)
        package=Path(folder)/'package'
        if digest(package/'release-manifest.json')!=descriptor['packageManifestSha256']:raise ValueError('Manifest differs')
        validate(read_json(package/'release-manifest.json'),package,'x64')
        validate_sources(Path(folder)/'onboarding',descriptor['sourceManifestSha256'])
    return dict(state='signed_bundle_verified',published=False,version=descriptor['version'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package')
    parser.add_argument('--signed-sources')
    parser.add_argument('--output',required=True)
    parser.add_argument('--tag')
    parser.add_argument('--verify',action='store_true')
    args=parser.parse_args()
    if args.verify:result=verify_bundle(args.output)
    else:
        if not all((args.package,args.signed_sources,args.tag)):parser.error('package, signed-sources and tag required')
        result=assemble(args.package,args.signed_sources,args.output,args.tag)
    print(json.dumps(result))
