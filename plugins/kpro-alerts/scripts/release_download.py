"""Bounded anonymous release acquisition. Signature verification is supplied separately."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
from urllib.parse import urlsplit
import urllib.request
import zipfile
import os
from spool import checked


API='https://api.github.com/repos/YSheldon/KProAlert/releases/latest'
PREFIX='/YSheldon/KProAlert/releases/download/'
PACKAGE={'KProSvc.exe','KProProtect.dll','KProFilter.sys','DrvCfg2.dat','default-policy.hex',
         'release-manifest.json','release-attestation.ps1'}
ONBOARDING={'Install-FalconPro.ps1','Install-KProAlert.ps1','onboarding-source.json',
            'plugins/kpro-alerts/scripts/EndpointFacts.ps1','tools/KProReleaseTrust.psm1'}
LIFECYCLE_ONBOARDING=ONBOARDING|{'Invoke-FalconProLifecycle.ps1','Uninstall-KProAlert.ps1',
            'plugins/kpro-alerts/scripts/Invoke-PolicySnapshot.ps1'}


def elevated():
    if os.name=='nt':
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return hasattr(os,'geteuid') and os.geteuid()==0


def version_tuple(value):
    if not isinstance(value,str) or not re.fullmatch(r'(0|[1-9][0-9]{0,4})(?:\.(0|[1-9][0-9]{0,4})){3}',value):
        raise ValueError('Canonical four-component version required')
    parts=tuple(map(int,value.split('.')))
    if max(parts)>65535:raise ValueError('Version component exceeds range')
    return parts


def allowed_url(url):
    if not isinstance(url,str):raise ValueError('Invalid release URL')
    p=urlsplit(url)
    if p.scheme!='https' or p.netloc!='github.com' or p.query or p.fragment:
        raise ValueError('Release URL origin rejected')
    if not re.fullmatch(re.escape(PREFIX)+r'[A-Za-z0-9_-][A-Za-z0-9._-]*/[A-Za-z0-9_-][A-Za-z0-9._-]*',p.path):
        raise ValueError('Release URL path rejected')
    return url


def validate_descriptor(value):
    keys={'schema','version','platform','releaseStatus','packageManifestSha256','sourceManifestSha256','assets'}
    if not isinstance(value,dict) or set(value)!=keys or value['schema']!='FalconProReleaseDescriptor/v1':
        raise ValueError('Unsupported release descriptor')
    version_tuple(value['version'])
    if value['platform']!='windows11-x64' or value['releaseStatus']!='verified':
        raise ValueError('No verified supported release')
    for key in ('packageManifestSha256','sourceManifestSha256'):
        if not isinstance(value[key],str) or not re.fullmatch('[a-f0-9]{64}',value[key]):
            raise ValueError('Invalid trusted digest')
    if not isinstance(value['assets'],dict) or set(value['assets'])!={'package','onboarding'}:
        raise ValueError('Unexpected asset set')
    for asset in value['assets'].values():
        if not isinstance(asset,dict) or set(asset)!={'url','sha256','size'}:
            raise ValueError('Unexpected asset fields')
        allowed_url(asset['url'])
        if type(asset['size']) is not int or not 0<asset['size']<=256*1024*1024:
            raise ValueError('Asset size rejected')
        if not isinstance(asset['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',asset['sha256']):
            raise ValueError('Asset digest rejected')
    return value


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        p=urlsplit(newurl)
        if p.scheme!='https' or p.netloc not in ('release-assets.githubusercontent.com','objects.githubusercontent.com','github.com') or p.username:
            raise ValueError('Download redirect origin rejected')
        if p.netloc=='github.com':allowed_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def read_url(url,maximum):
    if url!=API:allowed_url(url)
    opener=urllib.request.build_opener(Redirects())
    request=urllib.request.Request(url,headers={'User-Agent':'FalconPro-bootstrap','Accept':'application/octet-stream'})
    with opener.open(request,timeout=30) as response:
        data=response.read(maximum+1)
    if len(data)>maximum:raise ValueError('Download exceeds size budget')
    return data


def unpack(archive,target,allowed):
    if elevated():raise ValueError('Acquire/extract as a normal user, never with administrator/root privileges')
    target=Path(target)
    checked(target.parent)
    if target.exists() or target.is_symlink():raise FileExistsError('Extraction target already exists')
    with zipfile.ZipFile(archive) as z:
        entries=z.infolist()
        if len(entries)>100:raise ValueError('Too many archive members')
        names=set();total=0
        for entry in entries:
            name=entry.filename
            if '\\' in name or ':' in name or name.startswith('/') or '..' in PurePosixPath(name).parts:
                raise ValueError('Unsafe archive path')
            if stat.S_ISLNK(entry.external_attr>>16) or entry.flag_bits&1:
                raise ValueError('Encrypted/link archive member rejected')
            if entry.is_dir():
                if not any(p.startswith(name) for p in allowed):raise ValueError('Unexpected directory')
                continue
            if name not in allowed or name.casefold() in names:raise ValueError('Unexpected/duplicate member')
            names.add(name.casefold());total+=entry.file_size
            if not 0<entry.file_size<=64*1024*1024 or total>256*1024*1024:
                raise ValueError('Expanded archive exceeds budget')
        if names!={n.casefold() for n in allowed}:raise ValueError('Archive member set incomplete')
        target.mkdir(parents=False)
        for entry in entries:
            if entry.is_dir():continue
            path=target/entry.filename
            path.parent.mkdir(parents=True,exist_ok=True)
            checked(path.parent)
            with z.open(entry) as source,path.open('xb') as output:
                remaining=entry.file_size
                while remaining:
                    chunk=source.read(min(65536,remaining))
                    if not chunk:raise ValueError('Truncated archive entry')
                    output.write(chunk);remaining-=len(chunk)
                if source.read(1):raise ValueError('Archive entry size changed')


def acquire(destination,verify_descriptor,*,fetch=read_url):
    if elevated():raise ValueError('Download staging must run without elevation')
    destination=Path(destination)
    checked(destination.parent)
    if destination.exists():raise FileExistsError('Use a new staging directory')
    release=json.loads(fetch(API,1024*1024))
    if release.get('draft') is not False or release.get('prerelease') is not False:
        raise ValueError('Only a stable published release can be discovered')
    assets=release.get('assets')
    if not isinstance(assets,list) or len(assets)>100:raise ValueError('Release asset list invalid')
    descriptor=[a for a in assets if a.get('name')=='FalconPro-release.ps1']
    if len(descriptor)!=1:raise ValueError('Verified release descriptor is not published')
    data=fetch(allowed_url(descriptor[0]['browser_download_url']),65536)
    # Windows publisher verification must precede decoding/trusting any asset URL.
    verified=validate_descriptor(verify_descriptor(data))
    tag=release.get('tag_name')
    if not isinstance(tag,str) or not re.fullmatch('[A-Za-z0-9_-][A-Za-z0-9._-]*',tag):
        raise ValueError('Invalid discovered release tag')
    expected_prefix=PREFIX+tag+'/'
    if not urlsplit(descriptor[0]['browser_download_url']).path.startswith(expected_prefix) or any(
            not urlsplit(a['url']).path.startswith(expected_prefix) for a in verified['assets'].values()):
        raise ValueError('Descriptor/assets do not belong to the discovered release tag')
    destination.mkdir(parents=False)
    for kind,allowed in (('package',PACKAGE),('onboarding',ONBOARDING)):
        asset=verified['assets'][kind]
        payload=fetch(asset['url'],asset['size'])
        if len(payload)!=asset['size'] or hashlib.sha256(payload).hexdigest()!=asset['sha256']:
            raise ValueError('Downloaded asset hash/size mismatch')
        archive=destination/(kind+'.zip')
        with archive.open('xb') as f:f.write(payload)
        if kind=='onboarding':
            with zipfile.ZipFile(archive) as z:
                if 'Invoke-FalconProLifecycle.ps1' in z.namelist():
                    allowed=LIFECYCLE_ONBOARDING
        unpack(archive,destination/kind,allowed)
    for kind,name,key in (('package','release-manifest.json','packageManifestSha256'),
                          ('onboarding','onboarding-source.json','sourceManifestSha256')):
        if hashlib.sha256((destination/kind/name).read_bytes()).hexdigest()!=verified[key]:
            raise ValueError('Downloaded manifest differs from signed descriptor')
    with (destination/'FalconPro-release.ps1').open('xb') as f:f.write(data)
    return verified
