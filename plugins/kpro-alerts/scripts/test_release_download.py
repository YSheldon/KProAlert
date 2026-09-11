import hashlib
import io
import tempfile
import unittest
import zipfile
import json
from unittest.mock import Mock, patch
from pathlib import Path
from release_download import validate_descriptor, unpack, version_tuple, allowed_url, acquire


BASE='https://github.com/YSheldon/KProAlert/releases/download/v1.2.0.300/'


def descriptor():
    return dict(schema='FalconProReleaseDescriptor/v1',version='1.2.0.300',platform='windows11-x64',
        releaseStatus='verified',packageManifestSha256='a'*64,sourceManifestSha256='b'*64,
        assets={k:dict(url=BASE+k+'.zip',sha256='c'*64,size=123) for k in ('package','onboarding')})


class DownloadTests(unittest.TestCase):
    def setUp(self):
        guard=patch('release_download.elevated',return_value=False)
        guard.start();self.addCleanup(guard.stop)

    def test_elevated_extraction_is_rejected(self):
        with patch('release_download.elevated',return_value=True):
            with self.assertRaises(ValueError):unpack('unused','unused',set())

    def test_descriptor_requires_verified_and_exact_fields(self):
        self.assertEqual(validate_descriptor(descriptor())['version'],'1.2.0.300')
        for field,value in [('releaseStatus','candidate'),('version','1.2.bad'),('command','run me')]:
            d=descriptor();d[field]=value
            with self.assertRaises(ValueError):validate_descriptor(d)

    def test_arm64_download_selects_its_signed_descriptor_and_exact_files(self):
        from release_download import API, LIFECYCLE_ONBOARDING
        def packed(files):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as z:
                for name, data in files.items(): z.writestr(name, data)
            return output.getvalue()
        package_names = {'KProSvcArm.exe','KProProtectArm.dll','KProFilterArm.sys',
                         'DrvCfg2.dat','default-policy.hex','release-manifest.json','release-attestation.ps1'}
        package = {name: b'fixture' for name in package_names}
        onboarding = {name: b'fixture' for name in LIFECYCLE_ONBOARDING}
        arm = descriptor()
        arm['platform'] = 'windows11-arm64'
        arm['packageManifestSha256'] = hashlib.sha256(package['release-manifest.json']).hexdigest()
        arm['sourceManifestSha256'] = hashlib.sha256(onboarding['onboarding-source.json']).hexdigest()
        payloads = {BASE+'package.zip': packed(package), BASE+'onboarding.zip': packed(onboarding)}
        for asset in arm['assets'].values():
            data = payloads[asset['url']]
            asset.update(size=len(data),sha256=hashlib.sha256(data).hexdigest())
        release = dict(draft=False, prerelease=False, tag_name='v1.2.0.300', assets=[
            dict(name='FalconPro-release.ps1', browser_download_url=BASE+'FalconPro-release.ps1'),
            dict(name='FalconPro-release-arm64.ps1', browser_download_url=BASE+'FalconPro-release-arm64.ps1')])
        payloads[API] = json.dumps(release).encode()
        payloads[BASE+'FalconPro-release-arm64.ps1'] = b'arm-signed'
        verify = Mock(return_value=arm)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'release'
            result = acquire(target, verify, fetch=lambda url, _:payloads[url], platform='windows11-arm64')
            self.assertEqual(result['platform'], 'windows11-arm64')
            verify.assert_called_once_with(b'arm-signed')
            self.assertTrue((target/'package/KProFilterArm.sys').is_file())
            self.assertFalse((target/'package/KProFilter.sys').exists())
        with tempfile.TemporaryDirectory() as folder:
            wrong = descriptor()
            with self.assertRaises(ValueError):
                acquire(Path(folder)/'release', lambda _: wrong,
                        fetch=lambda url, _:payloads[url], platform='windows11-arm64')
            self.assertFalse((Path(folder)/'release').exists())

    def test_urls_cannot_escape_release_origin(self):
        for url in ('http://github.com/YSheldon/KProAlert/releases/download/v1/a.zip',
                    'https://github.com/other/repo/releases/download/v1/a.zip',
                    BASE+'../bad.zip',BASE+'a.zip?token=x',
                    'https://github.com.evil.test/a.zip',BASE+'%2e%2e.zip'):
            with self.assertRaises(ValueError):allowed_url(url)

    def test_numeric_downgrade_order(self):
        self.assertGreater(version_tuple('1.2.0.300'),version_tuple('1.2.0.99'))
        with self.assertRaises(ValueError):version_tuple('1.2.0.999999')

    def test_signature_rejection_precedes_asset_fetch_and_staging(self):
        release=dict(draft=False,prerelease=False,assets=[dict(name='FalconPro-release.ps1',browser_download_url=BASE+'FalconPro-release.ps1')])
        fetch=Mock(side_effect=[json.dumps(release).encode(),b'not signed'])
        verify=Mock(side_effect=ValueError('signature rejected'))
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'release'
            with self.assertRaises(ValueError):acquire(target,verify,fetch=fetch)
            self.assertFalse(target.exists())
            self.assertEqual(fetch.call_count,2)

    def test_cloud_or_unbound_bootstrap_does_not_download(self):
        from bootstrap import prepare
        download=Mock()
        sid=Mock()
        result=prepare('unused','',endpoint_probe=lambda _:dict(state='target_unbound'),download=download,sid_reader=sid)
        self.assertFalse(result['installPerformed'])
        download.assert_not_called()
        sid.assert_not_called()

    def test_zip_allowlist_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            archive=Path(folder)/'a.zip'
            with zipfile.ZipFile(archive,'w') as z:z.writestr('file.txt','safe')
            target=Path(folder)/'out'
            unpack(archive,target,{'file.txt'})
            self.assertEqual((target/'file.txt').read_text(),'safe')
            with self.assertRaises((ValueError,FileExistsError)):unpack(archive,target,{'file.txt'})

    def test_zip_traversal_duplicates_and_symlink(self):
        for entries in ([('../evil','x')],[('FILE.txt','x'),('file.txt','y')],[('file.txt:stream','x')]):
            with tempfile.TemporaryDirectory() as folder:
                archive=Path(folder)/'a.zip'
                with zipfile.ZipFile(archive,'w') as z:
                    for name,data in entries:z.writestr(name,data)
                with self.assertRaises(ValueError):unpack(archive,Path(folder)/'out',{'file.txt'})
        with tempfile.TemporaryDirectory() as folder:
            archive=Path(folder)/'a.zip'
            with zipfile.ZipFile(archive,'w') as z:
                info=zipfile.ZipInfo('file.txt');info.create_system=3;info.external_attr=0o120777<<16
                z.writestr(info,'target')
            with self.assertRaises(ValueError):unpack(archive,Path(folder)/'out',{'file.txt'})


if __name__=='__main__':unittest.main()
