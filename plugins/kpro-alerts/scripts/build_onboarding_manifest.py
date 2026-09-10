"""Publisher-only source digest manifest. Does not sign or approve a release."""
import hashlib
import json
from pathlib import Path
import argparse


NAMES=('Install-FalconPro.ps1','Install-KProAlert.ps1',
       'plugins/kpro-alerts/scripts/EndpointFacts.ps1','tools/KProReleaseTrust.psm1')


def build(root):
    root=Path(root)
    return {'schema':'FalconProOnboardingSource/v1','files':[
        {'name':name,'sha256':hashlib.sha256((root/name).read_bytes()).hexdigest()}
        for name in NAMES]}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    content=(json.dumps(build(args.root),indent=2)+'\n').encode('utf-8')
    with Path(args.output).open('xb') as stream:
        stream.write(content)
    print(json.dumps({'sha256':hashlib.sha256(content).hexdigest(),
                      'releaseApproved':False,'signed':False}))
