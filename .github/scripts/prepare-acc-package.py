#!/usr/bin/env python3
"""Build ACC package bytes before any upload or status credential is available."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def prepare(repo, route, release_tag, upstream_id, artifact_dir):
    if route.get('legacy_adapter') or route.get('mode') not in ('preview', 'production'):
        raise ValueError('package build requires an explicit publication mode')
    version = route['version']
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:\.dev[0-9]+)?', version):
        raise ValueError('invalid package version')
    if route['index'] != ('testpypi' if route['mode'] == 'preview' else 'pypi'):
        raise ValueError('package route index does not match its mode')
    if not re.fullmatch(r'[0-9a-f]+', upstream_id):
        raise ValueError('invalid upstream ID')
    repo, artifact_dir = Path(repo).resolve(), Path(artifact_dir).resolve()
    setup = repo / 'provision/setup.py'
    source, count = re.subn(r"(?m)^(\s*version\s*=\s*)['\"][^'\"]+['\"]", rf"\g<1>'{version}'", setup.read_text())
    if count != 1:
        raise ValueError('expected one package version declaration')
    setup.write_text(source)
    if route['mode'] == 'preview':
        if not route.get('development'):
            raise ValueError('preview must use a development package version')
        versions = repo / 'provision/acc_provision/versions.yaml'
        image_tag = f'{release_tag}.{upstream_id}'
        source, count = re.subn(rf'(?m)^(\s*[^#:\n]+:\s*){re.escape(image_tag)}(?:\.[^\s#]+)?[ \t]*$', rf'\g<1>{image_tag}.z', versions.read_text())
        if not count:
            raise ValueError('preview package has no matching image pins')
        versions.write_text(source)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, 'setup.py', 'sdist', '--dist-dir', str(artifact_dir)], cwd=repo/'provision', check=True)
    artifact = artifact_dir / f'acc_provision-{version}.tar.gz'
    if not artifact.is_file():
        raise ValueError('expected package artifact was not built')
    return {'artifact': str(artifact), 'version': version, 'index': route['index']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',required=True)
    parser.add_argument('--route',required=True)
    parser.add_argument('--release-tag',required=True)
    parser.add_argument('--upstream-id',required=True)
    parser.add_argument('--artifact-dir',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    result=prepare(args.repo,json.loads(Path(args.route).read_text()),args.release_tag,args.upstream_id,args.artifact_dir)
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':main()
