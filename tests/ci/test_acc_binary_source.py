"""Run the actual ACC workflow binary-build step with bounded fake Git/Go tools."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/'.github/workflows/acc-provision-tag-publish.yml'
LOCKED='a'*40
MOVED='b'*40
TAG='6.1.1.8'

class AccBinarySource(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='acc-binary-source-');self.addCleanup(self.temp.cleanup)
        self.dir=Path(self.temp.name);self.repo=self.dir/'repo';(self.repo/'provision/bin').mkdir(parents=True)
        (self.repo/'ci').mkdir();self.bin=self.dir/'bin';self.bin.mkdir()
        self.helpers=self.dir/'cicd/travis';self.helpers.mkdir(parents=True)
        self.preview=self.dir/'preview';self.preview.mkdir()
        self.runtime=self.dir/'runtime';self.runtime.mkdir()
        self.artifacts=self.repo/'ci-artifacts'
        self.env={**os.environ,'PATH':str(self.bin)+os.pathsep+os.environ['PATH'],'RUNNER_TEMP':str(self.runtime),
            'CICD_DIR':str(self.helpers.parent),'CI_ARTIFACT_DIR':str(self.artifacts),'PYPI_TARGET':'pypi','SAFE_TAG':TAG,
            'GITHUB_ENV':str(self.dir/'github-env'),'FIXTURE_DIR':str(self.dir),'FIXTURE_PREVIEW_DIR':str(self.preview),'FIXTURE_EXPECTED_SHA':LOCKED}
        self.lock(LOCKED)
        self.executable('python', "import sys\nif sys.argv[1:3] != ['-m','pip']: raise SystemExit(90)\n")
        self.executable('jq', "import json,sys\nif sys.argv[-2] != '.sources[\"noironetworks/aci-containers\"]': raise SystemExit(90)\nprint(json.load(open(sys.argv[-1]))['sources']['noironetworks/aci-containers'])\n")
        self.executable('git', '''import json,os,pathlib,sys
root=pathlib.Path(os.environ['FIXTURE_DIR']);args=sys.argv[1:]
with (root/'git-calls.jsonl').open('a') as stream: stream.write(json.dumps(args)+'\\n')
if args[:1] == ['-C']: args=args[2:]
if args[0] == 'init': pathlib.Path(args[-1]).mkdir(parents=True,exist_ok=True)
elif args[0] == 'fetch':
 value='b'*40 if 'refs/tags/' in args[-1] else args[-1]
 (root/'fetched').write_text(value)
elif args[0] == 'checkout':
 value=(root/'fetched').read_text() if args[-1] == 'FETCH_HEAD' else 'b'*40
 (root/'head').write_text(value)
elif args[:2] == ['rev-parse','HEAD']:
 print('b'*40 if os.environ.get('FIXTURE_WRONG_HEAD') else (root/'head').read_text())
elif args[0] != 'remote': raise SystemExit(90)
''')
        self.executable('make', '''import json,os,pathlib
root=pathlib.Path(os.environ['FIXTURE_DIR']);provenance=json.loads(pathlib.Path(os.environ['CI_ARTIFACT_DIR'],'acikubectl-source.json').read_text())
if provenance['source_sha'] != os.environ['FIXTURE_EXPECTED_SHA']: raise SystemExit(91)
(root/'make-called').write_text('verified-source-before-Go')
pathlib.Path('dist-static').mkdir(exist_ok=True);pathlib.Path('dist-static/acikubectl').write_text('fixture-binary')
''')
        for helper in ('show-git-repo-status.sh','build-acc-provision.sh'):
            path=self.helpers/helper;path.write_text('#!/bin/bash\nexit 0\n');path.chmod(0o755)
        path=self.helpers/'clone-aci-containers-repo.sh'
        path.write_text('#!/bin/bash\nset -eu\ntouch "${FIXTURE_DIR}/legacy-cloner-called"\nmkdir -p "${FIXTURE_PREVIEW_DIR}"\n')
        path.chmod(0o755)

    def executable(self,name,body):
        path=self.bin/name;path.write_text('#!'+sys.executable+'\n'+body);path.chmod(0o755)

    def lock(self,sha):
        (self.repo/'ci/release-inputs.json').write_text(json.dumps({'sources':{'noironetworks/aci-containers':sha}}))

    def script(self):
        workflow=yaml.safe_load(WORKFLOW.read_text())
        script=next(step['run'] for step in workflow['jobs']['build-and-publish']['steps'] if step['name']=='Build acc-provision package inputs')
        # Redirect only the legacy fixed checkout location into this fixture.
        # Production source selection and every Git/Go command remain unchanged.
        return script.replace('/tmp/noironetworks/aci-containers',str(self.preview))

    def execute(self,success=True):
        result=subprocess.run(['bash','-c',self.script()],cwd=self.repo,env=self.env,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode==0,success,result.stdout+result.stderr)
        return result

    def calls(self):
        return [json.loads(line) for line in (self.dir/'git-calls.jsonl').read_text().splitlines()]

    def test_production_uses_locked_source_even_when_release_tag_has_moved(self):
        self.execute()
        calls=self.calls()
        self.assertTrue(any(call[-1:]==[LOCKED] and 'fetch' in call for call in calls))
        self.assertTrue(any(call[-1:]==['FETCH_HEAD'] and '--detach' in call for call in calls))
        self.assertFalse(any('refs/tags/' in arg for call in calls for arg in call))
        self.assertFalse((self.dir/'legacy-cloner-called').exists())
        self.assertTrue((self.dir/'make-called').exists())
        provenance=json.loads((self.artifacts/'acikubectl-source.json').read_text())
        self.assertEqual(provenance['source_sha'],LOCKED)
        self.assertEqual(provenance['selection'],'locked-production-sha')
        self.assertIn('ACTUAL_ACI_SOURCE_SHA='+LOCKED,(self.dir/'github-env').read_text())
        self.assertEqual((self.repo/'provision/bin/acikubectl').read_text(),'fixture-binary')

    def test_wrong_checked_out_production_source_fails_before_Go(self):
        self.env['FIXTURE_WRONG_HEAD']='1'
        self.execute(success=False)
        self.assertFalse((self.dir/'make-called').exists())
        self.assertFalse((self.artifacts/'acikubectl-source.json').exists())

    def test_non_sha_lock_or_unknown_target_fails_before_git_or_Go(self):
        self.lock('master')
        self.execute(success=False)
        self.assertFalse((self.dir/'git-calls.jsonl').exists())
        self.assertFalse((self.dir/'make-called').exists())
        self.lock(LOCKED); self.env['PYPI_TARGET']='unknown'
        self.execute(success=False)
        self.assertFalse((self.dir/'git-calls.jsonl').exists())
        self.assertFalse((self.dir/'legacy-cloner-called').exists())

    def test_preview_retains_legacy_tag_route_and_records_actual_source(self):
        self.env.update(PYPI_TARGET='testpypi',FIXTURE_EXPECTED_SHA=MOVED)
        self.execute()
        self.assertTrue((self.dir/'legacy-cloner-called').exists())
        self.assertTrue(any(call[-1:]==[TAG] and 'checkout' in call for call in self.calls()))
        provenance=json.loads((self.artifacts/'acikubectl-source.json').read_text())
        self.assertEqual(provenance['source_sha'],MOVED)
        self.assertEqual(provenance['selection'],'legacy-preview-tag')
        self.assertIn('ACTUAL_ACI_SOURCE_SHA='+MOVED,(self.dir/'github-env').read_text())
        self.assertTrue((self.dir/'make-called').exists())

if __name__=='__main__':unittest.main()
