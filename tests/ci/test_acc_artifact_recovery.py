"""Evaluate actual workflow expressions with cached producer outputs across reruns."""
import hashlib
from pathlib import Path
import re
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[2]


def render(text, context):
    def resolve(path):
        value=context
        for key in path.strip().split('.'):
            value=value[key]
        return str(value)
    def expression(match):
        value=match.group(1).strip()
        formatted=re.fullmatch(r"format\('([^']*)',\s*(.*?)\)",value)
        if formatted:
            return formatted.group(1).format(*(resolve(arg) for arg in formatted.group(2).split(',')))
        return resolve(value)
    return re.sub(r'\$\{\{(.*?)\}\}',expression,text)


class AccArtifactRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs=yaml.safe_load((ROOT/'.github/workflows/acc-provision-tag-publish.yml').read_text())['jobs']

    def context(self,attempt,needs=None):
        return {'github':{'run_id':'7654321','run_attempt':str(attempt)},'needs':needs or {}}

    def outputs(self,job,context):
        return {key:render(value,context) for key,value in self.jobs[job]['outputs'].items()
                if key in ('package-artifact','evidence-run-attempt','receipt-artifact')}

    def step(self,job,name):
        return next(step for step in self.jobs[job]['steps'] if step['name']==name)

    def test_failed_upload_rerun_downloads_original_package_bytes_from_cached_build_outputs(self):
        build_context=self.context(1);build=self.outputs('build-and-publish',build_context)
        name=render(self.step('build-and-publish','Upload workflow artifacts')['with']['name'],build_context)
        self.assertEqual(name,build['package-artifact'])
        original=b'original retained package bytes from build attempt 1'
        artifact_store={name:{'package':original,'bundle_attempt':'1'}}
        upload_context=self.context(2,{'build-and-publish':{'outputs':build}})
        download=self.step('upload-package','Download prepared package and evidence')
        retained=artifact_store[render(download['with']['name'],upload_context)]
        self.assertEqual(retained['package'],original)
        self.assertEqual(hashlib.sha256(retained['package']).hexdigest(),hashlib.sha256(original).hexdigest())
        self.assertNotIn('setup.py',str(self.jobs['upload-package']))
        self.assertEqual(self.outputs('upload-package',upload_context)['receipt-artifact'],'acc-provision-upload-7654321-2')

    def test_status_only_rerun_uses_original_build_attempt_and_successful_upload_receipt(self):
        build=self.outputs('build-and-publish',self.context(1))
        upload=self.outputs('upload-package',self.context(2))
        artifacts={build['package-artifact']:{'manifest':{'run':{'attempt':'1'}}},
                   upload['receipt-artifact']:{'verified':True,'package_sha256':'a'*64}}
        status_context=self.context(3,{'build-and-publish':{'outputs':build},'upload-package':{'outputs':upload}})
        bundle_name=render(self.step('publish-status','Download prepared status bundle')['with']['name'],status_context)
        receipt_name=render(self.step('publish-status','Download verified upload receipt')['with']['name'],status_context)
        self.assertEqual(artifacts[bundle_name]['manifest']['run']['attempt'],'1')
        self.assertTrue(artifacts[receipt_name]['verified'])
        expected_attempt=render(self.jobs['publish-status']['env']['EVIDENCE_RUN_ATTEMPT'],status_context)
        self.assertEqual(expected_attempt,'1')
        publish=self.step('publish-status','Publish prepared package status')['run']
        self.assertIn('--expected-run-attempt "${EVIDENCE_RUN_ATTEMPT}"',publish)
        self.assertNotIn('--expected-run-attempt "${GITHUB_RUN_ATTEMPT}"',publish)
        self.assertNotIn('release_policy.py" upload',str(self.jobs['publish-status']))

    def test_new_producer_attempt_gets_distinct_immutable_artifact_names(self):
        for job,key in [('build-and-publish','package-artifact'),('upload-package','receipt-artifact')]:
            first=self.outputs(job,self.context(1))[key]
            second=self.outputs(job,self.context(2))[key]
            self.assertNotEqual(first,second)
        for job in ('build-and-publish','upload-package'):
            for step in self.jobs[job]['steps']:
                if step.get('uses','').startswith('actions/upload-artifact@'):
                    self.assertFalse(step.get('with',{}).get('overwrite',False))

if __name__=='__main__':unittest.main()
