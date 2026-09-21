import copy
import json
from pathlib import Path
import tempfile
import unittest
from check_guard_signature_boundaries import CANONICAL_SHA, fixtures, sha
from test_record010_adapters import PINS
from verify_guard_signature_evidence import verify


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.revision = 'a'*40
        self.hashes = {name:sha(name.encode()) for name in ('go', 'rust', 'audit')}
        self.checked = {'cases':10, 'valid':8, 'invalid':2, 'secp':{'secp_cases':4, 'low_s':True, 'recovery':True}}
        self.report = dict(kind='guard-signature-boundaries', status='PASS', actual_core_execution=True,
            conformance='NOT_ESTABLISHED', mcp_protocol_execution='NOT_RUN', proposal_cases={'NOT_RUN':71},
            lifecycle={'NOT_RUN':37}, fixture_sha256=CANONICAL_SHA, suite='canonical-signatures',
            inspector_revision=self.revision, signature_audit=self.checked, audit_executable_sha256=self.hashes['audit'],
            subjects={name:dict(revision=pin,adapter_sha256=self.hashes[name]) for name,pin in PINS.items()},
            limitations=['Test-only evidence']*4, results=[])
        for name in PINS:
            for c in fixtures(True):
                stem = name+'-'+c['id']
                q = dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',case_id=c['id'],operation=c['operation'],input=c['input'])
                self.write(stem+'.request.json', q)
                response = dict(schema_version=1,case_id=c['id'],verdict=c['expected'],output={'valid':True} if c['expected']=='ACCEPT' else {})
                self.write(stem+'.stdout', response)
                (self.root/(stem+'.stderr')).write_bytes(b'')
                self.report['results'].append(dict(subject=name,id=c['id'],status='PASS',verdict=c['expected'],response_sha256=sha((self.root/(stem+'.stdout')).read_bytes())))
        self.write('report.json', self.report)

    def write(self, name, value):
        (self.root/name).write_text(json.dumps(value)+'\n')

    def check(self):
        return verify(self.root,self.revision,self.hashes,self.checked)

    def test_complete_synthetic_evidence(self):
        self.assertEqual(self.check(),28)

    def test_report_mutations(self):
        mutations = [lambda r:r.update(status='FAIL'),lambda r:r.update(actual_core_execution=1),
            lambda r:r.update(conformance='PASS'),lambda r:r.update(mcp_protocol_execution='PASS'),
            lambda r:r.update(proposal_cases={'PASS':71}),lambda r:r.update(lifecycle={'PASS':37}),
            lambda r:r.update(inspector_revision='b'*40),lambda r:r.update(fixture_sha256='0'*64),
            lambda r:r.update(audit_executable_sha256='0'*64),lambda r:r['subjects']['go'].update(revision='b'*40),
            lambda r:r['subjects']['rust'].update(adapter_sha256='0'*64),lambda r:r['results'].pop(),
            lambda r:r['results'].append(r['results'][0]),lambda r:r['results'].reverse(),
            lambda r:r['results'][0].update(response_sha256='0'*64),lambda r:r.update(limitations=[])]
        for i, mutate in enumerate(mutations):
            with self.subTest(i=i):
                report = copy.deepcopy(self.report); mutate(report); self.write('report.json',report)
                with self.assertRaises(ValueError):self.check()

    def test_raw_mutations(self):
        for name, replacement in [('go-intent-ed-valid.request.json',b'{"schema_version":1,"schema_version":1}'),
            ('go-intent-ed-valid.stdout',b'{}'),('go-intent-ed-valid.stderr',b'error')]:
            with self.subTest(name=name):
                path=self.root/name; original=path.read_bytes(); path.write_bytes(replacement)
                with self.assertRaises(ValueError):self.check()
                path.write_bytes(original)

    def test_missing_extra_and_symlink_files(self):
        path=self.root/'go-intent-ed-valid.stderr'; path.unlink()
        with self.assertRaises(ValueError):self.check()
        path.write_bytes(b''); extra=self.root/'extra'; extra.write_bytes(b'')
        with self.assertRaises(ValueError):self.check()
        extra.unlink(); path.unlink(); path.symlink_to(self.root/'rust-intent-ed-valid.stderr')
        with self.assertRaises(ValueError):self.check()


if __name__ == '__main__':unittest.main()
