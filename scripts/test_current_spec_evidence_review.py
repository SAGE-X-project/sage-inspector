"""Measured inputs and distinct implementations are mandatory for claims."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest

from check_current_spec_evidence_review import check
from current_spec_catalog import catalog
from current_spec_evidence_bridge import observe
from current_spec_evidence_review import IDS, TRACKS, evaluate
from generate_current_spec_evidence_vectors import cases, scenarios


class EvidenceReviewTests(unittest.TestCase):
    def test_all_three_tracks_and_preserved_observations(self):
        self.assertEqual(check(), 9)

    def test_review_controls(self):
        revision = catalog()[0]['spec_revision']
        for ident, track, inp, expected in cases():
            with self.subTest(ident=ident, track=track):
                request = {'schema_version': 1, 'spec_revision': revision,
                           'id': ident, 'track': track, 'input': inp}
                actual = observe(json.dumps(request).encode())['actual']
                self.assertEqual(actual, expected)
                self.assertEqual(actual['verdict'],
                                 'ACCEPT' if ident == IDS[0] else 'REJECT')
                self.assertEqual(actual['effects'], {})

    def test_revision_and_execution_provenance_are_required(self):
        revision = catalog()[0]['spec_revision']
        changes = (
            ('spec_revision', '0' * 40, 'wrong_spec_revision'),
            ('execution_revision', 'f' * 40, 'unattributed_execution'),
            ('input_sha256', 'not-a-hash', 'missing_measurement'),
        )
        for kind, value, reason in changes:
            with self.subTest(kind=kind):
                report = deepcopy(scenarios()['EVIDENCE-01-P'])
                if kind == 'spec_revision':
                    report['spec_revision'] = value
                elif kind == 'execution_revision':
                    report['executions'][0]['revision'] = value
                else:
                    report['executions'][0]['input_sha256'] = value
                result = evaluate('EVIDENCE-01-P', 'runtime', report, revision)
                self.assertEqual(result['verdict'], 'REJECT')
                self.assertEqual(result['output']['reason'], reason)

    def test_evidence_review_cli_runs_every_track(self):
        script = Path(__file__).with_name('current_spec_evidence_bridge.py')
        revision = catalog()[0]['spec_revision']
        for ident, track, inp, expected in cases():
            with self.subTest(ident=ident, track=track):
                request = {'schema_version': 1, 'spec_revision': revision,
                           'id': ident, 'track': track, 'input': inp}
                result = subprocess.run(
                    [sys.executable, '-B', str(script)],
                    input=json.dumps(request).encode(), capture_output=True,
                    check=False, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(json.loads(result.stdout)['actual'], expected)


if __name__ == '__main__':
    unittest.main()
