"""Saved primitive-profile evidence must fail closed when it is altered."""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from current_spec_catalog import sha
import check_design_baseline_primitive_evidence as checker


def edit_observation(directory, ident, change):
    # Rewrites one observation and its manifest hash, as a forger would.
    manifest = json.loads((directory / 'manifest.json').read_text())
    row = next(item for item in manifest['observations'] if item['id'] == ident)
    observation = json.loads((directory / row['path']).read_text())
    change(observation)
    raw = (json.dumps(observation, indent=2) + '\n').encode()
    (directory / row['path']).write_bytes(raw)
    row['sha256'] = sha(raw)
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


class PrimitiveEvidenceCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'evidence'
        shutil.copytree(checker.BASE, self.base)

    def test_saved_evidence_passes(self):
        for lang in checker.SUBJECTS:
            self.assertEqual(checker.check(lang, self.base)['counts'], checker.COUNTS)

    def test_altered_outcome_is_detected_by_the_saved_assessment(self):
        def reject(observation):
            observation['actual'] = {'verdict': 'REJECT', 'output': {}, 'effects': {}}
            observation['facts']['actual_verdict'] = 'REJECT'
            observation['facts']['actual_output'] = {}
        edit_observation(self.base / 'go', 'JCS-01-P', reject)
        with self.assertRaisesRegex(ValueError, 'saved assessment drift'):
            checker.check('go', self.base)

    def test_unhashed_observation_edit_is_refused(self):
        directory = self.base / 'rust'
        manifest = json.loads((directory / 'manifest.json').read_text())
        path = directory / manifest['observations'][0]['path']
        path.write_text(path.read_text().replace('"local-process"', '"deployed"'))
        with self.assertRaisesRegex(ValueError, 'observation file hash'):
            checker.check('rust', self.base)

    def test_rerun_with_different_outcome_is_refused(self):
        fresh = Path(self.temp.name) / 'fresh'
        shutil.copytree(self.base / 'go', fresh)
        checker.compare('go', fresh, self.base)

        def unsupported(observation):
            observation['actual'] = {'verdict': 'UNSUPPORTED', 'reason': 'changed'}
            observation['facts'] = {}
        edit_observation(fresh, 'JCS-01-P', unsupported)
        with self.assertRaisesRegex(ValueError, 'rerun outcome drift'):
            checker.compare('go', fresh, self.base)

    def test_rerun_of_another_subject_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'rerun subject'):
            checker.compare('go', self.base / 'rust', self.base)


if __name__ == '__main__':
    unittest.main()
