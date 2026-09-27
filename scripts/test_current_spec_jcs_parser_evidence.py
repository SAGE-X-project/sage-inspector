"""Preserved six-case JCS evidence must remain revision-bound and unpromoted."""

from pathlib import Path
import shutil
import tempfile
import unittest

import check_current_spec_jcs_parser_evidence as checker


class PreservedJCSParserEvidenceTests(unittest.TestCase):
    def test_preserved_observations(self):
        result = checker.check()
        self.assertEqual([result['go'][f'JCS-01-N{n:02d}'] for n in range(1, 7)],
                         list(checker.EXPECTED['go']['statuses']))
        self.assertEqual([result['rust'][f'JCS-01-N{n:02d}'] for n in range(1, 7)],
                         list(checker.EXPECTED['rust']['statuses']))

    def test_tampered_observation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / 'jcs-parser'
            shutil.copytree(checker.BASE, base)
            observation = base / 'go/JCS-01-N01-runtime.json'
            observation.write_bytes(observation.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'observation hash'):
                checker.check(base)


if __name__ == '__main__':
    unittest.main()
