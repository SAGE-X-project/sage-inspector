"""Measured inputs and distinct implementations are mandatory for claims."""

import json
import unittest

from check_current_spec_evidence_review import check
from current_spec_catalog import catalog
from current_spec_evidence_bridge import observe
from current_spec_evidence_review import IDS, TRACKS
from generate_current_spec_evidence_vectors import cases


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


if __name__ == '__main__':
    unittest.main()
