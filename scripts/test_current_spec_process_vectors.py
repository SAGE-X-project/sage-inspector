"""Safe positive and negative controls for process-review decisions."""

import json
import unittest

from check_current_spec_process_vectors import check
from current_spec_catalog import catalog
from current_spec_process_bridge import observe
from current_spec_process_review import IDS, mapped_rules
from generate_current_spec_process_vectors import cases


class ProcessReviewTests(unittest.TestCase):
    def test_nine_cases_and_pinned_mapping(self):
        self.assertEqual(check(), 9)
        self.assertTrue(mapped_rules(catalog()[1]))

    def test_bridge_matches_independent_expectations(self):
        revision = catalog()[0]['spec_revision']
        for ident, inp, expected in cases():
            with self.subTest(ident=ident):
                request = {'schema_version': 1, 'spec_revision': revision,
                           'id': ident, 'track': 'document_review', 'input': inp}
                response = observe(json.dumps(request).encode())
                self.assertEqual(response['actual'], expected)
                self.assertEqual(expected['verdict'],
                                 'ACCEPT' if ident.endswith('-P') else 'REJECT')

    def test_wrong_revision_and_track_rejected(self):
        ident, inp, _ = next(cases())
        request = {'schema_version': 1, 'spec_revision': '0' * 40,
                   'id': ident, 'track': 'document_review', 'input': inp}
        with self.assertRaises(ValueError):
            observe(json.dumps(request).encode())
        request['spec_revision'] = catalog()[0]['spec_revision']
        request['track'] = 'runtime'
        with self.assertRaises(ValueError):
            observe(json.dumps(request).encode())


if __name__ == '__main__':
    unittest.main()
