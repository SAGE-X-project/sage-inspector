"""Web profile trust controls are explicit and undefined media stays unbound."""

import copy
import unittest

import check_current_spec_reg08_vectors as checker


class Reg08VectorTests(unittest.TestCase):
    def test_pinned_web_cases_and_gap(self):
        self.assertEqual(checker.check(), (4, 6, 'REG-08-N04'))

    def test_no_cache_or_origin_fallback(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        for path, value in ((('request', 'follow_redirects'), True),
                            (('response', 'cache_control'), 'max-age=60'),
                            (('response', 'status'), 304),
                            (('policy', 'approved_origins'), [])):
            changed = copy.deepcopy(good)
            changed[path[0]][path[1]] = value
            self.assertEqual(checker.decision(changed), 'REJECT', path)


if __name__ == '__main__':
    unittest.main()
