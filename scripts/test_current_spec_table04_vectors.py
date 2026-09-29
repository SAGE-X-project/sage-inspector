"""Domain labels remain exact and tied to their construction roles."""

import copy
import unittest

import check_current_spec_table04_vectors as checker


class Table04VectorTests(unittest.TestCase):
    def test_pinned_domains_and_controls(self):
        self.assertEqual(checker.check(), (4, 18, 12))

    def test_hkdf_domains_cannot_be_interchanged(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        self.assertTrue(checker.matches(good))
        swapped = copy.deepcopy(good)
        swapped['domains']['hpke_combiner'] = good['domains']['hpke_ack']
        self.assertFalse(checker.matches(swapped))


if __name__ == '__main__':
    unittest.main()
