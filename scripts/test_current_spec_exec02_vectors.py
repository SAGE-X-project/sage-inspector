"""Capture framing and policy artifact changes have distinct commitments."""

import unittest

import check_current_spec_exec02_vectors as checker


class Exec02VectorTests(unittest.TestCase):
    def test_pinned_commitment_probes(self):
        self.assertEqual(checker.check(), 4)

    def test_single_item_and_bundle_cannot_alias(self):
        one = checker.independent_capture([{'hex': '6162'}])
        bundle = checker.independent_capture([{'hex': '61'}, {'hex': '62'}])
        self.assertNotEqual(one, bundle)

    def test_policy_epoch_changes_commitment(self):
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        descriptor = suite['cases'][2]['input']['descriptor']
        changed = dict(descriptor, epoch='8f0264a0-8743-424a-b3d7-47090d31fca2')
        self.assertNotEqual(checker.independent_policy(descriptor),
                            checker.independent_policy(changed))


if __name__ == '__main__':
    unittest.main()
