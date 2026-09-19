"""Negative controls for review evidence, not protocol execution tests."""
import copy
import unittest
from unittest import mock
import inspect_guard_integration as checker
from inspect_guard_integration import ROOT, CONTRACT, audit, load, validate


class IntegrationReview(unittest.TestCase):
    def setUp(self):
        self.c = load((ROOT / CONTRACT).read_bytes())

    def reject(self, change):
        candidate = copy.deepcopy(self.c)
        change(candidate)
        with self.assertRaises((ValueError, TypeError)):
            validate(candidate)

    def test_review_is_not_runtime(self):
        report = audit()
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertFalse(report['actual_core_execution'])
        self.assertEqual(report['source_identity']['go']['status'], 'NOT_CHECKED')
        self.assertEqual(report['lifecycle'], dict(status='NOT_RUN', scenarios=37))

    def test_cannot_promote_claims(self):
        for key, value in [('conformance', 'PASS'), ('lifecycle', dict(status='PASS', scenarios=37))]:
            with self.subTest(key=key):
                self.reject(lambda c: c.update({key: value}))
        self.reject(lambda c: c['reviewed_cores']['go'].update(evidence='PASS'))
        self.reject(lambda c: c['boundaries'][0].update(status='PASS'))

    def test_dependencies_and_ownership(self):
        self.reject(lambda c: c['boundaries'][1].update(requires=[]))
        self.reject(lambda c: c['boundaries'][0].update(owner='peer'))
        self.reject(lambda c: c['boundaries'].reverse())

    def test_missing_or_duplicate_boundary(self):
        self.reject(lambda c: c['boundaries'].pop())
        self.reject(lambda c: c['boundaries'].__setitem__(1, c['boundaries'][0]))

    def test_unbound_sources(self):
        self.reject(lambda c: c['sources'].update({next(iter(c['sources'])): '0'*64}))
        self.reject(lambda c: c['reviewed_cores']['rust'].update(revision='main'))
        self.reject(lambda c: c['reviewed_cores']['go']['files'].update({'../outside': '0'*64}))

    def test_empty_requirements_and_unknown_fields(self):
        self.reject(lambda c: c['boundaries'][0].update(required_evidence=[]))
        self.reject(lambda c: c['boundaries'][0].update(failure=''))
        self.reject(lambda c: c.update(actual_core_execution=True))

    def test_core_identity_mismatch(self):
        with mock.patch.object(checker.subprocess, 'check_output', return_value='0'*40):
            with self.assertRaisesRegex(ValueError, 'core revision mismatch'):
                audit(core_roots={'go': ROOT})
        original_read = checker.read
        def changed(root, path):
            if path in checker.FILES['go']:
                return b'changed reviewed source'
            return original_read(root, path)
        with mock.patch.object(checker.subprocess, 'check_output',
                               return_value=self.c['reviewed_cores']['go']['revision']), \
                mock.patch.object(checker, 'read', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'core source mismatch'):
                audit(core_roots={'go': ROOT})

    def test_duplicate_json(self):
        with self.assertRaises(ValueError):
            load(b'{"conformance":"NOT_ESTABLISHED","conformance":"PASS"}')


if __name__ == '__main__':
    unittest.main()
