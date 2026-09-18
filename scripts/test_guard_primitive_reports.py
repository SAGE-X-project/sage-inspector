"""Check that primitive progress cannot promote unsupported or lifecycle evidence."""
import copy
import json
import unittest
from inspect_guard import ROOT
from test_guard_primitive_adapters import validate


class GuardReports(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT/'vectors/0.10.0/guard-records.json').read_bytes()
        # Synthetic report controls only; never emitted as core observations.
        self.primitive = json.loads((ROOT/'docs/evidence/guard/go/guard-records.json').read_text())
        for item in self.primitive['results']:
            if item['operation'] != 'sage.guard.mcp.result':
                item['status'] = 'PASS'
                item['actual'] = dict(schema_version=1, case_id=item['case_id'], **item['expected'])
        self.primitive['counts'] = dict(PASS=86, FAIL=0, UNSUPPORTED=16, NOT_RUN=0)
        self.primitive['status'] = 'INCOMPLETE'
        self.summary = json.loads((ROOT/'docs/evidence/guard/go/summary.json').read_text())
        self.summary['primitive_counts'] = self.primitive['counts'].copy()

    def test_valid_partial_scope(self):
        validate(self.summary, self.primitive, self.raw)

    def test_reject_promotions_and_missing_members(self):
        for mutation in ('mapping', 'scenario', 'full', 'missing', 'wrong-answer'):
            s, p = copy.deepcopy(self.summary), copy.deepcopy(self.primitive)
            if mutation == 'mapping':
                next(x for x in p['results'] if x['operation'] == 'sage.guard.mcp.result')['status'] = 'PASS'
            if mutation == 'scenario':
                s['scenarios'][0]['status'] = 'PASS'
            if mutation == 'full':
                s['status'] = 'PASS'
            if mutation == 'missing':
                s['scenarios'].pop()
            if mutation == 'wrong-answer':
                p['results'][0]['actual']['output'] = {}
            with self.assertRaises(ValueError, msg=mutation):
                validate(s, p, self.raw)


if __name__ == '__main__':
    unittest.main()
