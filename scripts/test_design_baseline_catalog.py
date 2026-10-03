"""Verify frozen source ownership and exact catalog regeneration."""

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from design_baseline_catalog import ROOT, rule_clauses, verify


SPEC = Path(os.environ.get('SAGE_SPEC_ROOT', '../sage-spec')).resolve()


class DesignBaselineCatalogTests(unittest.TestCase):
    def test_catalog_has_complete_case_and_clause_contracts(self):
        _, trace, contracts = verify()
        rows = contracts['contracts']
        self.assertEqual(len(trace['cases']), 489)
        self.assertEqual(len(trace['mandatory_subscenarios']), 26)
        self.assertEqual(sum(row['contract_kind'] == 'full-case-boundary'
                             for row in rows), 562)
        self.assertEqual(sum(row['contract_kind'] == 'operator-subcondition'
                             for row in rows), 19)
        self.assertEqual(sum(row['contract_kind'] == 'web-media-subcondition'
                             for row in rows), 13)

    def test_unowned_normative_statement_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = json.loads((ROOT / 'verification/0.10.0/design-baseline/'
                                'traceability.json').read_bytes())
            sources = {rule['source'] for rule in trace['rules']}
            sources.add('charter.md')
            sources.update(str(path.relative_to(SPEC))
                           for directory in ('spec', 'profiles')
                           for path in (SPEC / directory).glob('*.md'))
            for source in sources:
                target = root / source
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SPEC / source, target)
            path = root / 'spec/09-registry.md'
            path.write_text(path.read_text() + '\nA new receiver MUST accept this.\n')
            with self.assertRaisesRegex(ValueError, 'unowned normative line'):
                rule_clauses(root, trace)


if __name__ == '__main__':
    unittest.main()
