import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from check_mcp_catalog import BASE, ROOT, catalog, inspect, load


class CatalogTests(unittest.TestCase):
    def plans(self):
        return {name: load((BASE / name).read_bytes()) for name in
                ('cases.json', 'addendum-cases.json', 'resolutions.json')}

    def test_pinned_catalog(self):
        r = inspect()
        self.assertEqual(len(r['cases']), 71)
        self.assertFalse(r['actual_core_execution'])
        self.assertEqual(r['lifecycle'], {'NOT_RUN': 37})

    def test_case_loss_duplicate_and_promotion(self):
        for name in self.plans():
            for change in (lambda p: p['cases'].pop(),
                           lambda p: p['cases'].__setitem__(0, copy.deepcopy(p['cases'][1])),
                           lambda p: p['cases'][0].update(status='PASS')):
                plans = self.plans()
                change(plans[name])
                with self.subTest(source=name), self.assertRaises(ValueError):
                    catalog(plans)

    def test_claim_promotion(self):
        for name, key, value in [('cases.json', 'conformance', 'PASS'),
                                 ('addendum-cases.json', 'external_review', 'PASS'),
                                 ('resolutions.json', 'adoption', 'ADOPTED')]:
            plans = self.plans()
            plans[name][key] = value
            with self.assertRaises(ValueError):
                catalog(plans)

    def test_changed_snapshot_or_manifest(self):
        for name in ('consolidated.md', 'manifest.json', 'resolutions.json'):
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / 'snapshot'
                shutil.copytree(BASE, dest)
                (dest / name).write_bytes((dest / name).read_bytes() + b'changed')
                with self.subTest(name=name), self.assertRaises(ValueError):
                    inspect(dest)

    def test_cli_output_and_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'result'
            cmd = [sys.executable, '-B', str(ROOT / 'scripts/check_mcp_catalog.py'), '--output', str(out)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            self.assertEqual(p.returncode, 0, p.stderr)
            raw = (out / 'report.json').read_bytes()
            r = json.loads(raw)
            self.assertEqual(r['proposal_cases'], {'NOT_RUN': 71})
            self.assertEqual(r['protocol_execution'], 'NOT_RUN')
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(raw, (out / 'report.json').read_bytes())

    def test_cli_rejects_repository_output(self):
        p = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/check_mcp_catalog.py'),
                            '--output', str(ROOT / 'docs/evidence/catalog-must-not-create')],
                           capture_output=True, text=True, timeout=15)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse((ROOT / 'docs/evidence/catalog-must-not-create').exists())


if __name__ == '__main__':
    unittest.main()
