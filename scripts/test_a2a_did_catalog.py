"""Keep adopted inventories separate and reject missing or forged cases."""
import copy
import tempfile
from pathlib import Path
import unittest
from a2a_did_catalog import ROOT, BASE, SPEC_REVISION, inventory, verify, main

class CatalogTests(unittest.TestCase):
    def test_complete_inventory_without_observations(self):
        report = inventory()
        self.assertEqual(len(report['cases']), 583)
        self.assertEqual(report['counts']['added'], {'A2AB': 64, 'DIDP': 28, 'TABLE': 2})
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
        self.assertTrue(all(x['status']=='NOT_RUN' for x in report['cases']))
        self.assertEqual(report['spec_revision'], SPEC_REVISION)
        self.assertEqual(len({x['id'] for x in report['cases']}), 583)

    def test_missing_or_modified_inventory_rejected(self):
        import shutil
        for mutate in ('missing', 'changed', 'promoted', 'source'):
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                for base in (BASE, 'verification/0.10.0/case-map.json', 'verification/0.10.0/design-baseline/traceability.json'):
                    source=ROOT/base;target=root/base;target.parent.mkdir(parents=True,exist_ok=True)
                    if source.is_dir(): shutil.copytree(source,target)
                    else: shutil.copy(source,target)
                import json
                p=root/BASE/'manifest.json'
                obj=json.loads(p.read_bytes())
                if mutate=='missing': (root/BASE/'traceability.json').unlink()
                elif mutate=='changed': obj['counts']['cases']=582
                elif mutate=='promoted': obj['status']='PASS'
                else: obj['spec_revision']='0'*40
                p.write_text(json.dumps(obj))
                with self.assertRaises((ValueError,OSError)): verify(root)

    def test_cli_output_and_failures(self):
        import sys, json
        from unittest.mock import patch
        with patch.object(sys,'argv',['catalog']):main()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'report.json'
            with patch.object(sys,'argv',['catalog','--output',str(p)]):main()
            self.assertEqual(json.loads(p.read_bytes())['counts']['cases'],583)
            with patch.object(sys,'argv',['catalog','--output',str(p/'bad')]),self.assertRaises(SystemExit) as e:main()
            self.assertEqual(e.exception.code,1)

if __name__=='__main__': unittest.main()
