"""Controls for the MCP intent and result signature algorithm contract."""
import copy
import tempfile
from pathlib import Path
import unittest

import check_mcp_signature_boundary as checker


class SignatureBoundaryTests(unittest.TestCase):
    def test_contract_and_unchecked_audit(self):
        value = checker.contract()
        boundaries = {row['id']: row for row in value['boundaries']}
        self.assertEqual(set(boundaries), {'intent-algorithm', 'result-algorithm'})
        for boundary in boundaries.values():
            self.assertEqual(boundary['accepted'], 'ed25519')
            self.assertEqual(boundary['rejected'], ['ecdsa-p256-sha256', 'secp256k1'])
        report = checker.audit()
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['runtime'], 'NOT_RUN')
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
        self.assertEqual(set(report['boundaries']), set(boundaries))
        self.assertTrue(all(row['status'] == 'NOT_CHECKED' for row in report['source_identity'].values()))

    def test_contract_rejects_mutation(self):
        value = checker.load(checker.CONTRACT.read_bytes())
        changes = (
            lambda item: item.update(conformance='PASS'),
            lambda item: item['boundaries'].pop(),
            lambda item: item['boundaries'][0].update(accepted='secp256k1'),
            lambda item: item['boundaries'][1].update(rejected=['ecdsa-p256-sha256']),
            lambda item: item['cores']['go']['tests'].update({'result-algorithm': 'other'}),
            lambda item: item['cores']['rust']['files'].update({'extra': '0' * 64}),
        )
        for change in changes:
            candidate = copy.deepcopy(value)
            change(candidate)
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.validate(candidate)

    def test_cli_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'output'
            output.mkdir()
            with self.assertRaises(ValueError):
                checker.require(not output.exists(), 'new output outside Inspector required')


if __name__ == '__main__':
    unittest.main()
