"""Local contribution comparisons; no altered handshake is transmitted."""
import copy
import hashlib
import tempfile
from pathlib import Path
import unittest
from mcp_session_freshness import FIELDS, BINARY, PAIRS, check_sessions, check_matrix, check_seeds
from test_completion010 import encode


def samples():
    return [(str(n),{k:encode(hashlib.sha256((str(n)+k).encode()).digest()[:BINARY[k]])
                    if k in BINARY else str(n)+k for k in FIELDS}) for n in range(12)]


class FreshnessTests(unittest.TestCase):
    def test_distinct_contributions(self):
        result=check_sessions(samples())
        self.assertEqual(result['sessions'],12)
        self.assertEqual(result['distinct'],{k:12 for k in FIELDS})
        self.assertEqual(result['distinct_ephemeral_public_keys'],36)

    def test_each_reused_contribution_rejected(self):
        for name in FIELDS:
            records=samples();records[-1][1][name]=records[0][1][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError,'reused session contribution'):
                check_sessions(records)

    def test_public_key_reuse_across_roles_rejected(self):
        records=samples();records[-1][1]['ephS']=records[0][1]['enc']
        with self.assertRaisesRegex(ValueError,'across roles'):check_sessions(records)

    def test_binary_alias_does_not_hide_reuse(self):
        records=samples();records[-1][1]['nonce']=records[0][1]['nonce']+'=='
        with self.assertRaisesRegex(ValueError,'reused session contribution'):check_sessions(records)

    def test_missing_empty_and_duplicate_records_rejected(self):
        with self.assertRaisesRegex(ValueError,'empty'):check_sessions([])
        records=samples();records.append(copy.deepcopy(records[0]))
        with self.assertRaisesRegex(ValueError,'duplicate session evidence label'):check_sessions(records)
        for value in ('',False,encode(bytes(3))):
            records=samples();records[0][1]['nonce']=value
            with self.assertRaises(ValueError):check_sessions(records)

    def test_incomplete_matrices_rejected_before_reading(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError,'baseline inventory'):check_matrix(Path(root),{'pairs':[]})
            report={'pairs':[{'pair':p,'status':'PASS'} for p in PAIRS],'restart':[]}
            with self.assertRaisesRegex(ValueError,'recovery inventory'):check_matrix(Path(root),report)

    def test_session_seed_reuse_and_shape(self):
        self.assertEqual(check_seeds([bytes([n])*32 for n in range(12)]),12)
        with self.assertRaisesRegex(ValueError,'reused session seed'):
            check_seeds([bytes(32),bytes(32)])
        for value in (b'',bytes(31),'00'*32):
            with self.assertRaisesRegex(ValueError,'invalid session seed evidence'):
                check_seeds([value])


if __name__=='__main__':unittest.main()
