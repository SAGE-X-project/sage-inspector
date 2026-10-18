"""Inspector self-tests use reported outputs, never claim actual core execution."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import did_paired_observation as paired


def reported():
    rows = []
    for case in paired.fixtures():
        actual = copy.deepcopy(case['expected'])
        for row in actual['results']:
            for projection in ('core10', 'did11'):
                view = row[projection]
                if view is not None:
                    view['body_hex'] = paired.canonical(view.pop('body')).hex()
                    view['metadata_hex'] = paired.canonical(view.pop('metadata')).hex()
        rows.append({'id': case['id'], 'input_sha256': case['input_sha256'], 'actual': actual})
    return rows


class PairedAssessment(unittest.TestCase):
    def test_empty_incomplete_and_complete_keep_inventory_and_scope(self):
        empty = paired.assess([])
        self.assertEqual(empty['status_counts'], {'NOT_RUN': 583})
        self.assertEqual(paired.assess(reported()[:-1])['status_counts'], {'NOT_RUN': 583})
        report = paired.assess(reported())
        self.assertEqual(report['status_counts'], {'NOT_RUN': 582, 'PARTIAL': 1})
        self.assertEqual(len(report['scenario_results']), 8)
        self.assertEqual(report['evidence_kind'], 'reported-library-output')
        self.assertFalse(report['historical_results_merged'])
        self.assertEqual(report['scope']['full_conformance'], 'NOT_ESTABLISHED')
        self.assertEqual(report['scope']['deployed_registry'], 'NOT_BOUND')
        self.assertEqual([c['id'] for c in report['cases'] if c['status'] == 'PARTIAL'], [paired.CONTRACT])

    def test_counters_version_and_each_complete_view_are_checked(self):
        for change in ('source', 'producer', 'version', 'service', 'key', 'context', 'media', 'missing-second', 'code', 'alias'):
            with self.subTest(change=change):
                rows = reported()
                value = rows[0]['actual']
                first = value['results'][0]
                if change == 'source': value['source_calls'] = 1
                elif change == 'producer': value['producer_calls'] = 2
                elif change == 'missing-second': value['results'].pop()
                elif change == 'code': first['code'] = 'record.invalid'
                elif change == 'media': first['did11']['content_type'] = 'application/did+json'
                else:
                    view = first['core10']
                    key = 'metadata_hex' if change in ('version', 'alias') else 'body_hex'
                    body = paired.load(bytes.fromhex(view[key]))
                    if change == 'version': body['versionId'] = '8'
                    elif change == 'service': body['service'][0]['serviceEndpoint'] = 'https://next.example/a2a'
                    elif change == 'key': body['verificationMethod'][0]['publicKeyJwk']['crv'] = 'Ed25519'
                    elif change == 'context': body['@context'] = 'https://www.w3.org/ns/did/v1.1'
                    elif change == 'alias': body['canonicalId'] = 'did:example:other'
                    view[key] = paired.canonical(body).hex()
                self.assertEqual(paired.assess(rows)['status_counts'], {'NOT_RUN': 582, 'FAIL': 1})

    def test_typed_false_missing_members_array_order_and_partial_returns_fail(self):
        for change in ('number', 'string', 'absent', 'array', 'partial', 'bad-json', 'bad-hex', 'bad-shape'):
            rows = reported()
            first = rows[0]['actual']['results'][0]['core10']
            if change == 'partial':
                row = next(r for r in rows if r['id'] == 'second-error')
                row['actual']['results'][0]['core10'] = copy.deepcopy(first)
            elif change == 'bad-json': first['body_hex'] = b'[]'.hex()
            elif change == 'bad-hex': first['metadata_hex'] = 'not-hex'
            elif change == 'bad-shape': rows[0]['actual']['source_calls'] = False
            elif change == 'array':
                body = paired.load(bytes.fromhex(first['body_hex']))
                body['verificationMethod'].reverse()
                first['body_hex'] = paired.canonical(body).hex()
            else:
                md = paired.load(bytes.fromhex(first['metadata_hex']))
                if change == 'number': md['deactivated'] = 0
                elif change == 'string': md['deactivated'] = 'false'
                else: del md['deactivated']
                first['metadata_hex'] = paired.canonical(md).hex()
            self.assertEqual(paired.assess(rows)['status_counts'].get('FAIL'), 1, change)

    def test_observation_admission_refuses_duplicates_unknowns_and_wrong_input(self):
        base = reported()
        for value in (None, base + base, [base[0], base[0]], [{'id': 'unknown', 'input_sha256': 'x', 'actual': {}}],
                      [{'id': [], 'input_sha256': 'x', 'actual': {}}],
                      [{**base[0], 'input_sha256': '0' * 64}], [{**base[0], 'extra': True}]):
            with self.assertRaises((ValueError, TypeError)):
                paired.assess(value)

    def test_fixture_and_subject_hashes_and_closed_semantics(self):
        for relative, function, digest_name in ((paired.FIXTURE_PATH, paired.fixtures, 'FIXTURE_SHA256'),
                                                (paired.SUBJECT_PATH, paired.subject, 'SUBJECT_SHA256')):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / relative
                target.parent.mkdir(parents=True)
                original = (paired.ROOT / relative).read_bytes()
                target.write_bytes(original + b' ')
                with self.assertRaises(ValueError): function(root)
                value = paired.load(original)
                mutations = []
                if function is paired.fixtures:
                    changed = copy.deepcopy(value); changed['scope'] = 'operating'; mutations.append(changed)
                    changed = copy.deepcopy(value); changed['cases'][0]['input'] = {'scenario': 'other'}; mutations.append(changed)
                    changed = copy.deepcopy(value); changed['cases'].pop(); mutations.append(changed)
                else:
                    changed = copy.deepcopy(value); changed['revision'] = 'x'; mutations.append(changed)
                    changed = copy.deepcopy(value); changed['modules']['github.com/sage-x-project/did-go']['Sum'] = 'invalid'; mutations.append(changed)
                    changed = copy.deepcopy(value); changed['revision'] = '0' * 40; mutations.append(changed)
                for changed in mutations:
                    raw = paired.canonical(changed)
                    target.write_bytes(raw)
                    with patch.object(paired, digest_name, paired.sha(raw)), self.assertRaises(ValueError): function(root)

    def test_module_identity_and_cache_verification(self):
        expected = paired.subject()['modules']
        class Response:
            def __init__(self, raw): self.stdout = raw
        def execute(args, *_):
            if args[1:3] == ['mod', 'verify']: return Response(b'all modules verified\n')
            path = args[-1]
            return Response(paired.canonical({'Path': path, **expected[path]}))
        with patch.object(paired, 'execute', side_effect=execute):
            values = paired.module_info('fixture-go', Path('.'), {}, expected)
            self.assertEqual({r['Path'] for r in values}, set(expected))
        with patch.object(paired, 'execute', return_value=Response(paired.canonical({'Path': 'wrong'}))):
            with self.assertRaises(ValueError): paired.module_info('fixture-go', Path('.'), {}, expected)
        self.assertEqual(len(paired.observer_sources(paired.ROOT)), 6)

    def test_cli_exclusive_outputs_and_preserved_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            with patch('sys.argv', ['paired', '--output', str(path)]), contextlib.redirect_stdout(io.StringIO()):
                paired.main()
            self.assertEqual(json.loads(path.read_text())['status_counts'], {'NOT_RUN': 583})
            before = path.read_bytes()
            with patch('sys.argv', ['paired', '--output', str(path)]), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                paired.main()
            self.assertEqual(path.read_bytes(), before)
            failed = paired.assess(reported())
            failed['status_counts'] = {'NOT_RUN': 582, 'FAIL': 1}
            target = Path(directory) / 'finding.json'
            with patch.object(paired, 'assess', return_value=failed), patch('sys.argv', ['paired', '--output', str(target)]), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                paired.main()
            self.assertEqual(json.loads(target.read_text())['status_counts']['FAIL'], 1)
            # A symlink must not replace its target either.
            link = Path(directory) / 'link.json'; link.symlink_to(path)
            with patch('sys.argv', ['paired', '--output', str(link)]), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                paired.main()
            self.assertEqual(path.read_bytes(), before)

    def test_historical_fixtures_and_subject_remain_frozen(self):
        self.assertEqual(paired.sha((paired.ROOT / 'vectors/0.10.0/did-profile-observations.json').read_bytes()),
                         '299a25a3cee82880490ea46fb61cc15371e8175961fd3c8c4f725ea0f21cfbbf')
        self.assertEqual(paired.sha((paired.ROOT / 'verification/0.10.0/a2a-did/did-response-current-subject.json').read_bytes()),
                         '28946db1c3295b38fb8fa90d9dbb8f746ee4a565516810bfec26bd9679a1d8f4')


if __name__ == '__main__': unittest.main()
