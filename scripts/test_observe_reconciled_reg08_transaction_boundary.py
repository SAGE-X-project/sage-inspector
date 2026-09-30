"""Fixture and report-scope checks for Registry transaction decisions."""

import base64
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_transaction_boundary import (
    EXPECTED, GO_REVISION, RUST_REVISION, VECTOR, expectation,
    materialize, observe, request,
)


def test_fixture_and_materialization():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    base = json.loads((ROOT / 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json')
                      .read_bytes())['base']
    assert {row['mode'] for row in suite['cases']} == set(EXPECTED)
    for row in suite['cases']:
        assert row['expected'] == expectation(row['mode'])
        payload = json.loads(request(base, row))
        assert payload['action'] == 'transaction'
        assert payload['did'] == base['expected_did']
        assert payload['trusted_source'] == 'trusted-web-origin'
        assert payload['candidate']
        for entry in payload['history']:
            assert json.loads(base64.urlsafe_b64decode(entry['envelope'] + '=='))['record']
    expired = materialize(base['body']['record'], 'expired-key-recovery')
    assert expired['now'] == 102 and expired['previous']['keys'][0]['expires'] == 101
    assert len(expired['candidate']['keys']) == 3
    assert materialize(base['body']['record'], 'wrong-source')['source'] == 'other-origin'
    assert materialize(base['body']['record'], 'terminal-reuse')['tombstoned']
    assert not materialize(base['body']['record'], 'missing-credentials')['authenticated']


def report_patches(binary, decision):
    return (
        patch('observe_reconciled_reg08_transaction_boundary.check'),
        patch('observe_reconciled_reg08_transaction_boundary.revision',
              side_effect=[GO_REVISION, RUST_REVISION]),
        patch('observe_reconciled_reg08_transaction_boundary.build',
              return_value={'go': binary, 'rust': binary}),
        patch('observe_reconciled_reg08_transaction_boundary.run_case',
              side_effect=decision),
    )


def test_report_scope_and_decision_drift():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'test-binary')
        patches = report_patches(binary, lambda _binary, _base, row: row['expected'])
        with patches[0], patches[1], patches[2], patches[3]:
            report = observe(Path(directory), Path(directory))
        assert report['subjects']['go']['matched'] == len(EXPECTED)
        assert report['subjects']['rust']['matched'] == len(EXPECTED)
        assert report['transaction_decision'] == 'BOUNDED'
        for name in ('authenticated_source_history', 'credential_authentication',
                     'delegation_state_provenance', 'atomic_write'):
            assert report[name] == 'NOT_RUN'
        assert all(value == 'NOT_RUN' for value in report['parent_cases'].values())
        assert report['conformance'] == 'NOT_ESTABLISHED'

        patches = report_patches(binary, lambda *_args: expectation('create'))
        with patches[0], patches[1], patches[2], patches[3]:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core transaction mismatch' in str(error)
            else:
                raise AssertionError('incorrect transaction decision accepted')


def test_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_transaction_boundary.check'), patch(
                'observe_reconciled_reg08_transaction_boundary.revision',
                side_effect=['unexpected', RUST_REVISION]):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'revision mismatch' in str(error)
            else:
                raise AssertionError('core revision drift accepted')


if __name__ == '__main__':
    test_fixture_and_materialization()
    test_report_scope_and_decision_drift()
    test_revision_drift()
