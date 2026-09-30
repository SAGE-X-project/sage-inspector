"""Check local journal vectors, request boundaries and report scope."""

import base64
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_durable_write import (
    EXPECTED, GO_REVISION, RUST_REVISION, SEQUENCES, VECTOR,
    expectation, materialize, observe, request,
)


def test_vectors_and_requests():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    base = json.loads((ROOT / 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json')
                      .read_bytes())['base']
    assert [row['mode'] for row in suite['cases']] == list(EXPECTED)
    assert {name: [row['mode'] for row in suite['cases']
                   if row['sequence'] == name] for name in SEQUENCES} == SEQUENCES
    for row in suite['cases']:
        assert row['expected'] == expectation(row['mode'])
        payload = json.loads(request(base, row, Path('/tmp/journal-test')))
        assert payload['action'] == 'journal-transaction'
        assert payload['did'] == base['expected_did']
        assert payload['journal_path'] == '/tmp/journal-test'
        decoded = json.loads(base64.urlsafe_b64decode(payload['candidate'] + '=='))
        assert decoded['record'] == materialize(base['body']['record'], row['mode'])[0]
        assert decoded['issued'] == payload['candidate_now']
        assert decoded['expires'] == payload['candidate_now'] + 5
    assert materialize(base['body']['record'], 'expired-create')[0]['keys'][0]['expires'] == 101
    assert len(materialize(base['body']['record'], 'expired-repair')[0]['keys']) == 3
    assert materialize(base['body']['record'], 'recovered-service-update')[0]['services']


def patches(binary, decision):
    return (
        patch('observe_reconciled_reg08_durable_write.check'),
        patch('observe_reconciled_reg08_durable_write.revision',
              side_effect=[GO_REVISION, RUST_REVISION]),
        patch('observe_reconciled_reg08_durable_write.build',
              return_value={'go': binary, 'rust': binary}),
        patch('observe_reconciled_reg08_durable_write.run_case',
              side_effect=decision),
    )


def test_report_scope_and_drift():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'test-binary')
        context = patches(binary, lambda _binary, _base, row, _path: row['expected'])
        with context[0], context[1], context[2], context[3]:
            report = observe(Path(directory), Path(directory))
        assert all(item['matched'] == len(EXPECTED)
                   for item in report['subjects'].values())
        assert report['local_durable_write_journal'] == 'BOUNDED'
        for field in ('authenticated_source_history', 'credential_authentication',
                      'delegation_state_provenance', 'deployed_atomic_write'):
            assert report[field] == 'NOT_RUN'
        assert set(report['parent_cases'].values()) == {'NOT_RUN'}
        assert report['conformance'] == 'NOT_ESTABLISHED'

        context = patches(binary, lambda *_args: expectation('create'))
        with context[0], context[1], context[2], context[3]:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'journal mismatch' in str(error)
            else:
                raise AssertionError('incorrect journal result accepted')


def test_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_durable_write.check'), patch(
                'observe_reconciled_reg08_durable_write.revision',
                side_effect=['unexpected', RUST_REVISION]):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'revision mismatch' in str(error)
            else:
                raise AssertionError('core revision drift accepted')


if __name__ == '__main__':
    test_vectors_and_requests()
    test_report_scope_and_drift()
    test_revision_drift()
