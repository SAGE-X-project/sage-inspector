"""Check mTLS controller fixture identity, requests, and report boundaries."""

import base64
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_admin_mtls import (
    EXPECTED, GO_REVISION, RUST_REVISION, VECTOR,
    expectation, observe, request,
)


def test_vectors_and_requests():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    base = json.loads((ROOT / 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json')
                      .read_bytes())['base']
    assert [row['mode'] for row in suite['cases']] == list(EXPECTED)
    for row in suite['cases']:
        assert row['expected'] == expectation(row['mode'])
        payload = json.loads(request(base, row))
        assert set(payload) == {'candidate', 'operation', 'expected_version'}
        envelope = json.loads(base64.urlsafe_b64decode(payload['candidate'] + '=='))
        assert envelope['record']['id'] == base['expected_did']
        assert envelope['issued'] == row['now']
        assert envelope['expires'] == row['now'] + 5


def patches(binary, decision):
    return (
        patch('observe_reconciled_reg08_admin_mtls.check'),
        patch('observe_reconciled_reg08_admin_mtls.revision',
              side_effect=[GO_REVISION, RUST_REVISION]),
        patch('observe_reconciled_reg08_admin_mtls.certificates', return_value={}),
        patch('observe_reconciled_reg08_admin_mtls.build',
              return_value={'go': binary, 'rust': binary}),
        patch('observe_reconciled_reg08_admin_mtls.run_case', side_effect=decision),
    )


def test_report_scope_and_drift():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'test-binary')
        context = patches(binary, lambda _binary, _base, row, _certs, _path: row['expected'])
        with context[0], context[1], context[2], context[3], context[4]:
            report = observe(Path(directory), Path(directory))
        assert all(item['matched'] == len(EXPECTED)
                   for item in report['subjects'].values())
        assert report['controller_credential_binding'] == 'BOUNDED'
        for field in ('deployed_public_source_binding', 'delegation_state_provenance',
                      'production_admin_framing', 'remote_atomic_write'):
            assert report[field] == 'NOT_RUN'
        assert set(report['parent_cases'].values()) == {'NOT_RUN'}
        assert report['conformance'] == 'NOT_ESTABLISHED'

        context = patches(binary, lambda *_args: expectation('controller-create'))
        with context[0], context[1], context[2], context[3], context[4]:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'mTLS admin mismatch' in str(error)
            else:
                raise AssertionError('wrong mTLS decision accepted')


def test_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_admin_mtls.check'), patch(
                'observe_reconciled_reg08_admin_mtls.revision',
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
