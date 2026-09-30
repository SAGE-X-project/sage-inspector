"""Fixture and scope checks for expired signing-key recovery observations."""

import base64
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_expired_key_recovery import (
    EXPECTED, GO_REVISION, RUST_REVISION, VECTOR, materialize, observe, request,
)


def test_fixture_and_materialization():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    base = json.loads((ROOT / 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json')
                      .read_bytes())['base']
    assert {row['mode'] for row in suite['cases']} == set(EXPECTED)
    for row in suite['cases']:
        payload = json.loads(request(base, row))
        previous = json.loads(base64.urlsafe_b64decode(payload['previous'] + '=='))['record']
        candidate = json.loads(base64.urlsafe_b64decode(payload['candidate'] + '=='))['record']
        assert previous['version'] == '2' and candidate['version'] == '3'
        assert previous['keys'][0]['expires'] < payload['previous_now']
        assert payload['candidate_now'] == 102
    delegated = materialize(base['body']['record'], 'delegated-repair')
    assert delegated['actor'] == 'assistant' and delegated['scope'] == 'add-key'
    strict = materialize(base['body']['record'], 'strict-transition')
    assert strict['action'] == 'transition'
    unrepaired = materialize(base['body']['record'], 'unrepaired-candidate')
    assert all(key['alg'] == 'x25519' or key.get('expires', 999) < 102
               for key in unrepaired['candidate']['keys'])
    assert materialize(base['body']['record'], 'stale-version')['expected_version'] == '1'
    assert not materialize(base['body']['record'], 'missing-credentials')['authenticated']


def report_patches(binary, verdict):
    return (
        patch('observe_reconciled_reg08_expired_key_recovery.check'),
        patch('observe_reconciled_reg08_expired_key_recovery.revision',
              side_effect=[GO_REVISION, RUST_REVISION]),
        patch('observe_reconciled_reg08_expired_key_recovery.build',
              return_value={'go': binary, 'rust': binary}),
        patch('observe_reconciled_reg08_expired_key_recovery.run_case',
              side_effect=verdict),
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
        assert report['expired_key_recovery_policy'] == 'BOUNDED'
        for name in ('credential_authentication', 'delegation_state_provenance',
                     'authenticated_source_history', 'atomic_write'):
            assert report[name] == 'NOT_RUN'
        assert all(value == 'NOT_RUN' for value in report['parent_cases'].values())
        assert report['conformance'] == 'NOT_ESTABLISHED'

        patches = report_patches(binary, lambda *_args: 'WRITE_REJECTED')
        with patches[0], patches[1], patches[2], patches[3]:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core recovery mismatch' in str(error)
            else:
                raise AssertionError('incorrect recovery decision accepted')


def test_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_expired_key_recovery.check'), patch(
                'observe_reconciled_reg08_expired_key_recovery.revision',
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
