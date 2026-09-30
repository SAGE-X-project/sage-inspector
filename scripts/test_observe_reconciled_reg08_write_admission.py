"""Fixture and scope checks for web Registry write policy observations."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_write_admission import (
    EXPECTED, GO_REVISION, RUST_REVISION, VECTOR, materialize, observe, request,
)


def test_fixture_and_materialization():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    base = json.loads((ROOT / 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json')
                      .read_bytes())['base']
    assert {row['mode'] for row in suite['cases']} == set(EXPECTED)
    for row in suite['cases']:
        payload = json.loads(request(base, row))
        assert payload['candidate'] and payload['did'] == base['expected_did']
        assert payload['action'].startswith('admission-')
    delegated = materialize(base['body']['record'], 'delegated-activate')
    assert delegated['actor'] == 'assistant' and delegated['scope'] == 'activate'
    assert delegated['expected_version'] == '1'
    stale = materialize(base['body']['record'], 'wrong-expected-version')
    assert stale['expected_version'] == '2'
    assert stale['previous']['version'] == '1'
    missing = materialize(base['body']['record'], 'missing-mutation-credentials')
    assert not missing['authenticated']


def report_patches(binary, verdict):
    return (
        patch('observe_reconciled_reg08_write_admission.check'),
        patch('observe_reconciled_reg08_write_admission.revision',
              side_effect=[GO_REVISION, RUST_REVISION]),
        patch('observe_reconciled_reg08_write_admission.build',
              return_value={'go': binary, 'rust': binary}),
        patch('observe_reconciled_reg08_write_admission.run_case',
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
        assert report['fixture_authority_policy'] == 'BOUNDED'
        for name in ('credential_authentication', 'delegation_state_provenance',
                     'atomic_write', 'authenticated_source_history'):
            assert report[name] == 'NOT_RUN'
        assert all(value == 'NOT_RUN' for value in report['parent_cases'].values())
        assert report['conformance'] == 'NOT_ESTABLISHED'

        patches = report_patches(binary, lambda *_args: 'WRITE_REJECTED')
        with patches[0], patches[1], patches[2], patches[3]:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core admission mismatch' in str(error)
            else:
                raise AssertionError('incorrect admission decision accepted')


def test_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_write_admission.check'), patch(
                'observe_reconciled_reg08_write_admission.revision',
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
