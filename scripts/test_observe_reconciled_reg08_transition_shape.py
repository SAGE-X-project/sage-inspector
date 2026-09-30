"""Fixture and scope checks for web Registry transition observations."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_transition_shape import (
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
    action, before, after, operation = materialize(
        base['body']['record'], 'add-kem-revoked-endorser')
    assert action == 'transition' and operation == 'add-key'
    assert len(after['keys']) == len(before['keys']) + 1
    assert before['keys'][0]['state'] == after['keys'][0]['state'] == 'revoked'


def report_patches(binary, verdict):
    return (
        patch('observe_reconciled_reg08_transition_shape.check'),
        patch('observe_reconciled_reg08_transition_shape.revision',
              side_effect=[GO_REVISION, RUST_REVISION]),
        patch('observe_reconciled_reg08_transition_shape.build',
              return_value={'go': binary, 'rust': binary}),
        patch('observe_reconciled_reg08_transition_shape.run_case',
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
        assert report['creation_and_transition_shape'] == 'BOUNDED'
        assert report['controller_authentication'] == 'NOT_RUN'
        assert report['complete_authenticated_history'] == 'NOT_RUN'
        assert report['atomic_write'] == 'NOT_RUN'
        assert all(value == 'NOT_RUN' for value in report['parent_cases'].values())
        assert report['conformance'] == 'NOT_ESTABLISHED'

        patches = report_patches(binary, lambda *_args: 'RECORD_INVALID')
        with patches[0], patches[1], patches[2], patches[3]:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core transition mismatch' in str(error)
            else:
                raise AssertionError('incorrect transition decision accepted')


def test_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_transition_shape.check'), patch(
                'observe_reconciled_reg08_transition_shape.revision',
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
