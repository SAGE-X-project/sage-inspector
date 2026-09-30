"""Bounded fixture and scope checks for REG-08 proof observations."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_record_proofs import (
    GO_REVISION, RUST_REVISION, VECTOR, observe,
)
from observe_reconciled_reg08_record_shape import request


def test_fixture_bound():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    assert len(suite['cases']) == 16
    for row in suite['cases']:
        payload = json.loads(request(suite['base'], row))
        assert len(payload['body']) <= 69632
        assert payload['expected_did'] == suite['base']['expected_did']


def test_report_scope_and_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'test-binary')
        with patch('observe_reconciled_reg08_record_proofs.check'), patch(
                'observe_reconciled_reg08_record_proofs.revision',
                side_effect=[GO_REVISION, RUST_REVISION]), patch(
                    'observe_reconciled_reg08_record_proofs.build',
                    return_value={'go': binary, 'rust': binary}), patch(
                        'observe_reconciled_reg08_record_proofs.run_case',
                        side_effect=lambda _binary, _base, row: row['expected']):
            report = observe(Path(directory), Path(directory))
        assert report['subjects']['go']['matched'] == 16
        assert report['subjects']['rust']['matched'] == 16
        assert all(status == 'NOT_RUN' for status in report['parent_cases'].values())
        assert report['historical_signer_authority'] == 'NOT_RUN'
        assert report['conformance'] == 'NOT_ESTABLISHED'
        with patch('observe_reconciled_reg08_record_proofs.check'), patch(
                'observe_reconciled_reg08_record_proofs.revision',
                side_effect=['unexpected', RUST_REVISION]):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'revision mismatch' in str(error)
            else:
                raise AssertionError('core revision drift accepted')


def test_decision_drift():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'test-binary')
        with patch('observe_reconciled_reg08_record_proofs.check'), patch(
                'observe_reconciled_reg08_record_proofs.revision',
                side_effect=[GO_REVISION, RUST_REVISION]), patch(
                    'observe_reconciled_reg08_record_proofs.build',
                    return_value={'go': binary, 'rust': binary}), patch(
                        'observe_reconciled_reg08_record_proofs.run_case',
                        return_value='RECORD_INVALID'):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core proof mismatch' in str(error)
            else:
                raise AssertionError('incorrect core decision accepted')


if __name__ == '__main__':
    test_fixture_bound()
    test_report_scope_and_revision_drift()
    test_decision_drift()
