"""Scope and drift checks for REG-08 record-shape observations."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_record_shape import (
    GO_REVISION, RUST_REVISION, VECTOR, observe, request,
)


def test_exact_record_bound():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    rows = {row['id']: row for row in suite['cases']}
    for name, length in [('record-at-limit', 65536),
                         ('record-over-limit', 65537)]:
        payload = json.loads(request(suite['base'], rows[name]))
        record = payload['body'].split('"record":', 1)[1].split(',"issued":', 1)[0]
        assert len(record.encode()) == length
        assert len(payload['body']) <= 69632


def test_report_scope_and_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'test-binary')
        with patch('observe_reconciled_reg08_record_shape.check'), patch(
                'observe_reconciled_reg08_record_shape.revision',
                side_effect=[GO_REVISION, RUST_REVISION]), patch(
                    'observe_reconciled_reg08_record_shape.build',
                    return_value={'go': binary, 'rust': binary}), patch(
                        'observe_reconciled_reg08_record_shape.run_case',
                        side_effect=lambda _binary, _base, row: row['expected']):
            report = observe(Path(directory), Path(directory))
        assert report['subjects']['go']['matched'] == 26
        assert report['subjects']['rust']['matched'] == 26
        assert all(status == 'NOT_RUN' for status in report['parent_cases'].values())
        assert report['proof_verification'] == 'NOT_RUN'
        assert report['conformance'] == 'NOT_ESTABLISHED'
        with patch('observe_reconciled_reg08_record_shape.check'), patch(
                'observe_reconciled_reg08_record_shape.revision',
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
        with patch('observe_reconciled_reg08_record_shape.check'), patch(
                'observe_reconciled_reg08_record_shape.revision',
                side_effect=[GO_REVISION, RUST_REVISION]), patch(
                    'observe_reconciled_reg08_record_shape.build',
                    return_value={'go': binary, 'rust': binary}), patch(
                        'observe_reconciled_reg08_record_shape.run_case',
                        return_value='RECORD_INVALID'):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'record shape mismatch' in str(error)
            else:
                raise AssertionError('incorrect core decision accepted')


if __name__ == '__main__':
    test_exact_record_bound()
    test_report_scope_and_revision_drift()
    test_decision_drift()
