"""Scope and failure checks for bounded REG-08 envelope observations."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from observe_reconciled_reg08_envelope import (
    GO_REVISION, RUST_REVISION, observe, request,
)


def test_bounded_request():
    payload = request({'id': 'oversize', 'repeat_byte': ' ',
                       'repeat_count': 69633, 'now': 100,
                       'expected': 'SIZE_EXCEEDED'})
    assert len(payload) < 280000
    assert ' ' * 69633 in payload


def test_report_scope():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        go_binary = root / 'go'
        rust_binary = root / 'rust'
        go_binary.write_bytes(b'go-test-binary')
        rust_binary.write_bytes(b'rust-test-binary')
        with patch('observe_reconciled_reg08_envelope.revision',
                   side_effect=[GO_REVISION, RUST_REVISION]), patch(
                       'observe_reconciled_reg08_envelope.build',
                       return_value={'go': go_binary, 'rust': rust_binary}), patch(
                           'observe_reconciled_reg08_envelope.run_case',
                           side_effect=lambda _binary, row: row['expected']):
            report = observe(root, root)
        assert report['subjects']['go']['matched'] == 20
        assert report['subjects']['rust']['matched'] == 20
        assert all(status == 'NOT_RUN' for status in report['parent_cases'].values())
        assert report['complete_registry_record'] == 'NOT_RUN'
        assert report['conformance'] == 'NOT_ESTABLISHED'


def test_rejects_revision_and_decision_drift():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with patch('observe_reconciled_reg08_envelope.revision',
                   side_effect=['unexpected', RUST_REVISION]):
            try:
                observe(root, root)
            except ValueError as error:
                assert 'revision mismatch' in str(error)
            else:
                raise AssertionError('subject revision drift accepted')
        binary = root / 'binary'
        binary.write_bytes(b'test-binary')
        with patch('observe_reconciled_reg08_envelope.revision',
                   side_effect=[GO_REVISION, RUST_REVISION]), patch(
                       'observe_reconciled_reg08_envelope.build',
                       return_value={'go': binary, 'rust': binary}), patch(
                           'observe_reconciled_reg08_envelope.run_case',
                           return_value='RECORD_INVALID'):
            try:
                observe(root, root)
            except ValueError as error:
                assert 'core envelope mismatch' in str(error)
            else:
                raise AssertionError('incorrect core decision accepted')


if __name__ == '__main__':
    test_bounded_request()
    test_report_scope()
    test_rejects_revision_and_decision_drift()
