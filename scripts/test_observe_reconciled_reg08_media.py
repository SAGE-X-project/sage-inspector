"""Scope and failure checks for bounded core media observations."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from observe_reconciled_reg08_media import GO_REVISION, RUST_REVISION, observe


def test_report_and_scope():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        go_binary = root / 'go'
        rust_binary = root / 'rust'
        go_binary.write_bytes(b'go-test-binary')
        rust_binary.write_bytes(b'rust-test-binary')
        with patch('observe_reconciled_reg08_media.revision',
                   side_effect=[GO_REVISION, RUST_REVISION]), patch(
                       'observe_reconciled_reg08_media.build',
                       return_value={'go': go_binary, 'rust': rust_binary}), patch(
                           'observe_reconciled_reg08_media.run_case',
                           side_effect=lambda _binary, row: row['expected']):
            report = observe(root, root)
        assert report['subjects']['go']['matched'] == 13
        assert report['subjects']['rust']['matched'] == 13
        assert report['subjects']['go']['executable_sha256'] != report['subjects']['rust']['executable_sha256']
        assert report['parent_cases'] == {'REG-08-P': 'NOT_RUN', 'REG-08-N04': 'NOT_RUN'}
        assert report['complete_registry_record'] == 'NOT_RUN'
        assert report['conformance'] == 'NOT_ESTABLISHED'


def test_rejects_subject_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_media.revision',
                   side_effect=['unexpected', RUST_REVISION]):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'revision mismatch' in str(error)
            else:
                raise AssertionError('subject revision drift accepted')


def test_rejects_case_mismatch():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        binary = root / 'binary'
        binary.write_bytes(b'test-binary')
        with patch('observe_reconciled_reg08_media.revision',
                   side_effect=[GO_REVISION, RUST_REVISION]), patch(
                       'observe_reconciled_reg08_media.build',
                       return_value={'go': binary, 'rust': binary}), patch(
                           'observe_reconciled_reg08_media.run_case',
                           return_value='RECORD_INVALID'):
            try:
                observe(root, root)
            except ValueError as error:
                assert 'core media mismatch' in str(error)
            else:
                raise AssertionError('incorrect core decision accepted')


if __name__ == '__main__':
    test_report_and_scope()
    test_rejects_subject_revision_drift()
    test_rejects_case_mismatch()
