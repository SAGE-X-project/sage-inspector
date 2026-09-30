"""Fixture, revision, and scope checks for bounded REG-08 HTTP observations."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_http_record import (
    EXPECTED, GO_REVISION, RUST_REVISION, VECTOR, observe, response,
)


def test_fixture_and_framing():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    assert {row['mode'] for row in suite['cases']} == set(EXPECTED)
    body = b'{}'
    assert response('valid', body).endswith(body)
    assert b'Content-Length: 2\r\n' in response('valid', body)
    assert b'Content-Length: 2\r\nContent-Length: 2\r\n' in response(
        'duplicate-length', body)
    assert b'Transfer-Encoding: chunked\r\n' in response('transfer-coding', body)


def report_patches(binary, verdict):
    return (
        patch('observe_reconciled_reg08_http_record.check'),
        patch('observe_reconciled_reg08_http_record.revision',
              side_effect=[GO_REVISION, RUST_REVISION]),
        patch('observe_reconciled_reg08_http_record.build',
              return_value={'go': binary, 'rust': binary}),
        patch('observe_reconciled_reg08_http_record.certificate',
              return_value=(Path('cert'), Path('key'), b'root')),
        patch('observe_reconciled_reg08_http_record.run_case',
              side_effect=verdict),
    )


def test_report_scope_and_decision_drift():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'test-binary')
        patches = report_patches(binary, lambda _binary, row, _body,
                                 _certs: row['expected'])
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            report = observe(Path(directory), Path(directory))
        assert report['subjects']['go']['matched'] == len(EXPECTED)
        assert report['subjects']['rust']['matched'] == len(EXPECTED)
        assert report['authenticated_http_record'] == 'BOUNDED_CONTENT_LENGTH'
        assert report['controller_and_mutation_history'] == 'NOT_RUN'
        assert all(value == 'NOT_RUN' for value in report['parent_cases'].values())
        assert report['conformance'] == 'NOT_ESTABLISHED'

        patches = report_patches(binary, lambda *_args: 'RECORD_UNREACHABLE')
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core HTTP record mismatch' in str(error)
            else:
                raise AssertionError('incorrect HTTP decision accepted')


def test_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_http_record.check'), patch(
                'observe_reconciled_reg08_http_record.revision',
                side_effect=['unexpected', RUST_REVISION]):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'revision mismatch' in str(error)
            else:
                raise AssertionError('core revision drift accepted')


if __name__ == '__main__':
    test_fixture_and_framing()
    test_report_scope_and_decision_drift()
    test_revision_drift()
