"""Fixture, revision, and scope checks for local REG-08 TLS observations."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_tls_origin import (
    GO_REVISION, RUST_REVISION, VECTOR, observe, payload,
)


class FakeServer:
    endpoint = '127.0.0.1:12345'

    def __init__(self, *_args):
        pass

    def start(self):
        return self

    def stop(self):
        pass


def test_fixture_bound():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    assert len(suite['cases']) == 9
    servers = {'valid': FakeServer(), 'other': FakeServer()}
    roots = {'valid': b'valid', 'other': b'other'}
    for row in suite['cases']:
        request = json.loads(payload(suite['base'], row, servers, roots))
        assert request['destination'].startswith('127.0.0.1:')
        assert len(request['root_der']) < 16384


def observation_patches(binary, verdict):
    return (
        patch('observe_reconciled_reg08_tls_origin.check'),
        patch('observe_reconciled_reg08_tls_origin.revision',
              side_effect=[GO_REVISION, RUST_REVISION]),
        patch('observe_reconciled_reg08_tls_origin.build',
              return_value={'go': binary, 'rust': binary}),
        patch('observe_reconciled_reg08_tls_origin.certificate',
              return_value=(Path('cert'), Path('key'), b'root')),
        patch('observe_reconciled_reg08_tls_origin.LocalTLSServer', FakeServer),
        patch('observe_reconciled_reg08_tls_origin.run_case',
              side_effect=verdict),
    )


def test_report_scope_and_decision_drift():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'test-binary')
        patches = observation_patches(binary, lambda _binary, _base, row,
                                      _servers, _roots: row['expected'])
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            report = observe(Path(directory), Path(directory))
        assert report['subjects']['go']['matched'] == 9
        assert report['subjects']['rust']['matched'] == 9
        assert report['authenticated_http_record'] == 'NOT_RUN'
        assert all(value == 'NOT_RUN' for value in report['parent_cases'].values())
        assert report['conformance'] == 'NOT_ESTABLISHED'

        patches = observation_patches(binary, lambda *_args: 'RECORD_UNREACHABLE')
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core TLS origin mismatch' in str(error)
            else:
                raise AssertionError('incorrect TLS decision accepted')


def test_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_tls_origin.check'), patch(
                'observe_reconciled_reg08_tls_origin.revision',
                side_effect=['unexpected', RUST_REVISION]):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'revision mismatch' in str(error)
            else:
                raise AssertionError('core revision drift accepted')


if __name__ == '__main__':
    test_fixture_bound()
    test_report_scope_and_decision_drift()
    test_revision_drift()
