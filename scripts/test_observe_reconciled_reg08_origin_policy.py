"""Bounded fixture and scope checks for REG-08 origin policy observations."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_origin_policy import (
    GO_REVISION, RUST_REVISION, VECTOR, observe, payload, URL,
)


def test_fixture_bound():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    assert len(suite['cases']) == 15
    for row in suite['cases']:
        request = json.loads(payload(suite['base'], row))
        assert request['expected_did'].startswith('did:sage:')


def test_report_scope_and_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'test-binary')
        result = lambda _binary, _base, row: {
            'verdict': row['expected'],
            'url': URL if row['expected'] == 'POLICY_ACCEPT' else '',
        }
        with patch('observe_reconciled_reg08_origin_policy.check'), patch(
                'observe_reconciled_reg08_origin_policy.revision',
                side_effect=[GO_REVISION, RUST_REVISION]), patch(
                    'observe_reconciled_reg08_origin_policy.build',
                    return_value={'go': binary, 'rust': binary}), patch(
                        'observe_reconciled_reg08_origin_policy.run_case',
                        side_effect=result):
            report = observe(Path(directory), Path(directory))
        assert report['subjects']['go']['matched'] == 15
        assert report['subjects']['rust']['matched'] == 15
        assert all(status == 'NOT_RUN' for status in report['parent_cases'].values())
        assert report['trusted_tls_origin_and_destination'] == 'NOT_RUN'
        assert report['conformance'] == 'NOT_ESTABLISHED'
        with patch('observe_reconciled_reg08_origin_policy.check'), patch(
                'observe_reconciled_reg08_origin_policy.revision',
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
        with patch('observe_reconciled_reg08_origin_policy.check'), patch(
                'observe_reconciled_reg08_origin_policy.revision',
                side_effect=[GO_REVISION, RUST_REVISION]), patch(
                    'observe_reconciled_reg08_origin_policy.build',
                    return_value={'go': binary, 'rust': binary}), patch(
                        'observe_reconciled_reg08_origin_policy.run_case',
                        return_value={'verdict': 'RECORD_INVALID', 'url': ''}):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core origin policy mismatch' in str(error)
            else:
                raise AssertionError('incorrect core decision accepted')


if __name__ == '__main__':
    test_fixture_bound()
    test_report_scope_and_revision_drift()
    test_decision_drift()
