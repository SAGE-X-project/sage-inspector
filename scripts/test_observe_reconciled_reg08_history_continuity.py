"""Fixture and scope checks for asserted Registry history observations."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_history_continuity import (
    EXPECTED, GO_REVISION, RUST_REVISION, VECTOR, materialize, observe, request,
)


def test_fixture_and_materialization():
    suite = json.loads((ROOT / VECTOR).read_bytes())
    base = json.loads((ROOT / 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json')
                      .read_bytes())['base']
    assert {row['mode'] for row in suite['cases']} == set(EXPECTED)
    for row in suite['cases']:
        payload = json.loads(request(base, row))
        assert payload['action'] == 'history'
        assert payload['candidate'] and payload['did'] == base['expected_did']
        assert all(item['envelope'] for item in payload['history'])
    history, current = materialize(base['body']['record'], 'skipped-version')
    assert [entry['record']['version'] for entry in history] == ['1', '3']
    assert current['version'] == '3'
    history, current = materialize(base['body']['record'], 'complete-terminal')
    assert history[-1]['record']['state'] == current['state'] == 'deactivated'


def report_patches(binary, verdict):
    return (
        patch('observe_reconciled_reg08_history_continuity.check'),
        patch('observe_reconciled_reg08_history_continuity.revision',
              side_effect=[GO_REVISION, RUST_REVISION]),
        patch('observe_reconciled_reg08_history_continuity.build',
              return_value={'go': binary, 'rust': binary}),
        patch('observe_reconciled_reg08_history_continuity.run_case',
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
        assert report['asserted_history_continuity'] == 'BOUNDED'
        assert report['authenticated_source_history'] == 'NOT_RUN'
        assert report['controller_authentication'] == 'NOT_RUN'
        assert report['atomic_write'] == 'NOT_RUN'
        assert all(value == 'NOT_RUN' for value in report['parent_cases'].values())
        assert report['conformance'] == 'NOT_ESTABLISHED'

        patches = report_patches(binary, lambda *_args: 'RECORD_INVALID')
        with patches[0], patches[1], patches[2], patches[3]:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core history mismatch' in str(error)
            else:
                raise AssertionError('incorrect history decision accepted')


def test_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_history_continuity.check'), patch(
                'observe_reconciled_reg08_history_continuity.revision',
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
