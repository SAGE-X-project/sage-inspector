"""Check public Registry binding vectors and bounded report meaning."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_reconciled_reg08_public_binding import (
    GO_REVISION, RUST_REVISION, VECTOR, VECTOR_SHA256, observe, public_body,
)
from current_spec_catalog import sha


def test_vectors_and_bodies():
    raw = (ROOT / VECTOR).read_bytes()
    assert sha(raw) == VECTOR_SHA256
    rows = json.loads(raw)['cases']
    assert len(rows) == 7
    assert len({row['id'] for row in rows}) == len(rows)
    proof = json.loads((ROOT / 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json')
                       .read_bytes())['base']
    created = json.loads(public_body(proof, 'created', 100))
    different = json.loads(public_body(proof, 'different', 100))
    assert created['record']['id'] == proof['expected_did']
    assert created['record']['version'] == '1'
    assert different['record']['version'] == '2'
    assert created['issued'] == 100 and created['expires'] == 105


def test_report_scope_and_mismatch():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'public-adapter')
        mocks = (
            patch('observe_reconciled_reg08_public_binding.check'),
            patch('observe_reconciled_reg08_public_binding.revision',
                  side_effect=[GO_REVISION, RUST_REVISION]),
            patch('observe_reconciled_reg08_public_binding.certificates', return_value={}),
            patch('observe_reconciled_reg08_public_binding.public_certificate',
                  return_value=(Path(directory), Path(directory))),
            patch('observe_reconciled_reg08_public_binding.build',
                  return_value={'go': binary, 'rust': binary}),
            patch('observe_reconciled_reg08_public_binding.build_admin',
                  return_value=binary),
            patch('observe_reconciled_reg08_public_binding.run_case',
                  return_value={'verdict': 'TRANSITION_ACCEPT', 'committed': True}),
            patch('observe_reconciled_reg08_public_binding.run_public',
                  side_effect=lambda _binary, _journal, row, *_args: row['expected']),
        )
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], mocks[5], mocks[6], mocks[7]:
            report = observe(Path(directory), Path(directory))
        assert all(item['matched'] == 7 for item in report['subjects'].values())
        assert report['public_journal_snapshot_match'] == 'BOUNDED'
        assert set(report['parent_cases'].values()) == {'NOT_RUN'}
        assert report['conformance'] == 'NOT_ESTABLISHED'
        for field in ('deployed_storage_binding', 'production_admin_framing',
                      'delegation_state_provenance', 'remote_atomic_write'):
            assert report[field] == 'NOT_RUN'

        wrong = patch('observe_reconciled_reg08_public_binding.run_public',
                      return_value='MATCH')
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], mocks[5], mocks[6], wrong:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'core public binding mismatch' in str(error)
            else:
                raise AssertionError('wrong public binding result accepted')


if __name__ == '__main__':
    test_vectors_and_bodies()
    test_report_scope_and_mismatch()
