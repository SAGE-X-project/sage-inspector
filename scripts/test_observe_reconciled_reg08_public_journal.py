"""Check shared-journal vectors, configuration, and report limits."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT, sha
from observe_reconciled_reg08_public_journal import (
    EXPECTED, GO_REVISION, ORIGIN, RUST_REVISION, VECTOR, VECTOR_SHA256,
    observe, publisher_config,
)


def test_vectors_and_publisher_binding():
    raw = (ROOT / VECTOR).read_bytes()
    assert sha(raw) == VECTOR_SHA256
    rows = json.loads(raw)['cases']
    assert [row['id'] for row in rows] == list(EXPECTED)
    proof = json.loads((ROOT / 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json')
                       .read_bytes())['base']
    for row in rows:
        cfg = publisher_config(Path('/tmp/journal'), row, proof, b'cert', b'key')
        assert cfg['source'] == row['publisher_source']
        assert cfg['did'] == (proof['expected_did'] if row['publisher_did'] == 'expected'
                              else 'did:sage:web:agents.example.com:other-bot')
        assert cfg['now'] == row['now']
    assert rows[0]['publisher_source'] == ORIGIN


def test_report_scope_and_mismatch():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'binary'
        binary.write_bytes(b'publisher')
        programs = {'admin': binary, 'publisher': binary, 'fetcher': binary}
        mocks = (
            patch('observe_reconciled_reg08_public_journal.check'),
            patch('observe_reconciled_reg08_public_journal.revision',
                  side_effect=[GO_REVISION, RUST_REVISION]),
            patch('observe_reconciled_reg08_public_journal.certificates',
                  return_value={}),
            patch('observe_reconciled_reg08_public_journal.public_certificate_der',
                  return_value=(b'cert', b'key')),
            patch('observe_reconciled_reg08_public_journal.build',
                  return_value={'go': programs, 'rust': programs}),
            patch('observe_reconciled_reg08_public_journal.run_case_pair',
                  side_effect=lambda _programs, _journal, row, *_args:
                  (row['expected'], row['expected_version'])),
        )
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], mocks[5]:
            report = observe(Path(directory), Path(directory))
        assert all(item['matched'] == len(EXPECTED)
                   for item in report['subjects'].values())
        assert all(set(item['executables_sha256']) == {'admin', 'publisher', 'fetcher'}
                   for item in report['subjects'].values())
        assert report['local_shared_journal_publication'] == 'BOUNDED'
        assert set(report['parent_cases'].values()) == {'NOT_RUN'}
        assert report['conformance'] == 'NOT_ESTABLISHED'
        for field in ('deployed_public_server_storage', 'production_admin_framing',
                      'delegation_state_provenance', 'remote_atomic_write'):
            assert report[field] == 'NOT_RUN'

        wrong = patch('observe_reconciled_reg08_public_journal.run_case_pair',
                      return_value=('RECORD_ACCEPT', '1'))
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], wrong:
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'publication mismatch' in str(error)
            else:
                raise AssertionError('wrong publication result accepted')


def test_core_revision_drift():
    with tempfile.TemporaryDirectory() as directory:
        with patch('observe_reconciled_reg08_public_journal.check'), patch(
                'observe_reconciled_reg08_public_journal.revision',
                side_effect=['unexpected', RUST_REVISION]):
            try:
                observe(Path(directory), Path(directory))
            except ValueError as error:
                assert 'revision mismatch' in str(error)
            else:
                raise AssertionError('changed core revision accepted')


if __name__ == '__main__':
    test_vectors_and_publisher_binding()
    test_report_scope_and_mismatch()
    test_core_revision_drift()
