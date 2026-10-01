"""Check service observation vectors, configuration, and revision guards."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT, sha
from observe_reconciled_reg08_service_storage import (
    EXPECTED, GO_REVISION, RUST_REVISION, SERVICE_REVISION,
    VECTOR, VECTOR_SHA256, candidate, check_vector, configuration, observe,
)


def test_vectors_and_configuration():
    raw = (ROOT / VECTOR).read_bytes()
    assert sha(raw) == VECTOR_SHA256
    assert [row['id'] for row in check_vector(ROOT)['cases']] == list(EXPECTED)
    base = json.loads((ROOT / 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json')
                      .read_bytes())['base']
    cfg = configuration(Path('/tmp/service'),
                        {'ca_pem': Path('/tmp/service/ca.pem'), 'client_pin': 'pin'},
                        Path('/tmp/service/public.pem'), Path('/tmp/service/public.key'),
                        base, True)
    assert cfg['source'] == 'https://agents.example.com'
    assert cfg['did'] == base['expected_did']
    assert cfg['client_actors'] == {'pin': 'operator'}
    assert cfg['create'] is True
    record = json.loads(candidate(base, 'created', '1', 100))
    assert record['record']['version'] == '1'
    assert record['issued'] == 100 and record['expires'] == 105


def test_changed_vector_and_source_are_rejected():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / VECTOR
        path.parent.mkdir(parents=True)
        path.write_bytes((ROOT / VECTOR).read_bytes() + b' ')
        try:
            check_vector(root)
        except ValueError as error:
            assert 'vector changed' in str(error)
        else:
            raise AssertionError('changed vector was accepted')
    with patch('observe_reconciled_reg08_service_storage.check'), patch(
            'observe_reconciled_reg08_service_storage.revision',
            side_effect=[SERVICE_REVISION, GO_REVISION, 'unexpected']):
        try:
            observe(Path('/tmp/service'), Path('/tmp/go'), Path('/tmp/rust'))
        except ValueError as error:
            assert 'revision mismatch' in str(error)
        else:
            raise AssertionError('changed core revision was accepted')


if __name__ == '__main__':
    test_vectors_and_configuration()
    test_changed_vector_and_source_are_rejected()
