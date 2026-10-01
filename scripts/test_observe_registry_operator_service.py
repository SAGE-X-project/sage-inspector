"""Check the operator vector binding and refusal to promote local observations."""

import copy
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from current_spec_catalog import ROOT
from observe_registry_operator_service import (
    DID, GO_REVISION, ORIGIN, SERVICE_REVISION, SPEC_REVISION, VECTOR,
    check_report, check_vector, command, configuration, observe,
)


def test_vector_and_command_binding():
    suite = check_vector(ROOT)
    assert len(suite['cases']) == 17
    lifecycle = json.loads(command('activate', '2', candidate=b'{}'))
    assert set(lifecycle) == {'registry', 'did', 'operation',
                              'expected_version', 'candidate'}
    assert lifecycle['registry'] == ORIGIN and lifecycle['did'] == DID
    management = json.loads(command('authorize-operator', '2',
                                    target='delegate', scope='activate'))
    assert set(management) == {'registry', 'did', 'operation',
                               'expected_version', 'target_operator', 'scope'}
    assert 'candidate' not in management


def test_service_configuration_binds_separate_roles():
    with patch('observe_registry_operator_service.cert_pin', return_value='b' * 64):
        cfg = configuration(Path('/tmp/operator'),
                            {'ca_pem': Path('/tmp/operator/ca.pem'),
                             'client_pin': 'a' * 64,
                             'other_cert': Path('/tmp/operator/other.pem')},
                            Path('/tmp/operator/public.pem'),
                            Path('/tmp/operator/public.key'),
                            (Path('/tmp/operator/inspector.pem'),
                             Path('/tmp/operator/inspector.key'), 'c' * 64), True)
    assert cfg['client_actors'] == {'a' * 64: 'operator', 'b' * 64: 'delegate'}
    assert cfg['inspector_clients'] == ['c' * 64]
    assert cfg['create'] is True and cfg['journal_path'].startswith('/tmp/operator/')


def test_vector_mutation_is_rejected():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        path = root / VECTOR
        path.parent.mkdir(parents=True)
        path.write_bytes((ROOT / VECTOR).read_bytes() + b' ')
        try:
            check_vector(root)
        except ValueError as error:
            assert 'vector changed' in str(error)
        else:
            raise AssertionError('changed operator vector was accepted')


def test_report_does_not_promote_missing_evidence():
    cases = []
    for row in check_vector(ROOT)['cases']:
        entry = {'id': row['id'], 'parent_case_id': row['parent_case_id'],
                 'track': 'local_tls_runtime'}
        if row['id'] == 'storage-authority-loss':
            entry.update(status='NOT_RUN',
                         reason='No deployed origin and storage owner were supplied.')
        elif row['id'] == 'expired-key-management':
            entry.update(status='PARTIAL', reason='Expired signing keys and management '
                         'were observed; no protected-message authorization was exercised.')
        else:
            entry['status'] = 'PASS'
        cases.append(entry)
    report = {'schema_version': 1, 'kind': 'registry-operator-local-observation',
              'protocol_version': '0.10.0', 'spec_revision': SPEC_REVISION,
              'vector_sha256': 'c79ecaa507b8d92e2847924f1e4a19330ecfc2749372bfaa99d5503fd023046b',
              'subject_revisions': {'service': SERVICE_REVISION, 'go': GO_REVISION,
                                    'spec': SPEC_REVISION},
              'service_executable_sha256': 'a' * 64, 'cases': cases,
              'local_pass': 15, 'partial': 1, 'not_run': 1,
              'deployed_reg08': 'NOT_RUN', 'conformance': 'NOT_ESTABLISHED'}
    assert check_report(report)
    for field, value in [('conformance', 'PASS'), ('deployed_reg08', 'PASS')]:
        changed = copy.deepcopy(report)
        changed[field] = value
        try:
            check_report(changed)
        except ValueError:
            pass
        else:
            raise AssertionError('promoted report was accepted')
    changed = copy.deepcopy(report)
    next(row for row in changed['cases'] if row['id'] ==
         'storage-authority-loss')['status'] = 'PASS'
    try:
        check_report(changed)
    except ValueError:
        pass
    else:
        raise AssertionError('deployed case was promoted')


def test_recorded_report_matches_vector():
    path = ROOT / 'docs/evidence/registry-operator-0.10.0/local-service-observation.json'
    assert check_report(json.loads(path.read_bytes()))


def test_subject_revision_mismatch_stops_before_runtime():
    with patch('observe_registry_operator_service.revision',
               side_effect=[SERVICE_REVISION, GO_REVISION, 'unexpected']):
        try:
            observe(Path('/tmp/service'), Path('/tmp/go'), Path('/tmp/spec'))
        except ValueError as error:
            assert 'revision mismatch' in str(error)
        else:
            raise AssertionError('changed specification was accepted')


if __name__ == '__main__':
    test_vector_and_command_binding()
    test_service_configuration_binds_separate_roles()
    test_vector_mutation_is_rejected()
    test_report_does_not_promote_missing_evidence()
    test_recorded_report_matches_vector()
    test_subject_revision_mismatch_stops_before_runtime()
