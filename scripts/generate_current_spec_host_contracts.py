"""Bind remaining EXEC host probes without fabricating deployed evidence."""

import hashlib
import json
from pathlib import Path

from current_spec_host_probe import CONTRACTS


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
REVIEWS = {
    'EXEC-02-N02': ('route_inventory', 'signer_authority', 'authorization_trace'),
    'EXEC-06-N01': ('baseline_admin_authority', 'plugin_write_boundary'),
    'EXEC-06-N02': ('loader_path_policy', 'file_type_observation'),
    'EXEC-06-N04': ('measured_instance_binding', 'loader_instance_observation'),
    'EXEC-06-N05': ('security_claims', 'local_measurement_source'),
    'EXEC-02-P': ('capture_boundary', 'protected_original_store',
                  'derived_call_authority'),
    'EXEC-02-N01': ('original_store_write_boundary', 'capture_provenance'),
    'EXEC-02-N03': ('policy_authority_source', 'digest_admission_boundary'),
    'EXEC-06-P': ('complete_artifact_inventory', 'immutable_loader_binding'),
    'EXEC-06-N03': ('transitive_dependency_inventory', 'dynamic_load_policy'),
    'CST-02-01': ('policy_canonicalization_source', 'approval_record'),
    'CST-02-02': ('artifact_hash_inventory', 'approved_policy_epoch'),
    'CST-02-03': ('retirement_order', 'dispatch_coordinator'),
    'CST-02-04': ('ledger_recovery_authority', 'epoch_transition_record'),
    'CST-02-05': ('policy_mapping_administrator', 'peer_write_boundary'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    for ident, contract in CONTRACTS.items():
        trigger = contract['trigger']
        inp = {'operation': 'sage.host.execution.trace',
               'input': {'case_id': ident, 'trigger': trigger}}
        expected = {'verdict': 'ACCEPT',
                    'output': {'accepted': True, 'observed_trigger': trigger},
                    'effects': {'protected': contract['facts']['new_effects']}}
        yield ident, 'runtime', inp, expected
        if ident in REVIEWS:
            yield review(ident)
    for ident in REVIEWS:
        if ident not in CONTRACTS:
            yield review(ident)


def review(ident):
    refs = list(REVIEWS[ident])
    inp = {'operation': 'sage.host.deployment.review',
           'input': {'case_id': ident, 'required_artifacts': refs}}
    expected = {'verdict': 'ACCEPT',
                'output': {'reviewed': True, 'artifacts': refs},
                'effects': {}}
    return ident, 'deployment_review', inp, expected


def main():
    source = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(source.read_text())
    produced = list(cases())
    selected = {(ident, track) for ident, track, _, _ in produced}
    bindings['bindings'] = [row for row in bindings['bindings']
                            if (row['id'], row['track']) not in selected]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'scope': 'Inspector host observation and deployment review contracts only; no deployed subject or effect observation is claimed',
             'cases': []}
    for ident, track, inp, expected in produced:
        suite['cases'].append({'id': ident, 'track': track,
                               'input': inp, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': track, 'input': inp,
                   'expected': expected}
        relative = f'vectors/0.10.0/current-spec/{ident}-{track}.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': track,
                                     'fixture': relative,
                                     'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec-host-contracts.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    source.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
