"""Evaluate evidence for the frozen design without inheriting old PASSes."""

import argparse
import collections
import json
from pathlib import Path
import re

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import safe_file, same, validate_subject
from design_baseline_catalog import PROFILES, SPEC_REVISION, verify as verify_catalog


HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')


def identity(value, label):
    require(type(value) is dict and set(value) == {
        'repository', 'revision', 'artifact_sha256'}, label + ' identity')
    require(type(value['repository']) is str and value['repository'] and
            type(value['revision']) is str and HEX40.fullmatch(value['revision']) and
            type(value['artifact_sha256']) is str and
            HEX64.fullmatch(value['artifact_sha256']), label + ' fields')


def check_facts(row, facts, actual, subject, artifact_hashes):
    require(type(facts) is dict and
            set(facts) == set(row['required_observation_facts']),
            'observation facts: ' + row['id'])
    track = row['track']
    require(facts['subject_revision'] == subject['revision'], 'subject fact revision')
    if track == 'runtime':
        identity(facts['independent_observer'], 'runtime observer')
        require(facts['independent_observer']['repository'] != subject['repository'] and
                facts['independent_observer']['artifact_sha256'] in artifact_hashes and
                facts['executable_sha256'] == subject['executable_sha256'] and
                facts['input_sha256'] == row['input_sha256'] and
                type(facts['actual_verdict']) is str and
                facts['actual_verdict'] == actual.get('verdict', actual.get('decision')) and
                type(facts['actual_output']) is dict and
                type(facts['effect_counts']) is dict and
                all(type(count) is int and 0 <= count < 2**64
                    for count in facts['effect_counts'].values()),
                'runtime observer facts: ' + row['id'])
        if 'output' in actual:
            require(same(facts['actual_output'], actual['output']) and
                    same(facts['effect_counts'], actual['effects']),
                    'runtime outcome/fact mismatch: ' + row['id'])
    elif track == 'document_review':
        identity(facts['independent_reviewer'], 'document reviewer')
        require(facts['independent_reviewer']['repository'] != subject['repository'] and
                facts['independent_reviewer']['artifact_sha256'] in artifact_hashes and
                facts['source_sha256'] == row['normative_source_sha256'] and
                type(facts['clause_ids']) is list and
                row['rule_id'] in facts['clause_ids'] and
                type(facts['review_findings']) is dict and
                row['id'] in facts['review_findings'] and
                facts['review_findings'][row['id']] in ('MATCH', 'MISMATCH'),
                'document review facts: ' + row['id'])
    else:
        identity(facts['independent_observer'], 'deployment observer')
        require(facts['independent_observer']['repository'] != subject['repository'] and
                facts['independent_observer']['artifact_sha256'] in artifact_hashes and
                type(facts['deployment_identity']) is dict and
                facts['deployment_identity'] and
                type(facts['configuration_sha256']) is str and
                HEX64.fullmatch(facts['configuration_sha256']) and
                type(facts['authority_snapshot']) is dict and
                facts['authority_snapshot'] and
                type(facts['observed_decision']) is str and
                facts['observed_decision'] == actual.get('verdict', actual.get('decision')) and
                type(facts['effect_counts']) is dict and
                all(type(count) is int and 0 <= count < 2**64
                    for count in facts['effect_counts'].values()),
                'deployment observer facts: ' + row['id'])
    if row['contract_kind'] == 'full-case-boundary':
        findings = facts['clause_findings']
        require(type(findings) is dict and
                set(findings) == set(row['required_clause_ids']) and
                type(facts['effect_evidence_sha256']) is str and
                HEX64.fullmatch(facts['effect_evidence_sha256']) and
                facts['effect_evidence_sha256'] in artifact_hashes,
                'complete rule/effect evidence: ' + row['id'])
        for clause in findings.values():
            require(type(clause) is dict and
                    set(clause) == {'status', 'evidence_sha256'} and
                    clause['status'] == 'MATCH' and
                    type(clause['evidence_sha256']) is str and
                    HEX64.fullmatch(clause['evidence_sha256']) and
                    clause['evidence_sha256'] in artifact_hashes,
                    'unproved normative clause: ' + row['id'])
        if track in ('runtime', 'deployment_review') and actual['verdict'] == 'REJECT':
            require(facts['effect_counts'].get('protected') == 0,
                    'rejected case has a protected effect: ' + row['id'])
    if row['contract_kind'] == 'operator-subcondition':
        require(same(facts['operator_state'], row['operator_expected_state']) and
                type(facts['operator_state_evidence_sha256']) is str and
                facts['operator_state_evidence_sha256'] in artifact_hashes,
                'operator transition facts: ' + row['id'])


def status(row, actual, environment=None):
    if actual is None:
        return 'NOT_RUN'
    if actual.get('verdict') == 'UNSUPPORTED':
        require(set(actual) == {'verdict', 'reason'} and
                type(actual['reason']) is str and actual['reason'],
                'unsupported needs a reason')
        return 'UNSUPPORTED'
    if not same(actual, row['expected']):
        return 'FAIL'
    if environment == 'unit-simulation':
        return 'PARTIAL'
    return ('PASS' if row['coverage'] in
            ('required-subcondition', 'complete-boundary-contract') else 'PARTIAL')


def assess(root=ROOT, evidence_root=None):
    manifest, trace, source = verify_catalog(root)
    contracts = {(row['id'], row['track']): row for row in source['contracts']}
    observations = {}
    evidence_manifest = None
    artifact_hashes = set()
    if evidence_root is not None:
        evidence_manifest = load((evidence_root / 'manifest.json').read_bytes())
        require(set(evidence_manifest) == {'schema_version', 'protocol_version',
                'spec_revision', 'subject', 'runner_revision', 'runner_sha256',
                'adapter_sha256', 'observations', 'artifacts', 'profiles'} and
                evidence_manifest['schema_version'] == 1 and
                evidence_manifest['protocol_version'] == '0.10.0' and
                evidence_manifest['spec_revision'] == SPEC_REVISION,
                'observation manifest identity')
        require(type(evidence_manifest['profiles']) is list and
                evidence_manifest['profiles'] and
                len(set(evidence_manifest['profiles'])) == len(evidence_manifest['profiles'])
                and set(evidence_manifest['profiles']) <= set(PROFILES),
                'observation profile selection')
        subject = evidence_manifest['subject']
        validate_subject(subject)
        require(type(evidence_manifest['runner_revision']) is str and
                HEX40.fullmatch(evidence_manifest['runner_revision']) and
                type(evidence_manifest['runner_sha256']) is str and
                HEX64.fullmatch(evidence_manifest['runner_sha256']) and
                type(evidence_manifest['adapter_sha256']) is str and
                HEX64.fullmatch(evidence_manifest['adapter_sha256']) and
                type(evidence_manifest['observations']) is list and
                type(evidence_manifest['artifacts']) is list,
                'runner or observation inventory')
        for item in evidence_manifest['artifacts']:
            require(type(item) is dict and set(item) == {'path', 'sha256'},
                    'evidence artifact reference')
            raw = safe_file(evidence_root, item['path'])
            require(sha(raw) == item['sha256'] and
                    item['sha256'] not in artifact_hashes,
                    'evidence artifact hash or duplicate')
            artifact_hashes.add(item['sha256'])
        for item in evidence_manifest['observations']:
            require(type(item) is dict and set(item) == {'id', 'track', 'path', 'sha256'},
                    'observation reference')
            key = item['id'], item['track']
            require(key in contracts and key not in observations, 'unknown/duplicate observation')
            require(contracts[key]['profile'] in evidence_manifest['profiles'],
                    'observation outside selected profile')
            raw = safe_file(evidence_root, item['path'])
            require(sha(raw) == item['sha256'], 'observation file hash: ' + item['id'])
            observation = load(raw)
            require(set(observation) == {'schema_version', 'spec_revision', 'id',
                    'track', 'source_fixture_sha256', 'subject', 'actual',
                    'facts', 'environment'} and observation['schema_version'] == 1 and
                    observation['spec_revision'] == SPEC_REVISION and
                    (observation['id'], observation['track']) == key and
                    observation['source_fixture_sha256'] ==
                    contracts[key]['source_fixture_sha256'] and
                    same(observation['subject'], subject) and
                    type(observation['environment']) is str and
                    observation['environment'], 'observation identity')
            require(observation['environment'] in {
                'runtime': ('local-process', 'deployed', 'unit-simulation'),
                'document_review': ('document-review', 'unit-simulation'),
                'deployment_review': ('deployed', 'unit-simulation'),
            }[item['track']], 'observation environment/track mismatch')
            actual = observation['actual']
            require(type(actual) is dict and
                    (set(actual) == set(contracts[key]['expected']) or
                     set(actual) == {'verdict', 'reason'}), 'typed actual outcome')
            if actual.get('verdict') != 'UNSUPPORTED':
                check_facts(contracts[key], observation['facts'], actual, subject,
                            artifact_hashes)
            observations[key] = observation

    tracks = []
    for row in source['contracts']:
        observation = observations.get((row['id'], row['track']))
        actual = observation['actual'] if observation is not None else None
        environment = observation['environment'] if observation is not None else None
        tracks.append({'id': row['id'], 'parent_case': row['parent_case'],
                       'track': row['track'], 'expected': row['expected'],
                       'actual': actual, 'source_fixture_sha256':
                       row['source_fixture_sha256'],
                       'status': status(row, actual, environment)})
    track_status = {(row['id'], row['track']): row['status'] for row in tracks}
    per_parent = collections.defaultdict(list)
    required = collections.defaultdict(list)
    for row in tracks:
        per_parent[row['parent_case']].append(row['status'])
        contract = contracts[row['id'], row['track']]
        if contract['coverage'] in ('required-subcondition',
                                    'complete-boundary-contract'):
            required[row['parent_case']].append(row['status'])
    def parent_status(parent):
        all_states = per_parent[parent]
        required_states = required[parent]
        require(required_states, 'parent has no complete inspection contract: ' + parent)
        if 'FAIL' in all_states:
            return 'FAIL'
        if 'UNSUPPORTED' in all_states:
            return 'UNSUPPORTED'
        if all(value == 'PASS' for value in required_states):
            for key, contract in contracts.items():
                if (contract['parent_case'] == parent and
                        contract['contract_kind'] == 'full-case-boundary' and
                        contract['supporting_required_for_pass'] and
                        track_status[(contract['supporting_case_id'],
                                      contract['track'])] not in ('PASS', 'PARTIAL')):
                    return 'PARTIAL'
            return 'PASS'
        if any(value in ('PASS', 'PARTIAL') for value in all_states):
            return 'PARTIAL'
        return 'NOT_RUN'
    cases = [{'id': item['id'], 'rule_id': item['rule_id'],
              'status': parent_status(item['id'])}
             for item in trace['cases']]
    counts = {state: sum(item['status'] == state for item in cases)
              for state in ('PASS', 'FAIL', 'PARTIAL', 'UNSUPPORTED', 'NOT_RUN')}
    return {'schema_version': 1, 'kind': 'design-baseline-inspection-evidence',
            'protocol_version': '0.10.0', 'spec_revision': SPEC_REVISION,
            'profiles': evidence_manifest['profiles'] if evidence_manifest else list(PROFILES),
            'design_baseline_sha256': manifest['design_baseline_sha256'],
            'subject': evidence_manifest['subject'] if evidence_manifest else None,
            'runner_revision': evidence_manifest['runner_revision'] if evidence_manifest else None,
            'runner_sha256': evidence_manifest['runner_sha256'] if evidence_manifest else None,
            'adapter_sha256': evidence_manifest['adapter_sha256'] if evidence_manifest else None,
            'status': 'EVIDENCE_CHECKED' if evidence_root else 'CONTRACT_INVENTORY_ONLY',
            'conformance': 'NOT_ESTABLISHED', 'counts': counts,
            'case_count': 489, 'required_subcondition_count': 56,
            'tracks': tracks, 'cases': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assess(evidence_root=args.evidence)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        parser.exit(1, 'Design baseline evidence FAIL: ' + str(error) + '\n')
    print('Design baseline evidence: ' + str(result['counts']) +
          '; conformance NOT_ESTABLISHED')


if __name__ == '__main__':
    main()
