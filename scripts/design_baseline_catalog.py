"""Bind every 0.10.0 design case to the frozen specification revision.

This is an inspection-contract inventory, never implementation evidence.
Historical fixtures remain provenance for independent expectations and cannot
be presented as observations at the new revision.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess

from current_spec_catalog import ROOT, catalog, index, load, rendered_snapshot, require, sha
from latest_spec_catalog import LATEST_BASE


BASE = 'verification/0.10.0/design-baseline'
SPEC_REVISION = '85fee1830b2bc0d2420557df40796ae83073de12'
SOURCE_REVISION = '1820ab5eafb843e1c13f4c46c34aeeb28d934ac9'
BASELINE_FILE = 'verification/first-stage-baseline.json'
OPERATOR_FILE = 'vectors/0.10.0/registry-operator/subconditions.json'
MEDIA_FILE = 'vectors/0.10.0/reconciled-spec/reg08-media.json'
EXTRA_CLAUSE_SPANS = {
    'OVERVIEW-01': [('spec/00-overview.md', 36, 40)],
    'OVERVIEW-02': [('charter.md', 42, 45)],
    'MSG-04': [('spec/03-rfc9421.md', 140, 146)],
    'ID-01': [('spec/06-did-sage.md', 123, 130)],
    'TRANSPORT-01': [('spec/08-transport.md', 145, 152)],
    'REG-03': [('spec/09-registry.md', 235, 319)],
    'REG-08': [('spec/09-registry.md', 235, 319)],
    'MSET-01': [('profiles/non-http-mcp-security.md', 17, 34)],
    'MSET-08': [('profiles/non-http-mcp-security.md', 286, 306)],
    'MOWN-02': [('profiles/non-http-mcp-security.md', 388, 543)],
}

OBSERVATION_FACTS = {
    'runtime': ['subject_revision', 'executable_sha256', 'input_sha256',
                'actual_verdict', 'actual_output', 'effect_counts',
                'independent_observer'],
    'document_review': ['subject_revision', 'source_sha256', 'clause_ids',
                        'review_findings', 'independent_reviewer'],
    'deployment_review': ['deployment_identity', 'subject_revision',
                          'configuration_sha256', 'authority_snapshot',
                          'independent_observer', 'observed_decision',
                          'effect_counts'],
}
PROFILES = ('base', 'sage-execution-guard',
            'sage-mcp-non-http/0.10.0/mcp-2025-06-18')
OPERATOR_EXPECTED_STATE = {
    'ACCEPT_ONE_VERSION_AND_GRANT': {
        'version_delta': 1, 'grant_added': True, 'history_delta': 1,
        'unrelated_state_unchanged': True},
    'ACCEPT_ONE_NAMED_TRANSITION': {
        'version_delta': 1, 'named_transition_committed': True,
        'history_delta': 1, 'current_grant_checked': True},
    'ACCEPT_ONE_VERSION_AND_REMOVE_ONLY_TARGET': {
        'version_delta': 1, 'target_grant_removed': True,
        'other_grants_unchanged': True, 'history_delta': 1},
    'ACCEPT_ONE_VERSION_AND_RETIRE_INELIGIBLE': {
        'version_delta': 1, 'ineligible_grants_removed': True,
        'history_delta': 1},
    'ACCEPT_MANAGEMENT_ONLY_NO_MESSAGE_AUTHORITY': {
        'version_delta': 1, 'management_committed': True,
        'protected_message_authorized': False},
    'REJECT_UNCHANGED': {
        'version_delta': 0, 'grant_state_unchanged': True,
        'history_delta': 0, 'protected_effects': 0},
    'ONE_COMMIT_OTHER_STALE_BY_LINEARIZATION': {
        'committed_commands': 1, 'stale_commands': 1,
        'version_delta': 1, 'mixed_state': False},
    'QUARANTINE_NO_SUCCESS_CLAIM': {
        'quarantined': True, 'success_claims': 0,
        'additional_writes': 0},
    'RECOVER_EXACT_VERSION_AND_GRANTS': {
        'version_matches': True, 'grants_match': True,
        'history_matches': True},
    'COMPLETE_OLD_OR_NEW_RECORD': {
        'complete_old_or_new': True, 'mixed_state': False},
    'NO_CONFORMANCE_OR_SUCCESS_CLAIM': {
        'conformance_claims': 0, 'success_claims': 0},
}


def profile_for(source):
    if source == 'profiles/agent-mcp-security.md':
        return PROFILES[1]
    if source == 'profiles/non-http-mcp-security.md':
        return PROFILES[2]
    return PROFILES[0]


def owner_for(rule_id):
    if rule_id.startswith(('EXEC-', 'CST-', 'MSET-', 'MOWN-')):
        return 'trusted Agent/MCP host or binding owner'
    if rule_id.startswith('REG-'):
        return 'authoritative Registry Source and resolver'
    if rule_id.startswith('RESOLVE-'):
        return 'trusted DID resolver and HTTP adapter'
    return 'Go/Rust core or conforming protocol implementation'


def fixture_contract(root, trace, row):
    cases = index(trace['cases'], 'case')
    children = index(trace['mandatory_subscenarios'], 'mandatory child')
    source = root / row['fixture']
    require(sha(source.read_bytes()) == row['fixture_sha256'],
            'historical fixture drift: ' + row['id'])
    fixture = load(source.read_bytes())
    ident = row['id']
    if ident in cases:
        case = cases[ident]
        parent = ident
        expected_clause = case['expected']
        preconditions = case['preconditions']
        rule_id = case['rule_id']
    else:
        child = children[ident]
        parent = child['parent_case']
        rule_id = cases[parent]['rule_id']
        expected_clause = child['expected']
        preconditions = child['scenario']
    require(fixture['id'] == ident and fixture['track'] == row['track']
            and fixture['expected']['verdict'] in ('ACCEPT', 'REJECT'),
            'fixture identity or expectation: ' + ident)
    return {
        'id': ident, 'parent_case': parent, 'rule_id': rule_id,
        'track': row['track'], 'contract_kind': 'prior-independent-fixture',
        'source_fixture': row['fixture'],
        'source_fixture_sha256': row['fixture_sha256'],
        'source_fixture_spec_revision': fixture['spec_revision'],
        'source_operation': fixture['input'].get('operation', 'unspecified'),
        'input_sha256': sha(json.dumps(fixture['input'], sort_keys=True,
                                       separators=(',', ':'),
                                       allow_nan=False).encode()),
        'coverage': row['coverage'],
        'preconditions': preconditions,
        'expected_clause': expected_clause,
        'expected': fixture['expected'],
        'required_observation_facts': OBSERVATION_FACTS[row['track']],
    }


def added_contracts(root, trace):
    cases = index(trace['cases'], 'case')
    result = []
    for source, kind in ((OPERATOR_FILE, 'operator-subcondition'),
                         (MEDIA_FILE, 'web-media-subcondition')):
        raw = (root / source).read_bytes()
        suite = load(raw)
        require(suite['protocol_version'] == '0.10.0', 'subcondition version')
        expected_count = 17 if kind == 'operator-subcondition' else 13
        require(len(suite['cases']) == expected_count,
                'subcondition count: ' + kind)
        for item in suite['cases']:
            parent = item['parent_case_id']
            require(parent in cases and cases[parent]['rule_id'] in ('REG-03', 'REG-08'),
                    'subcondition parent: ' + item['id'])
            tracks = ['runtime']
            if item['id'] in ('storage-authority-loss', 'public-read-atomicity'):
                tracks.append('deployment_review')
            if kind == 'operator-subcondition':
                preconditions = item['precondition']
                require(item['expected'] in OPERATOR_EXPECTED_STATE,
                        'unknown operator expected state: ' + item['id'])
            else:
                preconditions = 'Apply the exact bounded HTTP media fields in the source vector.'
                from reconciled_spec_reg08_media import decision
                require(decision(item) == item['expected'],
                        'independent media decision: ' + item['id'])
            for track in tracks:
                row = {
                    'id': kind + '/' + item['id'],
                    'parent_case': parent, 'rule_id': cases[parent]['rule_id'],
                    'track': track, 'contract_kind': kind,
                    'source_fixture': source, 'source_fixture_sha256': sha(raw),
                    'source_fixture_spec_revision': SPEC_REVISION,
                    'input_sha256': sha(json.dumps(item, sort_keys=True,
                                                   separators=(',', ':'),
                                                   allow_nan=False).encode()),
                    'coverage': 'required-subcondition',
                    'preconditions': preconditions,
                    'expected_clause': item['expected'],
                    'expected': {'decision': item['expected']},
                    'required_observation_facts': OBSERVATION_FACTS[track],
                }
                if kind == 'operator-subcondition':
                    row['operator_expected_state'] = OPERATOR_EXPECTED_STATE[
                        item['expected']]
                    row['required_observation_facts'] = (OBSERVATION_FACTS[track] +
                        ['operator_state', 'operator_state_evidence_sha256'])
                result.append(row)
    return result


def rule_clauses(spec_root, trace):
    """Pin every nonblank line in each normative rule's owned source span."""
    rules = trace['rules']
    result = {}
    for rule in rules:
        source = rule['source']
        lines = (spec_root / source).read_text().splitlines()
        start = rule['line']
        following = [item['line'] for item in rules
                     if item['source'] == source and item['line'] > start]
        heading = [number for number in range(start + 1, len(lines) + 1)
                   if lines[number - 1].startswith('## ')]
        end = min(following + heading + [len(lines) + 1])
        require(rule['id'] in lines[start - 1] and end > start,
                'rule clause anchor: ' + rule['id'])
        clauses = [{'id': rule['id'] + ':' + source + ':L' + str(number),
                    'source': source, 'line': number,
                    'sha256': sha(lines[number - 1].encode())}
                   for number in range(start, end)
                   if lines[number - 1].strip()]
        for extra_source, extra_start, extra_end in EXTRA_CLAUSE_SPANS.get(rule['id'], []):
            extra_lines = (spec_root / extra_source).read_text().splitlines()
            require(1 <= extra_start < extra_end <= len(extra_lines) + 1,
                    'extra clause range: ' + rule['id'])
            clauses.extend({'id': rule['id'] + ':' + extra_source + ':L' + str(number),
                            'source': extra_source, 'line': number,
                            'sha256': sha(extra_lines[number - 1].encode())}
                           for number in range(extra_start, extra_end)
                           if extra_lines[number - 1].strip())
        require(clauses and clauses[0]['line'] == start,
                'empty rule clause span: ' + rule['id'])
        require(len({item['id'] for item in clauses}) == len(clauses),
                'duplicate clause span: ' + rule['id'])
        result[rule['id']] = {'source': source, 'clauses': clauses}
    owned = {}
    for group in result.values():
        for clause in group['clauses']:
            owned.setdefault(clause['source'], set()).add(clause['line'])
    for source in [*(f'spec/{number:02d}-{name}.md' for number, name in enumerate((
            'overview', 'crypto', 'jcs', 'rfc9421', 'hpke', 'session',
            'did-sage', 'a2a', 'transport', 'registry', 'resolution', 'registries'))),
            'profiles/agent-mcp-security.md',
            'profiles/non-http-mcp-security.md', 'charter.md']:
        for number, line in enumerate((spec_root / source).read_text().splitlines(), 1):
            if re.search(r'\b(?:MUST|SHOULD|MAY|REQUIRED|RECOMMENDED)\b', line):
                require(number in owned.get(source, set()),
                        'unowned normative line: ' + source + ':' + str(number))
    return result


def full_case_contracts(trace, supporting, clauses):
    cases = index(trace['cases'], 'case')
    children = index(trace['mandatory_subscenarios'], 'mandatory child')
    result = []
    seen = set()
    for source in supporting:
        parent = source['parent_case']
        if source['contract_kind'] != 'prior-independent-fixture':
            continue
        child = source['id'] in children
        if source['id'] != parent and not child:
            continue
        key = source['id'], source['track']
        require(key not in seen, 'duplicate supporting parent track')
        seen.add(key)
        case = cases[parent]
        clause_rows = clauses[case['rule_id']]['clauses']
        scenario = {'scenario': children[source['id']]['scenario'] if child else case['input'],
                    'preconditions': case['preconditions'],
                    'rule_clauses': [item['id'] for item in clause_rows]}
        expected = {'verdict': source['expected']['verdict'],
                    'output': {'rule_conformance': 'MATCH',
                               'case_expectation': 'MATCH'},
                    'effects': ({'protected': 0}
                                if source['track'] in ('runtime', 'deployment_review')
                                and source['expected']['verdict'] == 'REJECT' else {})}
        row = dict(source)
        row.update({
            'id': ('full-child/' if child else 'full-case/') + source['id'],
            'contract_kind': 'full-case-boundary',
            'coverage': 'complete-boundary-contract',
            'supporting_case_id': source['id'],
            'supporting_required_for_pass':
                source['source_operation'] != 'sage.spec.host_case',
            'input_sha256': sha(json.dumps(scenario, sort_keys=True,
                                           separators=(',', ':'),
                                           allow_nan=False).encode()),
            'expected': expected,
            'required_clause_ids': [item['id'] for item in clause_rows],
            'required_observation_facts':
                source['required_observation_facts'] +
                ['clause_findings', 'effect_evidence_sha256'],
        })
        result.append(row)
    require(len(seen) == 562 and set(cases) | set(children) ==
            {ident for ident, _ in seen}, 'full-case track coverage')
    return result


def render(root=ROOT, spec_root=None):
    require(spec_root is not None, 'spec root required for rendering')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=spec_root,
                                       text=True, timeout=10).strip()
    require(revision == SPEC_REVISION, 'frozen specification revision')
    spec_baseline_raw = (spec_root / BASELINE_FILE).read_bytes()
    baseline = load(spec_baseline_raw)
    require(baseline['normative_source_revision'] == SOURCE_REVISION and
            baseline['counts'] == {
                'requirements': 45, 'rule_groups': 91, 'parent_cases': 489,
                'traceability_children': 26, 'operator_subconditions': 17,
                'standards_sources': 22}, 'spec design baseline identity')
    for path, expected in baseline['source_sha256'].items():
        require(sha((spec_root / path).read_bytes()) == expected,
                'spec baseline source drift: ' + path)
    require(sha((root / OPERATOR_FILE).read_bytes()) == baseline['source_sha256'][
                'verification/vectors/registry-operator-0.10.0.json'] and
            sha((root / MEDIA_FILE).read_bytes()) == baseline['source_sha256'][
                'verification/vectors/web-registry-media-0.10.0.json'],
            'Inspector subconditions differ from frozen spec')
    snapshot = rendered_snapshot(spec_root)
    manifest = load(snapshot['manifest.json'])
    manifest['design_baseline_sha256'] = sha(spec_baseline_raw)
    manifest['normative_source_revision'] = SOURCE_REVISION
    manifest['inspection_contract_status'] = 'NOT_IMPLEMENTATION_EVIDENCE'
    trace = load(snapshot['traceability.json'])
    require(len(trace['cases']) == 489 and len(trace['mandatory_subscenarios']) == 26,
            'frozen traceability inventory')
    old = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    latest = load((root / LATEST_BASE / 'bindings.json').read_bytes())
    contracts = [fixture_contract(root, trace, row)
                 for row in old['bindings'] + latest['bindings']]
    contracts.extend(added_contracts(root, trace))
    clauses = rule_clauses(spec_root, trace)
    contracts.extend(full_case_contracts(trace, contracts, clauses))
    rules = index(trace['rules'], 'rule')
    for row in contracts:
        source = rules[row['rule_id']]['source']
        row['normative_source'] = source
        row['normative_source_sha256'] = manifest['source_sha256'][source]
        row['profile'] = profile_for(source)
        row['subject_owner'] = owner_for(row['rule_id'])
        row['trusted_observer'] = 'independent Inspector runner or reviewer'
    ids = {row['id'] for row in contracts}
    parents = {case['id'] for case in trace['cases']}
    children = {child['id'] for child in trace['mandatory_subscenarios']}
    require(parents | children <= ids, 'case or child missing a contract')
    require(len(contracts) == 1156 and len(ids - parents - children) == 545,
            'inspection contract count')
    contract = {'schema_version': 1, 'kind': 'sage-design-inspection-contracts',
                'protocol_version': '0.10.0', 'spec_revision': SPEC_REVISION,
                'status': 'CONTRACT_INVENTORY_ONLY',
                'contracts': contracts}
    snapshot['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    snapshot['contracts.json'] = (json.dumps(contract, indent=2,
                                             ensure_ascii=False) + '\n').encode()
    snapshot['rule-clauses.json'] = (json.dumps({
        'schema_version': 1, 'spec_revision': SPEC_REVISION,
        'rules': clauses}, indent=2) + '\n').encode()
    manifest['contracts_sha256'] = sha(snapshot['contracts.json'])
    manifest['rule_clauses_sha256'] = sha(snapshot['rule-clauses.json'])
    manifest['profiles'] = list(PROFILES)
    snapshot['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    return snapshot


def verify(root=ROOT, spec_root=None):
    base = root / BASE
    manifest, trace, mapped = catalog(root, spec_root, base_relative=BASE)
    require(manifest['spec_revision'] == SPEC_REVISION and
            manifest['normative_source_revision'] == SOURCE_REVISION and
            manifest['profiles'] == list(PROFILES) and
            len(mapped) == 489, 'frozen catalog identity')
    contract = load((base / 'contracts.json').read_bytes())
    require(contract['spec_revision'] == SPEC_REVISION and
            len(contract['contracts']) == 1156 and
            sha((base / 'contracts.json').read_bytes()) == manifest['contracts_sha256'],
            'contract inventory identity')
    clauses = load((base / 'rule-clauses.json').read_bytes())
    require(clauses['spec_revision'] == SPEC_REVISION and
            len(clauses['rules']) == 91 and
            sha((base / 'rule-clauses.json').read_bytes()) ==
            manifest['rule_clauses_sha256'], 'normative clause inventory')
    keys = {(row['id'], row['track']) for row in contract['contracts']}
    require(len(keys) == len(contract['contracts']), 'duplicate contract track')
    require(all(row['required_observation_facts'] ==
                OBSERVATION_FACTS[row['track']] +
                (['clause_findings', 'effect_evidence_sha256']
                 if row['contract_kind'] == 'full-case-boundary' else
                 ['operator_state', 'operator_state_evidence_sha256']
                 if row['contract_kind'] == 'operator-subcondition' else [])
                and row['expected_clause'] and row['preconditions']
                and row['profile'] == profile_for(row['normative_source'])
                and row['subject_owner'] == owner_for(row['rule_id'])
                and row['trusted_observer'] ==
                    'independent Inspector runner or reviewer'
                and row['normative_source_sha256'] ==
                    manifest['source_sha256'][row['normative_source']]
                and sha((root / row['source_fixture']).read_bytes()) ==
                    row['source_fixture_sha256']
                for row in contract['contracts']), 'contract fact/source drift')
    if spec_root is not None:
        expected = render(root, spec_root)
        require(all((base / name).read_bytes() == raw
                    for name, raw in expected.items()), 'rendered contract drift')
    return manifest, trace, contract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        if args.write:
            for name, raw in render(spec_root=args.spec_root).items():
                target = ROOT / BASE / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
        manifest, trace, contracts = verify(spec_root=args.spec_root)
        report = {'schema_version': 1, 'kind': 'design-baseline-inspection-report',
                  'spec_revision': manifest['spec_revision'],
                  'protocol_version': '0.10.0',
                  'profiles': list(PROFILES),
                  'subject': None, 'status': 'CONTRACT_INVENTORY_ONLY',
                  'conformance': 'NOT_ESTABLISHED',
                  'counts': {'requirements': 45, 'rules': 91,
                             'parent_cases': len(trace['cases']),
                             'traceability_children': len(trace['mandatory_subscenarios']),
                             'additional_required_subconditions': 30,
                             'case_not_run': len(trace['cases']),
                             'child_not_run': 56,
                             'contracts': len(contracts['contracts']),
                             'full_case_tracks': 562},
                  'cases': [{'id': item['id'],
                             'profile': profile_for(index(trace['rules'], 'rule')[
                                 item['rule_id']]['source']),
                             'status': 'NOT_RUN'}
                            for item in trace['cases']]}
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, OSError, KeyError, TypeError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        parser.exit(1, 'Design baseline catalog FAIL: ' + str(error) + '\n')
    print('Design baseline catalog PASS: 489 cases, 56 required subconditions; all NOT_RUN')


if __name__ == '__main__':
    main()
