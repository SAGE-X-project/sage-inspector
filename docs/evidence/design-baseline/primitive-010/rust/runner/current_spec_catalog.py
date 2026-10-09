"""Pin and validate the complete, current 0.10.0 specification inventory.

This catalog is a test plan. It never promotes historical observations to
current conformance evidence.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'verification/0.10.0/current-spec'
HISTORICAL = ROOT / 'verification/0.10.0/case-map.json'
TRACKS = {'runtime', 'document_review', 'deployment_review'}
MODES = {
    'independent_fixture_and_live_adapter': ('runtime',),
    'unit_and_bounded_local_runtime': ('runtime',),
    'unit_state_machine': ('runtime',),
    'owner_unit_plus_distinct_session_runtime': ('runtime',),
    'planned_boundary_or_state_test': ('runtime',),
    'deployment_or_document_review': ('document_review', 'deployment_review'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(raw):
    def unique_members(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON member: ' + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique_members,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError('non-finite JSON number: ' + value)))


def index(items, name):
    require(type(items) is list, name + ' is not a list')
    result = {}
    for item in items:
        require(type(item) is dict and type(item.get('id')) is str and item['id'],
                'invalid ' + name + ' ID')
        require(item['id'] not in result, 'duplicate ' + name + ' ID: ' + item['id'])
        result[item['id']] = item
    return result


def source_files(trace):
    files = {'verification/traceability.json',
             'profiles/non-http-mcp-tool.json',
             'verification/standards-clause-audit.md'}
    files.update(rule['source'] for rule in trace['rules'])
    for path in files:
        require(type(path) is str and path and not Path(path).is_absolute()
                and '..' not in Path(path).parts and '\\' not in path,
                'unsafe source path')
    return sorted(files)


def additional_case(case):
    mode = case['mode']
    require(mode in MODES, 'unknown case mode: ' + mode)
    tracks = list(MODES[mode])
    if case['id'].startswith('mset-08-'):
        tracks.append('document_review')
    return {
        'id': case['id'],
        'rule_id': case['rule_id'],
        'source_mode': mode,
        'verification_tracks': tracks,
        'classification_reason': ('Review normative claims and deployment evidence.'
                                  if mode == 'deployment_or_document_review' else
                                  'Exercise the stated scenario against an independently observed subject.'),
        'scenario': case['input'],
        'partial_vector_ids': [],
        'coverage': 'no_case_vector',
        'evidence_status': 'NOT_RUN',
    }


def rendered_snapshot(spec_root):
    raw = (spec_root / 'verification/traceability.json').read_bytes()
    trace = load(raw)
    original = load(HISTORICAL.read_bytes())
    historical = index(original['cases'], 'historical case')
    cases = index(trace['cases'], 'spec case')
    require(set(historical) <= set(cases), 'historical case removed from current spec')
    additions = [additional_case(case) for case in trace['cases']
                 if case['id'] not in historical]
    manifest = {
        'schema_version': 1,
        'protocol_version': trace['protocol_version'],
        'spec_revision': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=spec_root, text=True, timeout=10).strip(),
        'source_sha256': {path: sha((spec_root / path).read_bytes())
                          for path in source_files(trace)},
        'historical_case_map_sha256': sha(HISTORICAL.read_bytes()),
        'counts': {'requirements': len(trace['requirements']),
                   'rules': len(trace['rules']), 'cases': len(trace['cases']),
                   'mandatory_subscenarios': len(trace['mandatory_subscenarios']),
                   'historical_cases': len(historical), 'additional_cases': len(additions)},
        'status': 'INVENTORY_ONLY',
    }
    return {
        'manifest.json': (json.dumps(manifest, indent=2, ensure_ascii=False) + '\n').encode(),
        'traceability.json': raw,
        'additional-case-map.json': (json.dumps(additions, indent=2, ensure_ascii=False) + '\n').encode(),
    }


def catalog(root=ROOT, spec_root=None, base_relative='verification/0.10.0/current-spec'):
    base = root / base_relative
    manifest = load((base / 'manifest.json').read_bytes())
    trace_raw = (base / 'traceability.json').read_bytes()
    trace = load(trace_raw)
    old_raw = (root / 'verification/0.10.0/case-map.json').read_bytes()
    historical = load(old_raw)
    added = load((base / 'additional-case-map.json').read_bytes())
    require(manifest['schema_version'] == 1 and manifest['protocol_version'] == '0.10.0'
            and manifest['status'] == 'INVENTORY_ONLY', 'manifest identity')
    require(type(manifest['spec_revision']) is str and len(manifest['spec_revision']) == 40,
            'spec revision identity')
    require(sha(trace_raw) == manifest['source_sha256']['verification/traceability.json'],
            'traceability hash mismatch')
    require(sha(old_raw) == manifest['historical_case_map_sha256'],
            'historical case map changed')
    require(trace['protocol_version'] == manifest['protocol_version'], 'protocol version drift')
    requirements = index(trace['requirements'], 'requirement')
    rules = index(trace['rules'], 'rule')
    cases = index(trace['cases'], 'case')
    children = index(trace['mandatory_subscenarios'], 'mandatory subscenario')
    old = index(historical['cases'], 'historical case')
    new = index(added, 'additional case')
    require(not set(old) & set(new), 'historical case overwritten')
    mapped = {**old, **new}
    require(set(mapped) == set(cases), 'current spec has unmapped or obsolete cases')
    require(manifest['counts'] == {
        'requirements': len(requirements), 'rules': len(rules), 'cases': len(cases),
        'mandatory_subscenarios': len(children), 'historical_cases': len(old),
        'additional_cases': len(new)}, 'manifest count drift')
    require(set(manifest['source_sha256']) == set(source_files(trace)),
            'normative source set drift')
    for rid, rule in rules.items():
        require(set(rule['requirements']) <= set(requirements), 'unknown requirement: ' + rid)
        owned = {cid for cid, case in cases.items() if case['rule_id'] == rid}
        if rule.get('mapping_kind') == 'mandatory_child_assertions':
            require(not owned and set(rule['case_ids']) <= set(cases)
                    and all(any(child['parent_case'] == cid for child in children.values())
                            for cid in rule['case_ids']),
                    'mandatory child mapping: ' + rid)
        else:
            require(set(rule['case_ids']) == owned, 'rule case coverage: ' + rid)
        require(all(rid in requirements[qid]['rule_ids'] for qid in rule['requirements']),
                'reverse requirement mapping: ' + rid)
    for qid, requirement in requirements.items():
        require(set(requirement['rule_ids']) == {rid for rid, rule in rules.items()
                                                if qid in rule['requirements']},
                'requirement rule coverage: ' + qid)
    for cid, case in cases.items():
        row = mapped[cid]
        require(case['rule_id'] in rules and row['rule_id'] == case['rule_id']
                and row['source_mode'] == case['mode'] and row['scenario'] == case['input'],
                'case mapping drift: ' + cid)
        require(type(row['verification_tracks']) is list and row['verification_tracks']
                and set(row['verification_tracks']) <= TRACKS,
                'invalid verification tracks: ' + cid)
        require(row['evidence_status'] == 'NOT_RUN' and
                case['evidence_status'] == 'planned_not_executed',
                'planned case falsely promoted: ' + cid)
        if cid in new:
            require(row == additional_case(case), 'additional case classification drift: ' + cid)
    for child_id, child in children.items():
        require(child['parent_case'] in cases and child['status'] == 'NOT_RUN'
                and child['planned_method'] and child['expected'],
                'invalid mandatory subscenario: ' + child_id)
    if spec_root is not None:
        require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=spec_root,
                                        text=True, timeout=10).strip() == manifest['spec_revision'],
                'source spec revision drift')
        for path, expected in manifest['source_sha256'].items():
            require(sha((spec_root / path).read_bytes()) == expected,
                    'source spec file drift: ' + path)
    return manifest, trace, mapped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--report', type=Path,
                        help='Write a complete, non-conformance inventory report')
    args = parser.parse_args()
    try:
        manifest, trace, mapped = catalog(spec_root=args.spec_root)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        parser.exit(1, 'Current spec catalog FAIL: ' + str(error) + '\n')
    if args.report is not None:
        rules = index(trace['rules'], 'rule')
        report = {
            'schema_version': 1,
            'kind': 'current-spec-inventory',
            'protocol_version': manifest['protocol_version'],
            'spec_revision': manifest['spec_revision'],
            'status': 'INCOMPLETE',
            'conformance': 'NOT_ESTABLISHED',
            'counts': {'requirements': len(trace['requirements']),
                       'rules': len(rules), 'cases': len(mapped),
                       'mandatory_subscenarios': len(trace['mandatory_subscenarios']),
                       'case_not_run': len(mapped),
                       'mandatory_subscenario_not_run': len(trace['mandatory_subscenarios'])},
            'cases': [{
                'id': case['id'],
                'rule_id': case['rule_id'],
                'source': rules[case['rule_id']]['source'],
                'verification_tracks': mapped[case['id']]['verification_tracks'],
                'status': 'NOT_RUN',
                'mandatory_subscenarios': [child['id'] for child in trace['mandatory_subscenarios']
                                           if child['parent_case'] == case['id']],
            } for case in trace['cases']],
        }
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print('Current spec inventory: ' + str(len(trace['requirements'])) +
          ' requirements, ' + str(len(trace['rules'])) + ' rules, ' +
          str(len(mapped)) + ' cases, ' +
          str(len(trace['mandatory_subscenarios'])) +
          ' mandatory subscenarios; execution not established; spec ' +
          manifest['spec_revision'])


if __name__ == '__main__':
    main()
