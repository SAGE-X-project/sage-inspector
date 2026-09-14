"""Validate an explicit evidence inventory and join observations to the frozen plan.

Exit 0 means evidence validation succeeded, never subject certification. Use
--require-conformance to fail unless complete protocol conformance is established.
"""
import argparse
import collections
import hashlib
import json
import re
from pathlib import Path

from check_spec_baseline import check as check_baseline
from inspect_guard import validate_report, validate_scenario
from inspect_http import CONDITIONAL

ROOT = Path(__file__).resolve().parents[1]
STATUSES = ('PASS', 'FAIL', 'UNSUPPORTED', 'NOT_RUN')
SUITES = ('foundation', 'jcs-signatures', 'http-signatures', 'http-boundaries',
          'http-envelope-primitives', 'hpke-primitives', 'hpke-schedule',
          'session-records', 'registry-records', 'guard-records')
GROUPS = {'hpke': 6, 'session': 37, 'registry': 17, 'guard': 37}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(items, key='id'):
    result = {item[key]: item for item in items}
    require(len(result) == len(items), 'duplicate ' + key)
    return result


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('nonfinite JSON number: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def same(left, right):
    # Python's True == 1 must not manufacture a matching observation.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def counts(statuses):
    result = dict.fromkeys(STATUSES, 0)
    for status in statuses:
        require(status in result, 'invalid observation status')
        result[status] += 1
    return result


def subject_identity(report, core):
    subject = report['subject']
    require(subject['kind'] == 'external' and subject['name'] in core['subject_names'] and
            subject['revision'] == core['revision'], 'wrong subject identity')
    require(re.fullmatch('[0-9a-f]{64}', subject['executable_sha256']) is not None,
            'missing executable identity')
    for key in (('environment', 'created', 'runner_version') if report['schema_version'] == 1 else ('environment', 'created')):
        require(isinstance(report.get(key), str) and report[key], 'missing execution ' + key)


def primitive(raw, report, core):
    require(type(report['schema_version']) is int, 'invalid report schema type')
    require(all(type(n) is int and n >= 0 for n in report['counts'].values()), 'invalid counts')
    validate_report(raw, report)
    suite = decode(raw)
    subject_identity(report, core)
    require(report['profile'] == suite['profile'] and same(report['sources'], suite['sources']),
            'report profile or source mismatch')
    fixtures = unique(suite['cases'])
    for result in report['results']:
        case = fixtures[result['case_id']]
        require(same(result['expected'], case['expected']), 'changed expectation')
        require(result['source_ids'] == case['source_ids'] and result['derivation'] == case['derivation'],
                'changed case provenance')
        actual = result.get('actual')
        if actual is not None:
            require(type(actual['schema_version']) is int and actual['schema_version'] == 1 and
                    actual['case_id'] == case['id'], 'observation identity mismatch')
            require(actual['verdict'] in ('ACCEPT', 'REJECT', 'UNSUPPORTED') and
                    isinstance(actual['output'], dict), 'invalid observation')
        if result['status'] == 'PASS':
            require(same(actual['output'], case['expected']['output']), 'false typed PASS')
        if result['status'] == 'NOT_RUN':
            require(actual is None and result.get('reason'), 'NOT_RUN has observation or no reason')
        if result['status'] == 'FAIL':
            require(result.get('reason'), 'failure lacks evidence reason')
        for key in ('input_sha256', 'adapter_request_sha256'):
            # Retain these runner-recorded hashes; suite/raw-report pins supply
            # byte integrity without reconstructing Go JSON serialization.
            require(re.fullmatch('[0-9a-f]{64}', result[key]) is not None, 'missing input identity')
    return suite


def build(root, catalog_path):
    check_baseline(root)
    catalog_raw = catalog_path.read_bytes()
    catalog = decode(catalog_raw)
    require(catalog['schema_version'] == 1 and catalog['protocol_version'] == '0.10.0', 'catalog version')
    evidence = {}

    def read(path):
        require(isinstance(path, str) and not Path(path).is_absolute(), 'absolute evidence path')
        resolved = (root / path).resolve()
        require(resolved.is_relative_to(root.resolve()), 'evidence path escapes repository')
        raw = resolved.read_bytes()
        require(sha(raw) == catalog['files'][path], 'hash mismatch: ' + path)
        evidence[path] = sha(raw)
        return raw

    # Pin every declared attachment, including historical provenance. Provenance
    # describes its historical run, not today's adapter source tree.
    for path in catalog['files']:
        read(path)
    baseline = 'verification/0.10.0/'
    snapshot = decode(read(baseline + 'snapshot.json'))
    trace = decode(read(baseline + 'snapshot/verification/traceability.json'))
    matrix = decode(read(baseline + 'case-map.json'))
    rules = unique(trace['rules'])
    planned = unique(matrix['cases'])
    requirements = unique(trace['requirements'])
    lock = decode(read('docs/evidence/core-source-lock.json'))
    core_revisions = {c['repository']: c['revision'] for c in lock['cores']}
    scenarios = unique(catalog['scenarios'])
    fixtures = {}
    for group, total in GROUPS.items():
        entries = [e for e in scenarios.values() if e['group'] == group]
        files = {str(p.relative_to(root)) for p in (root / 'vectors/0.10.0' / (group + '-scenarios')).glob('*.json')}
        require(len(entries) == total and {e['fixture'] for e in entries} == files, 'scenario inventory incomplete')
    for ident, entry in scenarios.items():
        fixture = decode(read(entry['fixture']))
        require(entry['group'] in GROUPS and fixture['id'] == ident and fixture['schema_version'] == 2, 'scenario identity mismatch')
        require(set(entry['rule_ids']) <= rules.keys(), 'unknown scenario rule')
        fixtures[ident] = fixture

    outputs = {}
    require(set(unique(catalog['cores'])) == {'go', 'rust'}, 'core inventory incomplete')
    for core in catalog['cores']:
        require(core['revision'] == core_revisions[core['repository']], 'source lock revision mismatch')
        reports = unique(core['reports'], 'suite')
        require(set(reports) == set(SUITES), 'suite inventory incomplete')
        observations, runs = [], []
        for name, entry in reports.items():
            vector_path = 'vectors/0.10.0/' + name + '.json'
            report = decode(read(entry['report']))
            suite = primitive(read(vector_path), report, core)
            runs.append(dict(report=entry['report'], report_sha256=evidence[entry['report']],
                             suite=vector_path, suite_sha256=evidence[vector_path],
                             subject=report['subject'], environment=report['environment'],
                             created=report['created'], runner_version=report['runner_version']))
            for result_index, result in enumerate(report['results']):
                require(set(result['rule_ids']) <= rules.keys(), 'unknown primitive rule')
                conditional = name == 'http-boundaries' and result['case_id'] in CONDITIONAL
                observations.append(dict(id=suite['id'] + '/' + result['case_id'], kind='primitive',
                                         case_id=result['case_id'], suite_id=suite['id'], rule_ids=result['rule_ids'],
                                         status=result['status'], coverage='conditional' if conditional else 'partial',
                                         report=entry['report'], result_index=result_index))
        state_reports = core['scenario_reports']
        require(set(state_reports) <= scenarios.keys(), 'unknown scenario report')
        state_rows = []
        for ident, entry in scenarios.items():
            fixture = fixtures[ident]
            row = dict(id=ident, kind='scenario', rule_ids=entry['rule_ids'], fixture=entry['fixture'],
                       fixture_sha256=evidence[entry['fixture']], status='NOT_RUN', coverage='prepared',
                       steps=len(fixture['steps']), observed_effects=None,
                       reason='No stateful core binding observation supplied.')
            if ident in state_reports:
                path = state_reports[ident]
                raw_report = decode(read(path))
                validate_scenario(read(entry['fixture']), raw_report)
                subject_identity(raw_report, core)
                require(type(raw_report['schema_version']) is int and same(raw_report['sources'], fixture['sources']),
                        'scenario schema or provenance mismatch')
                for step, actual in zip(fixture['steps'], raw_report['steps']):
                    require(same(actual['expected'], step['expected']) and same(actual['input'], step['input']) and
                            same(actual['expected_effects'], step['effects']), 'changed scenario contract')
                    observation = actual.get('actual')
                    if observation is not None:
                        require(type(observation['schema_version']) is int and observation['schema_version'] == 2 and
                                observation['case_id'] == ident and observation['step_id'] == step['id'], 'wrong step observation')
                        require(isinstance(observation['effects'], dict) and all(type(v) is int and 0 <= v < 2**64
                                for v in observation['effects'].values()), 'invalid observed effect counters')
                    if actual['status'] == 'PASS':
                        require(same(actual['actual']['output'], step['expected']['output']) and
                                same(actual['actual']['effects'], step['effects']), 'false typed effects')
                    if actual['status'] == 'NOT_RUN':
                        require(actual.get('actual') is None, 'unexecuted step has observation')
                row.update(status=raw_report['status'], coverage='partial', report=path,
                           reason=raw_report.get('reason', ''), subject=raw_report['subject'],
                           environment=raw_report['environment'], created=raw_report['created'],
                           step_counts=counts(s['status'] for s in raw_report['steps']),
                           observed_effects=[{'step_id': s['step_id'], 'status': s['status'],
                                             'effects': (s.get('actual') or {}).get('effects')}
                                            for s in raw_report['steps']])
            state_rows.append(row)
        by_rule = {}
        for rule_id, rule in rules.items():
            related = [o for o in observations if rule_id in o['rule_ids']]
            related_states = [s for s in state_rows if rule_id in s['rule_ids']]
            by_rule[rule_id] = dict(case_ids=rule['case_ids'], requirement_ids=rule['requirements'],
                                   source=rule['source'], line=rule['line'],
                                   coverage='partial' if related or related_states else 'unmapped',
                                   conformance='NOT_ESTABLISHED', primitive_counts=counts(o['status'] for o in related),
                                   observation_ids=[o['id'] for o in related], scenario_ids=[s['id'] for s in related_states])
        case_rows = []
        for item in planned.values():
            # A shared rule is a discovery link, never an exact planned-case run.
            case_rows.append(dict(item, related_rule=item['rule_id'],
                                  partial_observation_ids=[o['id'] for o in observations
                                      if o['suite_id'] == 'sage-foundation-0.10.0' and o['case_id'] in item['partial_vector_ids']]))
        primitive_counts = counts(o['status'] for o in observations)
        req_rows = [dict(id=r['id'], description=r['description'], rule_ids=r['rule_ids'],
                         conformance='NOT_ESTABLISHED',
                         case_ids=[c['id'] for c in case_rows if c['rule_id'] in r['rule_ids']])
                    for r in requirements.values()]
        outputs[core['id']] = dict(repository=core['repository'], revision=core['revision'],
            observation_status='FAIL' if primitive_counts['FAIL'] or any(s['status'] == 'FAIL' for s in state_rows) else 'INCOMPLETE',
            conformance='NOT_ESTABLISHED', primitive_counts=primitive_counts,
            scenario_counts=dict(collections.Counter(s['status'] for s in state_rows)),
            scenario_steps=sum(s['steps'] for s in state_rows),
            planned_case_counts=counts(c['evidence_status'] for c in case_rows),
            runs=runs, observations=observations, scenarios=state_rows, rules=by_rule,
            requirements=req_rows, planned_cases=case_rows)
    return dict(schema_version=1, protocol_version='0.10.0', evidence_validation='VALID',
                catalog_sha256=sha(catalog_raw), spec_snapshot=snapshot,
                scope='Archived observations joined to the plan; no fresh core run or whole-protocol certification. '
                      'Rule links and primitive PASS are partial evidence. Hashes detect drift relative to this reviewed inventory, not malicious replacement of the inventory itself.',
                totals=dict(requirements=len(requirements), rules=len(rules), planned_cases=len(planned)),
                evidence_files=evidence, cores=outputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--catalog', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', action='store_true', help='Require an existing deterministic report to match')
    parser.add_argument('--require-conformance', action='store_true')
    args = parser.parse_args()
    try:
        catalog = args.catalog or args.root / 'verification/0.10.0/evidence-catalog.json'
        report = build(args.root, catalog)
        encoded = json.dumps(report, indent=2, ensure_ascii=True) + '\n'
        if args.check:
            require(args.output.read_text() == encoded, 'integrated report is stale')
        else:
            require(not args.output.exists(), 'output exists; use a new path')
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open('x') as stream:
                stream.write(encoded)
        print(json.dumps({k: v['primitive_counts'] for k, v in report['cores'].items()}))
        return 3 if args.require_conformance else 0
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        print('Evidence validation failed: ' + str(error))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
