"""Audit a pinned Guard implementation handoff; never execute tools or core code."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'verification/0.10.0/guard-binding-contract.json'
SPEC = 'verification/0.10.0/snapshot/profiles/agent-mcp-security.md'
RECORDS = 'vectors/0.10.0/guard-records.json'
MANIFEST = 'vectors/0.10.0/guard-manifest.json'
STAGES = ('commitments', 'intent', 'ledger', 'dispatch', 'result')
OPERATIONS = {
    'commitments': {'sage.guard.original.commit', 'sage.guard.manifest.verify', 'sage.guard.policy.commit'},
    'intent': {'sage.guard.json.bounds', 'sage.guard.intent.verify', 'signature.verify', 'jcs.canonicalize'},
    'result': {'sage.guard.result.verify', 'sage.guard.mcp.result'},
    'ledger': set(), 'dispatch': set(),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON member')
        result[key] = value
    return result


def load(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'unexpected contract fields')


def audit(root=ROOT):
    raw = (root / CONTRACT).read_bytes()
    c = load(raw)
    exact(c, ('schema_version', 'protocol_version', 'kind', 'conformance', 'sources', 'reviewed_cores', 'stages'))
    require(type(c['schema_version']) is int and c['schema_version'] == 1, 'schema version')
    require(c['protocol_version'] == '0.10.0' and c['kind'] == 'guard-binding-handoff', 'contract kind')
    require(c['conformance'] == 'NOT_ESTABLISHED', 'handoff cannot certify conformance')
    exact(c['sources'], (SPEC, RECORDS, MANIFEST))
    for path, expected in c['sources'].items():
        require(sha((root / path).read_bytes()) == expected, 'source hash mismatch: ' + path)
    records = load((root / RECORDS).read_bytes())
    manifest = load((root / MANIFEST).read_bytes())
    require(manifest['records_sha256'] == c['sources'][RECORDS], 'manifest records mismatch')
    cases = {case['id']: case for case in records['cases']}
    require(len(cases) == len(records['cases']) == 102, 'primitive membership changed')
    scenarios = {}
    for entry in manifest['scenarios']:
        ident = entry['id']
        require(type(ident) is str and re.fullmatch(r'guard-[a-z0-9-]+', ident), 'invalid scenario id')
        require(entry['file'] == ident + '.json', 'invalid fixture path')
        require(ident not in scenarios, 'duplicate scenario id')
        data = (root / 'vectors/0.10.0/guard-scenarios' / entry['file']).read_bytes()
        require(sha(data) == entry['sha256'], 'scenario hash mismatch: ' + ident)
        fixture = load(data)
        require(fixture['id'] == ident, 'scenario identity mismatch')
        scenarios[ident] = len(fixture['steps'])
    require(len(scenarios) == 37 and sum(scenarios.values()) == 297, 'scenario membership changed')
    exact(c['reviewed_cores'], ('go', 'rust'))
    for core in c['reviewed_cores'].values():
        exact(core, ('revision', 'evidence', 'files'))
        require(type(core['revision']) is str and re.fullmatch('[0-9a-f]{40}', core['revision']), 'invalid core revision')
        require(core['evidence'] == 'SOURCE_REVIEW_ONLY', 'source review is not runtime evidence')
        require(type(core['files']) is dict and core['files'], 'missing reviewed sources')
        for path, digest in core['files'].items():
            require(type(path) is str and not Path(path).is_absolute() and '..' not in Path(path).parts, 'invalid source path')
            require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'invalid source digest')
    require(type(c['stages']) is list and [s['id'] for s in c['stages']] == list(STAGES), 'stage order')
    seen_cases, seen_scenarios, stages = set(), set(), []
    for index, stage in enumerate(c['stages']):
        exact(stage, ('id', 'requires', 'binding_status', 'primitive_cases', 'scenarios'))
        require(stage['requires'] == list(STAGES[:index]), 'missing prerequisite')
        require(stage['binding_status'] == 'NOT_RUN', 'unexecuted binding promoted')
        for field in ('primitive_cases', 'scenarios'):
            require(type(stage[field]) is list and all(type(x) is str for x in stage[field]), 'invalid case list')
            require(len(set(stage[field])) == len(stage[field]), 'duplicate assigned case')
        expected = {ident for ident, case in cases.items() if case['operation'] in OPERATIONS[stage['id']]}
        require(set(stage['primitive_cases']) == expected, 'wrong primitive allocation')
        require(not seen_cases.intersection(expected), 'primitive counted twice')
        require(set(stage['scenarios']) <= set(scenarios), 'unknown scenario')
        require(not seen_scenarios.intersection(stage['scenarios']), 'scenario counted twice')
        seen_cases.update(expected)
        seen_scenarios.update(stage['scenarios'])
        stages.append(dict(id=stage['id'], status='NOT_RUN', requires=stage['requires'],
                           primitive_cases=stage['primitive_cases'], scenarios=stage['scenarios']))
    require(seen_cases == set(cases) and seen_scenarios == set(scenarios), 'unassigned cases')
    return dict(schema_version=1, protocol_version='0.10.0', kind='guard-binding-readiness',
                contract_audit='PASS', status='INCOMPLETE', conformance='NOT_ESTABLISHED',
                scope='Pinned implementation handoff only; no core verification, dispatch or host execution.',
                contract_sha256=sha(raw), sources=c['sources'], reviewed_cores=c['reviewed_cores'],
                counts=dict(primitives=len(cases), scenarios=len(scenarios), steps=sum(scenarios.values())),
                stages=stages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new evidence directory')
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        historical = ROOT / 'docs/evidence'
        require(historical not in (output, *output.parents), 'preserve historical evidence')
        report = audit()
        output.mkdir(parents=True, exist_ok=False)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(2, 'guard binding audit error: ' + str(error) + '\n')
    print('Contract audit PASS; Guard bindings INCOMPLETE (no runtime claim).')
    return 3


if __name__ == '__main__':
    raise SystemExit(main())
