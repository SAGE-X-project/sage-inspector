"""Validate the adopted specification and implementation revisions for ordered work."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'verification/0.10.0/normative-baseline-lock.json'
SETUP_EVIDENCE = ROOT / 'verification/0.10.0/mcp-setup-case-contract.json'
AGGREGATE_EVIDENCE = ROOT / 'verification/0.10.0/mcp-case-evidence-contract.json'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(raw):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON member')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError('non-finite number')))


def exact(value, fields, message):
    require(type(value) is dict and set(value) == set(fields), message)


def git_head(path):
    return subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=path, text=True, timeout=10).strip()


def validate_contract(value):
    exact(value, ('schema_version','protocol_version','kind','spec','cores','inspector',
                  'case_model','execution_order','conformance'), 'contract fields')
    require(value['schema_version'] == 1 and value['protocol_version'] == '0.10.0',
            'contract version')
    require(value['kind'] == 'normative-baseline-lock', 'contract kind')
    require(value['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')

    spec = value['spec']
    exact(spec, ('repository','revision','adoption_record','adoption_record_sha256',
                 'status','artifacts'), 'spec fields')
    require(spec['repository'] == 'SAGE-X-project/sage-spec', 'spec repository')
    require(len(spec['revision']) == 40 and spec['status'] == 'ADOPTED_NORMATIVE_DESIGN',
            'spec identity')
    require(spec['adoption_record'] == 'verification/mcp-adoption.json',
            'adoption record path')
    require(set(spec['artifacts']) == {
        'profiles/non-http-mcp-security.md',
        'profiles/non-http-mcp-tool.json',
        'verification/traceability.json'}, 'normative artifacts')
    require(all(len(value) == 64 for value in spec['artifacts'].values()),
            'normative artifact hash')

    exact(value['cores'], ('go','rust'), 'core fields')
    for language, repository in (('go','SAGE-X-project/sage'),
                                 ('rust','SAGE-X-project/rs-sage-core')):
        core = value['cores'][language]
        exact(core, ('repository','revision'), language + ' core fields')
        require(core['repository'] == repository and len(core['revision']) == 40,
                language + ' core identity')

    inspector = value['inspector']
    exact(inspector, ('alignment_base_revision','historical_spec_revision',
                      'historical_catalog','runtime_overlay','runtime_classification',
                      'adoption_review_classification'), 'inspector fields')
    require(inspector['historical_catalog'] == {'NOT_RUN':71}, 'historical catalog')
    require(inspector['runtime_overlay'] == {'PASS':71,'PARTIAL':0,'NOT_RUN':0},
            'runtime overlay')
    require(inspector['runtime_classification'] == 'EXECUTED_PENDING_NORMATIVE_MAPPING',
            'runtime classification')
    require(inspector['adoption_review_classification'] ==
            'HISTORICAL_POST_ADOPTION_REVIEW', 'adoption review classification')

    require(value['case_model'] == {
        'baseline_parent_cases':386,
        'binding_parent_cases':71,
        'total_parent_cases':457,
        'mandatory_binding_children':26,
        'separate_historical_lifecycle_cases':37}, 'case model')
    expected_order = [
        'normative-provenance','go-implementation-review','rust-implementation-review',
        'inspector-binding-evidence','ins-11-core-lifecycle','registry-source',
        'agent-host','integrated-verdict','post-plan-errata-and-refactor']
    require(value['execution_order'] == expected_order, 'execution order')
    return value


def validate_historical_evidence():
    setup = load(SETUP_EVIDENCE.read_text())
    aggregate = load(AGGREGATE_EVIDENCE.read_text())
    require(setup['historical_catalog'] == {'NOT_RUN':71}, 'setup historical catalog')
    require(setup['case_counts'] == {'PASS':58,'PARTIAL':0,'NOT_RUN':0},
            'setup runtime counts')
    require(aggregate['historical_catalog'] == {'NOT_RUN':71},
            'aggregate historical catalog')
    require(aggregate['runtime_case_counts'] == {'PASS':71,'PARTIAL':0,'NOT_RUN':0},
            'aggregate runtime counts')
    for value in (setup, aggregate):
        require(value['adoption'] == 'PROPOSAL_NOT_ADOPTED',
                'historical evidence was relabelled')
        require(value['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')


def validate_spec(contract, root, revision_reader=git_head):
    spec = contract['spec']
    require(revision_reader(root) == spec['revision'], 'spec revision')
    record_path = root / spec['adoption_record']
    raw = record_path.read_bytes()
    require(sha(raw) == spec['adoption_record_sha256'], 'adoption record hash')
    record = load(raw.decode())
    require(record['status'] == spec['status'], 'adoption status')
    require(record['protocol_version'] == '0.10.0', 'adoption protocol version')
    require(record['conformance'] == 'NOT_ESTABLISHED', 'adoption conformance promotion')
    require(record['counts'] == {
        'requirements':45,
        'baseline_rule_groups':77,
        'binding_rule_groups':14,
        'total_rule_groups':91,
        'baseline_parent_cases':386,
        'binding_parent_cases':71,
        'total_parent_cases':457,
        'mandatory_binding_children':26,
        'historical_inspector_lifecycle_not_run':37}, 'adoption counts')
    for relative, expected in spec['artifacts'].items():
        require(sha((root / relative).read_bytes()) == expected,
                'normative artifact drift: ' + relative)
        require(record['normative_sha256'][relative] == expected,
                'adoption artifact drift: ' + relative)
    return record


def validate_core(contract, language, root, revision_reader=git_head):
    require(revision_reader(root) == contract['cores'][language]['revision'],
            language + ' core revision')


def inspect(spec_root, go_root, rust_root):
    contract_raw = CONTRACT.read_bytes()
    contract = validate_contract(load(contract_raw.decode()))
    validate_historical_evidence()
    record = validate_spec(contract, spec_root)
    validate_core(contract, 'go', go_root)
    validate_core(contract, 'rust', rust_root)
    return {
        'schema_version': 1,
        'protocol_version': '0.10.0',
        'kind': 'normative-baseline-report',
        'status': 'BASELINE_LOCKED',
        'spec_revision': contract['spec']['revision'],
        'spec_status': record['status'],
        'go_revision': contract['cores']['go']['revision'],
        'rust_revision': contract['cores']['rust']['revision'],
        'historical_catalog': contract['inspector']['historical_catalog'],
        'runtime_overlay': contract['inspector']['runtime_overlay'],
        'runtime_classification': contract['inspector']['runtime_classification'],
        'next_step': contract['execution_order'][1],
        'conformance': 'NOT_ESTABLISHED',
        'contract_sha256': sha(contract_raw)
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path, required=True)
    parser.add_argument('--go-root', type=Path, required=True)
    parser.add_argument('--rust-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        require(not output.exists() and not output.is_relative_to(ROOT),
                'new external output required')
        report = inspect(args.spec_root.resolve(), args.go_root.resolve(),
                         args.rust_root.resolve())
        output.mkdir(parents=True, exist_ok=False)
        (output / 'contract.json').write_bytes(CONTRACT.read_bytes())
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, UnicodeError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        print('Normative baseline FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('Normative baseline locked: adopted spec and pinned Go/Rust revisions verified; '
          'conformance NOT_ESTABLISHED.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

