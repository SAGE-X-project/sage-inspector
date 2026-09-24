"""Join the ordered INS-11 evidence without promoting scoped passes to conformance."""
import argparse
import hashlib
import json
from pathlib import Path

from check_agent_host_deployment_audit import check as check_host
from check_close_evidence import check as check_close
from check_core_lifecycle_evidence import check as check_lifecycle
from check_mcp_binding_evidence import inspect as inspect_mcp_binding
from check_registry_source_deployment_audit import check as check_registry
from integrate_evidence import build as build_legacy, same

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'docs/evidence/ins11-integrated-verdict'
CI = {
    'run_id': 35933387031,
    'head_sha': '690a8e0f85897e0615abb1cd0c7980442100c50e',
    'artifact_id': 10781767710,
    'artifact_name': 'mcp-native-interop-690a8e0f85897e0615abb1cd0c7980442100c50e',
    'artifact_digest': 'sha256:701eef92d20f4fddb8fece47e9763d9501f5bd4a44b85f27446b3e7583e8e61d',
    'conclusion': 'success',
}
CI_REPORTS = {
    'baseline': 'ci-reports/normative-baseline.json',
    'go_review': 'ci-reports/go-review.json',
    'rust_review': 'ci-reports/rust-review.json',
    'mcp_binding': 'ci-reports/mcp-binding.json',
}
INPUTS = {
    **{key: 'docs/evidence/ins11-integrated-verdict/' + path
       for key, path in CI_REPORTS.items()},
    'normative_lock': 'verification/0.10.0/normative-baseline-lock.json',
    'legacy_catalog': 'docs/evidence/integrated.json',
    'core_lifecycle': 'docs/evidence/core-lifecycle/manifest.json',
    'registry_source': 'docs/evidence/registry-source-deployment-audit/manifest.json',
    'agent_host': 'docs/evidence/agent-host-deployment-audit/manifest.json',
    'legacy_close': 'docs/evidence/deployment/close-race/report.json',
    'legacy_exchange': 'docs/evidence/deployment/exchange.json',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(relative):
    raw = (ROOT / relative).read_bytes()
    return json.loads(raw), sha(raw)


def build(artifact=None):
    source = {key: read(path) for key, path in INPUTS.items()}
    data = {key: value for key, (value, _) in source.items()}
    lock, baseline = data['normative_lock'], data['baseline']
    go, rust, binding = (data[key] for key in ('go_review', 'rust_review', 'mcp_binding'))
    spec = lock['spec']['revision']
    require(lock['execution_order'][7] == 'integrated-verdict'
            and lock['conformance'] == 'NOT_ESTABLISHED', 'ordered baseline')
    require(baseline['kind'] == 'normative-baseline-report'
            and baseline['status'] == 'BASELINE_LOCKED'
            and baseline['spec_status'] == 'ADOPTED_NORMATIVE_DESIGN'
            and baseline['spec_revision'] == spec
            and baseline['contract_sha256'] == source['normative_lock'][1]
            and baseline['conformance'] == 'NOT_ESTABLISHED', 'normative baseline')
    for language, report, key in (('go', go, 'go_revision'),
                                  ('rust', rust, 'rust_revision')):
        require(report['kind'] == language + '-normative-implementation-review-report'
                and report['status'] == 'COMPLETE'
                and report['spec_revision'] == spec
                and report[key] == lock['cores'][language]['revision']
                and report['counts'] == {'DIRECT': 26, 'PARTIAL': 0, 'MISSING': 0}
                and report['conformance'] == 'NOT_ESTABLISHED',
                language + ' implementation review')
    require(binding['kind'] == 'mcp-binding-evidence'
            and binding['status'] == 'EVIDENCE_CHECKED'
            and binding['spec_revision'] == spec
            and binding['normative_baseline_sha256'] == source['normative_lock'][1]
            and binding['historical_catalog'] == {'NOT_RUN': 71}
            and binding['current_parent_cases'] == {'PASS': 71, 'PARTIAL': 0, 'NOT_RUN': 0}
            and binding['protected_pairs'] == {'PASS': 4}
            and binding['restart_observations'] == {'PASS': 8}
            and binding['conformance'] == 'NOT_ESTABLISHED', 'MCP binding report')
    for language in ('go', 'rust'):
        require(binding['mandatory_children'][language] == {
            'revision': lock['cores'][language]['revision'],
            'status': 'PASS', 'mandatory_children': 26,
        }, 'MCP child/revision binding: ' + language)
    require(baseline['go_revision'] == go['go_revision']
            and baseline['rust_revision'] == rust['rust_revision'],
            'implementation review revision split')
    if artifact is not None:
        paths = {
            'baseline': artifact / 'normative-baseline/report.json',
            'go_review': artifact / 'go-normative-review/report.json',
            'rust_review': artifact / 'rust-normative-review/report.json',
            'mcp_binding': artifact / 'mcp-binding-evidence/report.json',
        }
        for key, path in paths.items():
            require(sha(path.read_bytes()) == source[key][1],
                    'CI artifact report differs: ' + key)
        fresh = inspect_mcp_binding(artifact / 'mcp-core-runtime',
                                    artifact / 'mcp-case-evidence',
                                    artifact / 'mcp-native-protected')
        require(same(fresh, binding), 'MCP raw artifact does not support binding report')

    lifecycle = check_lifecycle()
    registry = check_registry()
    host = check_host()
    close = check_close()
    legacy = build_legacy(ROOT, ROOT / 'verification/0.10.0/evidence-catalog.json')
    require(same(legacy, data['legacy_catalog']), 'legacy aggregate drift')
    require(lifecycle['spec_revision'] == registry['spec_revision']
            == host['spec_revision'] == spec, 'stage specification revision')
    require(lifecycle['status'] == 'EVIDENCE_CHECKED'
            and lifecycle['conformance'] == 'NOT_ESTABLISHED'
            and lifecycle['subjects']['go']['revision'] == registry['go_revision']
            == host['sources']['go']['revision']
            and lifecycle['subjects']['rust']['revision']
            == host['sources']['rust']['revision'], 'lifecycle source identity')
    require(registry['status'] == registry['live_chain_verification'] == 'NOT_RUN'
            and registry['conformance'] == 'NOT_ESTABLISHED'
            and host['status'] == 'NOT_RUN'
            and host['conformance'] == 'NOT_ESTABLISHED'
            and close['go_status'] == 'FAIL'
            and close['rust_status'] == 'UNSUPPORTED', 'unresolved deployment or legacy findings')
    require(legacy['totals'] == {'requirements': 45, 'rules': 77, 'planned_cases': 386}
            and legacy['cores']['go']['primitive_counts']
            == {'PASS': 145, 'FAIL': 69, 'UNSUPPORTED': 311, 'NOT_RUN': 0}
            and legacy['cores']['rust']['primitive_counts']
            == {'PASS': 159, 'FAIL': 63, 'UNSUPPORTED': 303, 'NOT_RUN': 0}
            and legacy['cores']['go']['planned_case_counts']['NOT_RUN'] == 386
            and legacy['cores']['rust']['planned_case_counts']['NOT_RUN'] == 386
            and legacy['deployment_evidence']['exchange_counts']
            == {'PASS': 28, 'FAIL': 0, 'UNSUPPORTED': 4, 'NOT_RUN': 0}
            and legacy['deployment_evidence']['host_not_run'] == 8,
            'historical inventory or incomplete exchange')
    require(lifecycle['historical'] == {
        'legacy_go_close_race': 'FAIL',
        'rust_direct_concurrent_close': 'UNSUPPORTED',
        'lifecycle_catalog': {'NOT_RUN': 37},
    }, 'historical lifecycle findings')
    return {
        'schema_version': 1,
        'protocol_version': '0.10.0',
        'kind': 'ins11-integrated-verdict',
        'spec_revision': spec,
        'source_ci': CI,
        'inputs': {key: {'path': INPUTS[key], 'sha256': digest}
                   for key, (_, digest) in source.items()},
        'scopes': {
            'normative_baseline': 'BASELINE_LOCKED',
            'go_implementation_review': {'revision': go['go_revision'], 'direct_children': 26},
            'rust_implementation_review': {'revision': rust['rust_revision'], 'direct_children': 26},
            'mcp_binding': {
                'status': 'EVIDENCE_CHECKED', 'parent_pass': 71,
                'mandatory_children_per_core': 26, 'protected_pairs_pass': 4,
                'restart_pass': 8, 'go_revision': binding['mandatory_children']['go']['revision'],
                'rust_revision': binding['mandatory_children']['rust']['revision'],
            },
            'core_lifecycle': {
                'status': 'EVIDENCE_CHECKED',
                'go_revision': lifecycle['subjects']['go']['revision'],
                'rust_revision': lifecycle['subjects']['rust']['revision'],
            },
            'registry_source': 'NOT_RUN',
            'agent_host': {'status': 'NOT_RUN', 'scenarios_not_run': 8},
        },
        'unresolved': {
            'legacy_planned_cases_not_run_per_core': 386,
            'legacy_primitive_counts': {
                language: legacy['cores'][language]['primitive_counts']
                for language in ('go', 'rust')
            },
            'historical_lifecycle_not_run': 37,
            'legacy_go_close_race': 'FAIL',
            'rust_direct_concurrent_close': 'UNSUPPORTED',
            'legacy_record_exchange_unsupported': 4,
            'live_registry': 'NOT_RUN',
            'deployed_host': 'NOT_RUN',
            'mcp_go_revision_differs_from_lifecycle':
                go['go_revision'] != lifecycle['subjects']['go']['revision'],
        },
        'ordered_review': 'COMPLETE_WITH_UNVERIFIED_DEPLOYMENTS',
        'ins11': 'INCOMPLETE',
        'conformance': 'NOT_ESTABLISHED',
        'conformance_claim': 'NOT_READY',
    }


def check_saved(path=BASE / 'report.json', artifact=None):
    expected = build(artifact)
    actual = json.loads(path.read_text())
    require(same(actual, expected), 'integrated verdict drift')
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path,
                        help='Also recheck the exact downloaded CI raw evidence')
    parser.add_argument('--write-new', action='store_true')
    args = parser.parse_args()
    path = BASE / 'report.json'
    if args.write_new:
        report = build(args.artifact)
        encoded = json.dumps(report, indent=2, ensure_ascii=False) + '\n'
        with path.open('x') as stream:
            stream.write(encoded)
    else:
        check_saved(path, args.artifact)
    print('INS-11 INCOMPLETE; conformance NOT_ESTABLISHED; '
          'Registry Source and Agent host NOT_RUN')


if __name__ == '__main__':
    raise SystemExit(main())
