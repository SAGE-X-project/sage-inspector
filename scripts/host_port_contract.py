#!/usr/bin/env python3
"""Check pinned host-port cases and report bounded, unpromoted observations.

This script does not execute an Agent or accept subject-reported conformance.
Its controls refine existing normative cases and can never return PASS.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / 'verification/0.10.0/host-port/cases.json'
BASE = ROOT / 'verification/0.10.0/design-baseline'
PORTS = {
    'CaptureStore', 'PolicyAuthorizer', 'IdentityAndReadiness',
    'MeasuredComponent', 'IntentSigner', 'TransportOwner',
    'AdmissionLedger', 'EffectOwner', 'ResultConsumer',
}
STATES = {'denied', 'unknown', 'unsupported'}
SHA_FILES = {
    'profiles/agent-mcp-security.md', 'verification/traceability.json',
    'architecture/host-port-contract.md',
    'verification/host-port-reconciliation.md',
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def hex_string(value, length):
    return (type(value) is str and len(value) == length and
            all(char in '0123456789abcdef' for char in value))


def bounded_id(value):
    return type(value) is str and 1 <= len(value) <= 128


def bounded_ids(value):
    return (type(value) is list and len(value) <= 64 and
            all(bounded_id(item) for item in value) and
            len(value) == len(set(value)))


def expected_facts(case_id, facts):
    """Check typed, inert contradictions; provenance remains a separate gate."""
    if case_id == 'host-capture-changed':
        return (hex_string(facts['submitted_bytes_sha256'], 64) and
                hex_string(facts['captured_bytes_sha256'], 64) and
                facts['submitted_bytes_sha256'] !=
                facts['captured_bytes_sha256'] and
                facts['capture_before_model'] is True and
                bounded_id(facts['protected_store_identity']))
    if case_id == 'host-proposal-unchecked':
        return (hex_string(facts['proposal_digest'], 64) and
                hex_string(facts['approved_policy_digest'], 64) and
                facts['authorization_event_ids'] == [] and
                facts['signed_intent_ids'] == [])
    if case_id == 'host-signing-key-missing':
        return (bounded_id(facts['registry_source_identity']) and
                facts['active_role_keys'] == [] and
                facts['selected_signing_key'] is None and
                facts['fallback_attempts'] == [])
    if case_id == 'host-component-reopened':
        return (hex_string(facts['approved_manifest_digest'], 64) and
                bounded_id(facts['measured_instance_id']) and
                bounded_id(facts['loaded_instance_id']) and
                facts['measured_instance_id'] != facts['loaded_instance_id'] and
                facts['load_event_ids'] == [])
    if case_id == 'host-signing-oracle':
        return (bounded_ids(facts['model_callable_routes']) and
                facts['authorization_capability_ids'] == [] and
                facts['signer_event_ids'] == [] and
                facts['signed_intent_ids'] == [])
    if case_id == 'host-uncertain-retry':
        return (hex_string(facts['original_envelope_sha256'], 64) and
                bounded_id(facts['original_call_id']) and
                bounded_ids(facts['retry_call_ids']) and
                all(ident == facts['original_call_id']
                    for ident in facts['retry_call_ids']) and
                facts['durable_journal_state'] == 'UNKNOWN')
    if case_id == 'host-close-before-reserve':
        return (type(facts['owner_close_sequence']) is int and
                0 <= facts['owner_close_sequence'] < 2**64 and
                facts['reservation_sequence'] is None and
                facts['queue_insertions'] == 0 and
                facts['durable_call_state'] == 'ABSENT')
    if case_id == 'host-final-arguments-change':
        return (hex_string(facts['verified_arguments_sha256'], 64) and
                hex_string(facts['dispatch_arguments_sha256'], 64) and
                facts['verified_arguments_sha256'] !=
                facts['dispatch_arguments_sha256'] and
                facts['effect_event_ids'] == [] and
                bounded_id(facts['loaded_instance_id']))
    if case_id == 'host-direct-route':
        return (bounded_ids(facts['complete_route_inventory']) and
                bool(facts['complete_route_inventory']) and
                bounded_ids(facts['isolated_capabilities']) and
                bool(facts['isolated_capabilities']) and
                bounded_ids(facts['gate_event_ids']) and
                facts['independent_effect_event_ids'] == [])
    if case_id == 'host-required-hook-disabled':
        return (bounded_id(facts['host_build']) and
                facts['hook_configuration'] == 'disabled' and
                facts['mandatory_gate_inventory'] == [] and
                bounded_ids(facts['protected_profile_advertisements']) and
                'protected' not in facts['protected_profile_advertisements'])
    if case_id == 'host-gate-timeout':
        start, deadline = facts['gate_start_time'], facts['gate_deadline']
        completion = facts['gate_completion_time']
        return (type(start) is int and type(deadline) is int and
                0 <= start < deadline < 2**64 and
                (completion is None or type(completion) is int and
                 deadline <= completion < 2**64) and
                facts['independent_effect_event_ids'] == [])
    if case_id == 'host-result-unverified':
        return (bounded_id(facts['tracked_call_id']) and
                facts['result_envelope_sha256'] is None and
                facts['verification_event_ids'] == [] and
                facts['output_release_event_ids'] == [])
    if case_id == 'host-optional-verifier-skipped':
        return (facts['diagnostic_call_ids'] == [] and
                bounded_ids(facts['mandatory_gate_event_ids']) and
                bool(facts['mandatory_gate_event_ids']) and
                facts['trusted_verdict_event_ids'] == [] and
                facts['output_release_event_ids'] == [])
    raise ValueError('unknown host-port case: ' + case_id)


def catalog(spec_root=None, suite_path=SUITE):
    suite = load_json(suite_path)
    require(type(suite) is dict and set(suite) == {
        'schema_version', 'protocol_version', 'normative_source_revision',
        'spec_main_revision', 'source_sha256', 'scope', 'cases',
    }, 'closed host-port catalog')
    manifest = load_json(BASE / 'manifest.json')
    trace_path = BASE / 'traceability.json'
    trace = load_json(trace_path)
    require(suite['schema_version'] == 1 and
            suite['protocol_version'] == manifest['protocol_version'] == '0.10.0' and
            suite['normative_source_revision'] ==
            manifest['normative_source_revision'] and
            hex_string(suite['spec_main_revision'], 40),
            'pinned 0.10.0 source revision')
    sources = suite['source_sha256']
    require(type(sources) is dict and set(sources) == SHA_FILES and
            all(hex_string(value, 64) for value in sources.values()),
            'closed source digest set')
    require(sources['verification/traceability.json'] == digest(trace_path) ==
            manifest['source_sha256']['verification/traceability.json'] and
            sources['profiles/agent-mcp-security.md'] ==
            manifest['source_sha256']['profiles/agent-mcp-security.md'],
            'normative source bytes')
    if spec_root is not None:
        for path, expected in sources.items():
            require(digest(spec_root / path) == expected,
                    'spec source drift: ' + path)
    cases = suite['cases']
    require(type(suite['scope']) is str and suite['scope'] and
            type(cases) is list and len(cases) == 13,
            'bounded host-port controls')
    source_cases = {row['id']: row for row in trace['cases']}
    seen = set()
    for row in cases:
        require(type(row) is dict and set(row) == {
            'id', 'port', 'source_case_id', 'rule_id', 'trigger',
            'expected_state', 'required_observations',
        }, 'closed host-port case')
        ident = row['id']
        require(type(ident) is str and ident.startswith('host-') and
                ident not in seen and row['port'] in PORTS and
                row['source_case_id'] in source_cases and
                row['rule_id'] == source_cases[row['source_case_id']]['rule_id'] and
                row['expected_state'] in STATES and
                type(row['trigger']) is str and row['trigger'] and
                type(row['required_observations']) is list and
                1 <= len(row['required_observations']) <= 16 and
                all(type(item) is str and item.isidentifier()
                    for item in row['required_observations']) and
                len(set(row['required_observations'])) ==
                len(row['required_observations']),
                'host-port source case or observation: ' + str(ident))
        seen.add(ident)
    require({row['port'] for row in cases} == PORTS,
            'all nine host ports require controls')
    return suite


def report(suite, observations=None):
    observations = [] if observations is None else observations
    require(type(observations) is list and len(observations) <= len(suite['cases']),
            'bounded observation list')
    by_case = {}
    known = {row['id'] for row in suite['cases']}
    for item in observations:
        require(type(item) is dict and set(item) == {
            'id', 'subject_revision', 'observer_revision', 'observer_id',
            'independent_observer', 'actual_state',
            'new_protected_effects', 'observations',
        }, 'closed host observation')
        ident = item['id']
        require(ident in known and ident not in by_case and
                hex_string(item['subject_revision'], 40) and
                hex_string(item['observer_revision'], 40) and
                type(item['observer_id']) is str and
                1 <= len(item['observer_id']) <= 128 and
                type(item['independent_observer']) is bool and
                item['actual_state'] in STATES and
                type(item['new_protected_effects']) is int and
                0 <= item['new_protected_effects'] <= 2**32 and
                type(item['observations']) is dict and
                all(type(key) is str and key.isidentifier()
                    for key in item['observations']),
                'host observation identity or bounds')
        by_case[ident] = item
    rows = []
    for contract in suite['cases']:
        ident = contract['id']
        item = by_case.get(ident)
        if item is None:
            verdict = 'NOT_RUN'
            missing = contract['required_observations']
        else:
            missing = sorted(set(contract['required_observations']) -
                             set(item['observations']))
            contradiction = (item['actual_state'] !=
                             contract['expected_state'] or
                             item['new_protected_effects'] != 0 or
                             not missing and not expected_facts(
                                 ident, item['observations']))
            verdict = 'FAIL' if contradiction else 'PARTIAL'
        rows.append({'id': ident, 'source_case_id': contract['source_case_id'],
                     'port': contract['port'], 'verdict': verdict,
                     'missing_observations': missing,
                     'independent_observer_recorded': bool(
                         item and item['independent_observer'])})
    return {'protocol_version': suite['protocol_version'],
            'normative_source_revision': suite['normative_source_revision'],
            'counts': dict(Counter(row['verdict'] for row in rows)),
            'cases': rows,
            'limit': 'PARTIAL is the maximum from this bounded catalog; full case PASS needs separate deployment evidence'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path,
                        help='optionally verify exact sage-spec source bytes')
    parser.add_argument('--observations', type=Path,
                        help='bounded independent-observer records')
    args = parser.parse_args()
    try:
        suite = catalog(args.spec_root)
        observed = load_json(args.observations) if args.observations else None
        print(json.dumps(report(suite, observed), sort_keys=True,
                         separators=(',', ':')))
    except (ValueError, OSError, KeyError, TypeError,
            json.JSONDecodeError) as error:
        print('Host-port inspection error: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
