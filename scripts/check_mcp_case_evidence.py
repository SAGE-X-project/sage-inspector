"""Derive conservative proposal-case results from pinned core runtime evidence."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from check_mcp_catalog import BASE as CATALOG_BASE, catalog
from check_mcp_owner_admission import load, require, sha
from run_mcp_core_runtime import (OWNER_CONTRACT, OWNER_CONTRACT_CASES, PINS,
                                  NORMATIVE_CONTRACTS,
                                  SETUP_CONTRACT, SIGNATURE_CONTRACT, SIGNATURE_CONTRACT_CASES,
                                  observed, successful)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'verification/0.10.0/mcp-case-evidence-contract.json'
CATALOG_MANIFEST = CATALOG_BASE / 'manifest.json'
CATALOG_MANIFEST_SHA = '5727834113a41ef910d4a5c5487457b6e3ae9f89ac36e86946a6e72ae28c1f35'
ASSESSMENTS = {
    'mres-close-after-reservation': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestMCPAdmissionCloseDuringFence'),
            ('rust', 'hpke::completion010::tests::mcp_admission_tests::close_during_post_fence_callback_denies_and_retains_history'),
        ),
    },
    'mres-close-after-admission': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestMCPAdmissionCloseAfterInsertionKeepsAdmission'),
            ('go', 'TestMCPAdmissionAuthenticatedExecutionAndDuplicate'),
            ('rust', 'hpke::completion010::tests::mcp_admission_tests::admitted_worker_persists_signed_result_once_and_duplicate_never_runs'),
        ),
    },
    'mres-crash-after-admission': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestMCPAdmissionCrashRecoveryDoesNotExecuteAgain'),
            ('rust', 'hpke::completion010::tests::mcp_admission_tests::crash_recovery_marks_admission_unknown_and_never_executes_again'),
        ),
    },
    'mres-protected-timeout-before-admission': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestMCPAdmissionProtectedDeadlineBeforeFinalAdmissionRetainsReservation'),
            ('rust', 'hpke::completion010::tests::mcp_admission_tests::protected_deadline_before_final_admission_retains_identity_and_reservation'),
        ),
    },
    'mres-protected-timeout-after-admission': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestMCPProtectedReplyDeadlineAfterAdmissionRetainsCompletion'),
            ('rust', 'hpke::completion010::tests::mcp_admission_tests::mcp_reply_tests::protected_deadline_after_admission_fails_transport_without_rollback'),
        ),
    },
    'mres-ready-session-expiry': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestMCPAdmissionReadySessionExpiryDeniesNewAdmission'),
            ('rust', 'hpke::completion010::tests::mcp_admission_tests::ready_session_expiry_denies_new_admission_and_closes_owner'),
        ),
    },
    'mres-signature-intent': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestBridgeIntentSignatureAlgorithmBoundary'),
            ('rust', 'guard010::ledger::tests::intent_signature_algorithm_boundary_accepts_only_ed25519'),
        ),
    },
    'mres-signature-result': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestBridgeResultSignatureAlgorithmBoundary'),
            ('rust', 'guard010::ledger::tests::result_signature_algorithm_boundary_accepts_only_ed25519'),
        ),
    },
    'mres-signature-carriage': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestCompletion010SignatureCarriageRequiresRoleBoundEd25519'),
            ('rust', 'hpke::completion010::tests::signature_carriage_requires_role_bound_ed25519'),
        ),
    },
    'mres-missing-signing-key': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestCompletion010MissingSigningKeyHasNoFallback'),
            ('rust', 'hpke::completion010::tests::missing_signing_key_has_no_fallback'),
        ),
    },
    'mres-ready-past-setup': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestMCPOwnerSetupAndRetainedHistory'),
            ('rust', 'hpke::completion010::tests::mcp_setup_tests::mcp_setup_ready_past_setup_deadline_uses_protected_limits'),
        ),
    },
    'mres-stale-setup-completion': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestMCPOwnerStaleSetupCompletionAfterReady'),
            ('rust', 'hpke::completion010::tests::mcp_setup_tests::mcp_setup_stale_completion_after_ready_is_inert'),
        ),
    },
    'mres-close-before-reservation': {
        'status': 'PASS',
        'requirements': (
            ('go', 'TestMCPAdmissionCloseBeforeReservationHasNoEffects'),
            ('rust', 'hpke::completion010::tests::mcp_admission_tests::close_before_reservation_denies_with_zero_effects'),
        ),
    },
}


def exact(value, fields, message):
    require(type(value) is dict and set(value) == set(fields), message)


def safe_read(base, name, limit=16 * 1024 * 1024):
    require(type(name) is str and name and '/' not in name and '\\' not in name, 'invalid evidence file')
    path = base / name
    require(path.resolve().is_relative_to(base.resolve()), 'evidence path escape')
    require(not path.is_symlink(), 'evidence symlink')
    raw = path.read_bytes()
    require(len(raw) <= limit, 'evidence file too large')
    return raw


def catalog_rows():
    require(sha(CATALOG_MANIFEST.read_bytes()) == CATALOG_MANIFEST_SHA, 'catalog manifest identity')
    manifest = load(CATALOG_MANIFEST.read_bytes())
    plans = {}
    for name, expected in manifest['files'].items():
        raw = (CATALOG_BASE / name).read_bytes()
        require(sha(raw) == expected, 'catalog source drift: ' + name)
        if name in ('cases.json', 'addendum-cases.json', 'resolutions.json'):
            plans[name] = load(raw)
    return catalog(plans)


def validate_contract(value):
    exact(value, ('schema_version', 'protocol_version', 'kind', 'catalog_manifest_sha256',
                  'owner_admission_contract_sha256', 'signature_boundary_contract_sha256',
                  'setup_case_contract_sha256', 'historical_catalog', 'runtime_case_counts',
                  'external_review', 'adoption', 'conformance', 'assessments'), 'contract fields')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'schema version')
    require(value['protocol_version'] == '0.10.0' and value['kind'] == 'mcp-proposal-case-evidence', 'contract identity')
    require(value['catalog_manifest_sha256'] == CATALOG_MANIFEST_SHA, 'catalog binding')
    require(value['owner_admission_contract_sha256'] == sha(OWNER_CONTRACT.read_bytes()), 'owner contract binding')
    require(value['signature_boundary_contract_sha256'] == sha(SIGNATURE_CONTRACT.read_bytes()), 'signature contract binding')
    require(value['setup_case_contract_sha256'] == sha(SETUP_CONTRACT.read_bytes()), 'setup contract binding')
    require(value['historical_catalog'] == {'NOT_RUN': 71}, 'historical catalog promotion')
    require(value['runtime_case_counts'] == {'PASS': 71, 'PARTIAL': 0, 'NOT_RUN': 0}, 'runtime counts')
    require(value['external_review'] == 'NOT_PERFORMED' and value['adoption'] == 'PROPOSAL_NOT_ADOPTED', 'review or adoption promotion')
    require(value['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')
    require(type(value['assessments']) is list and len(value['assessments']) == len(ASSESSMENTS), 'assessment count')
    found = set()
    for row in value['assessments']:
        exact(row, ('id', 'status', 'claim', 'requirements'), 'assessment fields')
        ident = row['id']
        require(ident in ASSESSMENTS and ident not in found, 'assessment identity')
        require(row['status'] == ASSESSMENTS[ident]['status'], 'assessment status')
        require(type(row['claim']) is str and 40 <= len(row['claim']) <= 300, 'assessment claim')
        require(type(row['requirements']) is list and len(row['requirements']) >= 2, 'assessment requirements')
        actual = []
        for requirement in row['requirements']:
            exact(requirement, ('language', 'test'), 'requirement fields')
            language, test = requirement['language'], requirement['test']
            require(language in PINS, 'requirement language')
            require(test in OWNER_CONTRACT_CASES[language] or test in SIGNATURE_CONTRACT_CASES[language], 'test outside evidence contracts')
            actual.append((language, test))
        require(tuple(actual) == ASSESSMENTS[ident]['requirements'], 'changed case mapping')
        found.add(ident)
    return value


def validate_runtime(base):
    raw = safe_read(base, 'report.json')
    report = load(raw)
    require(report.get('kind') == 'mcp-core-runtime-tests' and report.get('status') == 'PASS', 'runtime status')
    require(report.get('conformance') == 'NOT_ESTABLISHED' and report.get('interoperability') == 'NOT_RUN', 'runtime claim promotion')
    require(report.get('catalog') == {'NOT_RUN': 71}
            and report.get('mandatory_children') == 'PINNED_CORE_ASSERTIONS',
            'historical catalog or mandatory child evidence changed')
    require(report.get('owner_admission_contract_sha256') == sha(OWNER_CONTRACT.read_bytes()), 'runtime owner contract')
    require(report.get('signature_boundary_contract_sha256') == sha(SIGNATURE_CONTRACT.read_bytes()), 'runtime signature contract')
    require(safe_read(base, 'owner-admission-contract.json') == OWNER_CONTRACT.read_bytes(), 'preserved owner contract')
    require(safe_read(base, 'signature-boundary-contract.json') == SIGNATURE_CONTRACT.read_bytes(), 'preserved signature contract')
    for language, contract in NORMATIVE_CONTRACTS.items():
        require(safe_read(base, language + '-normative-review-contract.json') == contract.read_bytes(),
                'preserved normative contract: ' + language)
        require(report.get('normative_contract_sha256', {}).get(language) == sha(contract.read_bytes()),
                'runtime normative contract: ' + language)
    runner = safe_read(base, 'runner.py')
    require(sha(runner) == report.get('runner_sha256'), 'runtime runner hash')
    subjects = report.get('subjects')
    require(successful(subjects), 'incomplete core runtime')
    for language, pin in PINS.items():
        require(subjects[language].get('revision') == pin, 'core revision: ' + language)
    evidence = {}
    for ident, assessment in ASSESSMENTS.items():
        rows = []
        for language, test in assessment['requirements']:
            matches = [row for row in subjects[language]['cases'] if row.get('test') == test]
            require(len(matches) == 1, 'missing or duplicate required test')
            row = matches[0]
            require(row.get('status') == 'PASS' and row.get('execution_status') == 'PASS'
                    and row.get('exit_code') == 0 and row.get('evidence_kind') == 'pinned-core-assertions', 'required test failed')
            if test in OWNER_CONTRACT_CASES[language]:
                require(row.get('owner_admission_boundaries') == OWNER_CONTRACT_CASES[language][test], 'owner boundary mapping drift')
            else:
                require(row.get('signature_boundary') == SIGNATURE_CONTRACT_CASES[language][test], 'signature boundary mapping drift')
            log = safe_read(base, row.get('log', ''))
            require(sha(log) == row.get('log_sha256'), 'required log hash')
            require(observed(language, test, log.decode('utf-8'), row['exit_code']), 'required test not observed')
            rows.append({'language': language, 'revision': PINS[language], 'test': test,
                         'log': row['log'], 'log_sha256': row['log_sha256']})
        evidence[ident] = rows
    return report, evidence


def validate_setup(base):
    raw = safe_read(base, 'report.json')
    report = load(raw)
    require(report.get('kind') == 'mcp-setup-case-evidence' and report.get('status') == 'EVIDENCE_CHECKED', 'setup evidence status')
    require(report.get('case_counts') == {'PASS': 58, 'PARTIAL': 0, 'NOT_RUN': 0}, 'setup evidence counts')
    require(report.get('historical_catalog') == {'NOT_RUN': 71}, 'setup historical catalog')
    require(report.get('contract_sha256') == sha(SETUP_CONTRACT.read_bytes()), 'setup evidence contract')
    require(safe_read(base, 'contract.json') == SETUP_CONTRACT.read_bytes(), 'preserved setup evidence contract')
    require(report.get('external_review') == 'NOT_PERFORMED' and report.get('adoption') == 'PROPOSAL_NOT_ADOPTED', 'setup claim promotion')
    require(report.get('conformance') == 'NOT_ESTABLISHED', 'setup conformance promotion')
    cases = report.get('cases')
    require(type(cases) is list and len(cases) == 58, 'setup case inventory')
    found = {}
    for row in cases:
        require(type(row) is dict and row.get('status') == 'PASS' and row.get('id') not in found, 'setup case result')
        require(type(row.get('evidence')) is list and row['evidence'], 'setup case evidence')
        found[row['id']] = row
    return report, found


def inspect(runtime, setup):
    contract_raw = CONTRACT.read_bytes()
    contract = validate_contract(load(contract_raw))
    rows = catalog_rows()
    all_ids = {row['id'] for row in rows}
    require(set(ASSESSMENTS) <= all_ids and len(all_ids) == 71, 'catalog case identity')
    runtime_report, evidence = validate_runtime(runtime)
    setup_report, setup_evidence = validate_setup(setup)
    require(setup_report.get('runtime_report_sha256') == sha(safe_read(runtime, 'report.json')),
            'setup runtime report binding')
    cases = []
    assessments = {row['id']: row for row in contract['assessments']}
    for row in rows:
        ident = row['id']
        if ident in ASSESSMENTS:
            assessment = assessments[ident]
            cases.append({'id': ident, 'source': row['source'], 'status': assessment['status'],
                          'claim': assessment['claim'], 'evidence': evidence[ident]})
        else:
            require(ident in setup_evidence, 'missing setup case evidence')
            item = setup_evidence[ident]
            cases.append({'id': ident, 'source': row['source'], 'status': 'PASS',
                          'claim': item['claim'], 'evidence': item['evidence']})
    require(len(setup_evidence) == 58 and sum(row['status'] == 'PASS' for row in cases) == 71
            and not any(row['status'] == 'PARTIAL' for row in cases), 'case result counts')
    return {
        'schema_version': 1,
        'kind': 'mcp-proposal-case-runtime-evidence',
        'status': 'EVIDENCE_CHECKED',
        'historical_catalog': {'NOT_RUN': 71},
        'runtime_case_counts': {'PASS': 71, 'PARTIAL': 0, 'NOT_RUN': 0},
        'external_review': 'NOT_PERFORMED',
        'adoption': 'PROPOSAL_NOT_ADOPTED',
        'conformance': 'NOT_ESTABLISHED',
        'contract_sha256': sha(contract_raw),
        'runtime_report_sha256': sha(safe_read(runtime, 'report.json')),
        'setup_report_sha256': sha(safe_read(setup, 'report.json')),
        'runtime_inspector_revision': runtime_report.get('inspector_revision'),
        'cases': cases,
        'limitation': 'All 71 proposal cases have selected implementation, interoperability or policy evidence; external review, normative adoption and full protocol conformance remain unestablished.'
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--setup', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        runtime = args.runtime.resolve(strict=True)
        setup = args.setup.resolve(strict=True)
        output = args.output.resolve()
        require(runtime.is_dir() and setup.is_dir(), 'evidence directories')
        require(not output.exists() and not output.is_relative_to(ROOT), 'use a new external output directory')
        report = inspect(runtime, setup)
        output.mkdir(parents=True, exist_ok=False)
        (output / 'contract.json').write_bytes(CONTRACT.read_bytes())
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print('MCP case evidence FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('MCP case evidence checked: 71 PASS, 0 PARTIAL, 0 NOT_RUN; conformance NOT_ESTABLISHED.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
