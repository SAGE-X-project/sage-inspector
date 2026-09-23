"""Audit the pinned MCP owner/admission source and selected runtime contract."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'verification/0.10.0/mcp-owner-admission-contract.json'
BOUNDARIES = {'durable-admission', 'close-linearization', 'owner-isolation', 'output-publication',
              'ready-past-setup', 'stale-setup-completion', 'close-before-reservation'}
LANGUAGES = {'go', 'rust'}
SOURCE_FILES = {
    'go': {
        'pkg/agent/guard010/mcp_admission.go', 'pkg/agent/guard010/mcp_owner.go',
        'pkg/agent/guard010/mcp_protected_reply.go', 'pkg/agent/guard010/mcp_admission_test.go',
        'pkg/agent/guard010/mcp_owner_test.go', 'pkg/agent/guard010/mcp_protected_reply_test.go'},
    'rust': {
        'src/guard010/mcp_setup.rs', 'src/guard010/dispatch/mcp_admission.rs',
        'src/guard010/dispatch/mcp_admission/reply.rs',
        'src/hpke/completion010/mcp_admission_tests.rs',
        'src/hpke/completion010/mcp_reply_tests.rs',
        'src/hpke/completion010/mcp_setup_tests.rs'},
}
SELECTED_TESTS = {
    'go': {
        'TestMCPAdmissionAuthenticatedExecutionAndDuplicate', 'TestMCPAdmissionCloseDuringFence',
        'TestMCPAdmissionCloseAfterInsertionKeepsAdmission', 'TestMCPAdmissionSharedOwners',
        'TestMCPAdmissionCrashRecoveryDoesNotExecuteAgain',
        'TestMCPAdmissionProtectedDeadlineBeforeFinalAdmissionRetainsReservation',
        'TestMCPAdmissionReadySessionExpiryDeniesNewAdmission',
        'TestMCPOwnerBlockedSendDoesNotBlockClose',
        'TestMCPProtectedReplyCloseDoesNotReleaseBlockedOutput',
        'TestMCPProtectedReplyDeadlineAfterAdmissionRetainsCompletion',
        'TestMCPOwnerSetupAndRetainedHistory',
        'TestMCPOwnerStaleSetupCompletionAfterReady',
        'TestMCPAdmissionCloseBeforeReservationHasNoEffects'},
    'rust': {
        'hpke::completion010::tests::mcp_admission_tests::admission_fences_before_effects_and_gate_close_cancels_unclaimed_work',
        'hpke::completion010::tests::mcp_admission_tests::admitted_worker_persists_signed_result_once_and_duplicate_never_runs',
        'hpke::completion010::tests::mcp_admission_tests::close_during_post_fence_callback_denies_and_retains_history',
        'hpke::completion010::tests::mcp_admission_tests::capacity_is_shared_across_connections_and_retained_during_actual_run',
        'hpke::completion010::tests::mcp_admission_tests::crash_recovery_marks_admission_unknown_and_never_executes_again',
        'hpke::completion010::tests::mcp_admission_tests::protected_deadline_before_final_admission_retains_identity_and_reservation',
        'hpke::completion010::tests::mcp_admission_tests::ready_session_expiry_denies_new_admission_and_closes_owner',
        'hpke::completion010::tests::mcp_admission_tests::mcp_reply_tests::failed_reply_does_not_erase_execution_or_allow_second_response',
        'hpke::completion010::tests::mcp_admission_tests::mcp_reply_tests::close_after_durable_acceptance_suppresses_output_and_reopen_cannot_redeliver',
        'hpke::completion010::tests::mcp_admission_tests::mcp_reply_tests::protected_deadline_after_admission_fails_transport_without_rollback',
        'hpke::completion010::tests::mcp_setup_tests::mcp_setup_ready_past_setup_deadline_uses_protected_limits',
        'hpke::completion010::tests::mcp_setup_tests::mcp_setup_stale_completion_after_ready_is_inert',
        'hpke::completion010::tests::mcp_admission_tests::close_before_reservation_denies_with_zero_effects'},
}
TEST_MAPPING_HASHES = {
    'go': '8dc2a89d59a2e0ab0585e3ddbbceec70569188d6b5db409e0c9fca544ba6b0d4',
    'rust': '1509ba0e4fa03111e33b655c928cfd0c774b9ae6cd7432a093534c432a597914',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def load(raw):
    return json.loads(raw, object_pairs_hook=lambda pairs: _object(pairs))


def _object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), 'unexpected fields')


def read(root, relative):
    path = root / relative
    require(path.resolve().is_relative_to(root.resolve()), 'path escapes checkout')
    require(not path.is_symlink(), 'source is a symlink')
    raw = path.read_bytes()
    require(len(raw) <= 1024 * 1024, 'source size limit')
    return raw


def validate(contract):
    exact(contract, ('schema_version', 'protocol_version', 'kind', 'conformance', 'boundaries', 'cores'))
    require(type(contract['schema_version']) is int and contract['schema_version'] == 1, 'schema version')
    require(contract['protocol_version'] == '0.10.0', 'protocol version')
    require(contract['kind'] == 'mcp-owner-admission-contract', 'contract kind')
    require(contract['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')
    require(type(contract['boundaries']) is list and len(contract['boundaries']) == len(BOUNDARIES), 'boundary count')
    found = set()
    for boundary in contract['boundaries']:
        exact(boundary, ('id', 'contract'))
        require(boundary['id'] in BOUNDARIES and boundary['id'] not in found, 'boundary identity')
        require(type(boundary['contract']) is str and 40 <= len(boundary['contract']) <= 500, 'boundary text')
        found.add(boundary['id'])
    require(set(contract['cores']) == LANGUAGES, 'core languages')
    coverage = {language: set() for language in LANGUAGES}
    for language, core in contract['cores'].items():
        exact(core, ('revision', 'files', 'tests'))
        require(re.fullmatch('[0-9a-f]{40}', core['revision']) is not None, 'core revision')
        require(type(core['files']) is dict and set(core['files']) == SOURCE_FILES[language], 'source inventory')
        for path, digest in core['files'].items():
            require(type(path) is str and not path.startswith('/') and '..' not in Path(path).parts, 'source path')
            require(re.fullmatch('[0-9a-f]{64}', digest) is not None, 'source digest')
        require(type(core['tests']) is dict and set(core['tests']) == SELECTED_TESTS[language], 'test inventory')
        encoded = json.dumps(core['tests'], sort_keys=True, separators=(',', ':')).encode()
        require(sha(encoded) == TEST_MAPPING_HASHES[language], 'changed test boundary mapping')
        for name, boundaries in core['tests'].items():
            require(type(name) is str and len(name) >= 20, 'test name')
            require(type(boundaries) is list and boundaries and len(boundaries) == len(set(boundaries)), 'test boundaries')
            require(set(boundaries) <= BOUNDARIES, 'unknown test boundary')
            coverage[language].update(boundaries)
        require(coverage[language] == BOUNDARIES, 'incomplete boundary coverage: ' + language)
    return contract


def audit(roots=None):
    raw = CONTRACT.read_bytes()
    contract = validate(load(raw))
    identities = {}
    for language, root in (roots or {}).items():
        require(language in LANGUAGES, 'unknown core')
        root = root.resolve(strict=True)
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root,
                                           text=True, timeout=10).strip()
        core = contract['cores'][language]
        require(revision == core['revision'], 'core revision mismatch: ' + language)
        for path, expected in core['files'].items():
            require(sha(read(root, path)) == expected, 'core source mismatch: ' + path)
        identities[language] = {'status': 'SOURCE_IDENTITY_VERIFIED', 'revision': revision}
    return {
        'schema_version': 1,
        'kind': 'mcp-owner-admission-audit',
        'status': 'PASS',
        'conformance': 'NOT_ESTABLISHED',
        'runtime': 'NOT_RUN',
        'contract_sha256': sha(raw),
        'boundary_count': len(BOUNDARIES),
        'selected_tests': {language: len(core['tests']) for language, core in contract['cores'].items()},
        'source_identity': {language: identities.get(language, {'status': 'NOT_CHECKED'}) for language in sorted(LANGUAGES)},
        'scope': 'Pinned private source and test mapping audit; runtime and protocol conformance require separate evidence.'
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path)
    parser.add_argument('--rust-root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        roots = {name: value for name, value in (('go', args.go_root), ('rust', args.rust_root)) if value}
        require(output != ROOT and not output.is_relative_to(ROOT), 'output inside Inspector')
        require(not output.exists(), 'output already exists')
        report = audit(roots)
        output.mkdir(parents=True, exist_ok=False)
        (output / 'contract.json').write_bytes(CONTRACT.read_bytes())
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(2, 'owner admission audit error: ' + str(error) + '\n')
    print('MCP owner admission contract audit PASS; runtime NOT_RUN; conformance NOT_ESTABLISHED.')


if __name__ == '__main__':
    main()
