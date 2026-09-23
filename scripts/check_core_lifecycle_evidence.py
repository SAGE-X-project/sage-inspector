"""Recheck saved, bounded INS-11 core lifecycle evidence without rerunning probes."""
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs/evidence/core-lifecycle'

GO_TESTS = (
    'TestRecord010CloseOpenOrder',
    'TestRecord010State',
    'TestMCPOwnerStaleSetupCompletionAfterReady',
    'TestMCPOwnerConcurrentCloseAndPublication',
    'TestMCPAdmissionCloseBeforeReservationHasNoEffects',
    'TestMCPAdmissionCloseDuringFence',
    'TestMCPAdmissionRequestExpiryClosesOwner',
    'TestMCPAdmissionProtectedDeadlineBeforeFinalAdmissionRetainsReservation',
    'TestReplayJournalVectors010',
    'TestReplayJournalFailures010',
)
RUST_TESTS = (
    'mcp_setup_stale_completion_after_ready_is_inert',
    'close_before_reservation_denies_with_zero_effects',
    'close_during_fence_preserves_actual_storage_outcome',
    'ready_session_expiry_denies_new_admission_and_closes_owner',
    'protected_deadline_before_final_admission_retains_identity_and_reservation',
    'owner_close_interrupts_native_client_receive_while_server_handler_remains_charged',
    'replay_journal010::tests::vectors',
    'replay_journal010::tests::faults',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(base, relative, expected_hash):
    require(type(relative) is str and relative and '..' not in Path(relative).parts,
            'invalid evidence path')
    path = base / relative
    require(path.resolve().is_relative_to(base.resolve()) and not path.is_symlink(),
            'evidence path escapes bundle')
    raw = path.read_bytes()
    require(len(raw) <= 2 * 1024 * 1024 and sha(raw) == expected_hash,
            'evidence file hash or size differs: ' + relative)
    return raw


def check(base=EVIDENCE):
    manifest = json.loads((base / 'manifest.json').read_text())
    require(manifest['kind'] == 'ins11-core-lifecycle'
            and manifest['status'] == 'EVIDENCE_CHECKED'
            and manifest['conformance'] == 'NOT_ESTABLISHED', 'manifest verdict')
    baseline = json.loads((ROOT / 'verification/0.10.0/normative-baseline-lock.json').read_text())
    require(manifest['spec_revision'] == baseline['spec']['revision'], 'spec revision')
    require(manifest['historical'] == {'legacy_go_close_race': 'FAIL',
                                      'rust_direct_concurrent_close': 'UNSUPPORTED',
                                      'lifecycle_catalog': {'NOT_RUN': 37}},
            'historical results were promoted')
    for language, tests in (('go', GO_TESTS), ('rust', RUST_TESTS)):
        row = manifest['subjects'][language]
        require(row['status'] == 'PASS' and row['test_exit_code'] == 0,
                'core test status: ' + language)
        compressed = read(base, row['log'], row['log_sha256'])
        log = gzip.decompress(compressed).decode()
        require(sha(log.encode()) == row['uncompressed_sha256'],
                'decompressed log hash: ' + language)
        if language == 'go':
            require(all('--- PASS: ' + name in log for name in tests)
                    and '--- FAIL:' not in log
                    and 'Secret (hex):' not in log
                    and log.count('\nPASS\n') == 3,
                    'Go core assertions or package results')
        else:
            require(all(any(name in line and line.endswith(' ... ok')
                            for line in log.splitlines()) for name in tests)
                    and 'test result: ok. 565 passed; 0 failed' in log,
                    'Rust core assertions or suite result')
    replay = manifest['replay']
    report = json.loads(read(base, replay['report'], replay['report_sha256']))
    require(report['kind'] == 'replay-journal010' and report['status'] == 'PASS'
            and report['conformance'] == 'NOT_ESTABLISHED'
            and len(report['scenarios']) == 24 and len(report['restarts']) == 20,
            'replay report claims')
    require(report['development'] is True
            and report['fixture_sha256'] == sha(
                (ROOT / 'vectors/0.10.0/replay-journal010.json').read_bytes())
            and all(row['tracked_diff_sha256'] == sha(b'')
                    for row in report['subjects'].values()),
            'replay fixture or source cleanliness')
    require({name: row['revision'] for name, row in report['subjects'].items()}
            == {name: row['revision'] for name, row in manifest['subjects'].items()},
            'replay/core revisions differ')
    raw = read(base, 'replay/' + report['raw'], report['raw_sha256'])
    require(raw.count(b'\n') >= 44, 'missing runtime process observations')
    require(len({row['id'] for row in report['scenarios']}) == 24
            and len({row['id'] for row in report['restarts']}) == 20,
            'duplicate replay case')
    for row in report['scenarios']:
        require(row['status'] == 'PASS', 'replay scenario failed')
        if row['journal'] is not None:
            read(base, 'replay/' + row['journal'], row['journal_sha256'])
    for row in report['restarts']:
        require(row['status'] == 'PASS', 'replay restart failed')
        read(base, 'replay/' + row['before'], row['before_sha256'])
        read(base, 'replay/' + row['after'], row['after_sha256'])
    return manifest


if __name__ == '__main__':
    checked = check()
    print(f"INS-11 core evidence checked: {checked['subjects']['go']['revision'][:12]} / "
          f"{checked['subjects']['rust']['revision'][:12]}; conformance NOT_ESTABLISHED")
