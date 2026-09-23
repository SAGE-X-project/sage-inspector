"""Run pinned private core tests; this is not an interoperability adapter."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import tarfile
import tempfile
import time

from check_mcp_owner_admission import load as load_owner_contract, validate as validate_owner_contract
from check_mcp_signature_boundary import CONTRACT as SIGNATURE_CONTRACT, contract as signature_contract

ROOT = Path(__file__).resolve().parents[1]
OWNER_CONTRACT = ROOT / 'verification/0.10.0/mcp-owner-admission-contract.json'
SETUP_CONTRACT = ROOT / 'verification/0.10.0/mcp-setup-case-contract.json'
PINS = {'go': '2322b2aa4b13ed41b2c5232a1d7382003ebee0e1',
        'rust': 'c89d1d5121b2c5ccb89b393ae0e32120de2f7726'}
PREFIX = 'hpke::completion010::tests::mcp_admission_tests::mcp_reply_tests::mcp_transport_tests::'
CASES = {
    'go': ('TestMCPHostConnectionRuntime', 'TestMCPHostConnectionRetainsBlockedHandshake',
           'TestMCPHostConnectionRetainsSocketCleanup'),
    'rust': tuple(PREFIX + name for name in (
        'owned_tcp_listener_completes_real_handshake_setup_and_protected_exchange',
        'handshake_timeout_shuts_socket_but_retains_factory_and_fixed_worker_capacity',
        'failed_handshake_keeps_connection_slot_until_endpoint_cleanup_finishes')),
}


# These are core-specific trusted schedules, not equivalent cross-core obligations.
SCHEDULES = {
    'go': {
        'TestMCPStreamRuntimeCancellation': 'Blocked pipe send/receive settles on cancellation or I/O timeout',
        'TestMCPHostQueuedCancellationAndBoundedStop': 'Cancelled queued work has no effect; stalled work remains charged until termination',
        'TestMCPHostIdleResponseExpiryPreservesCompletion': 'Response expiry closes the owner without changing the completed result',
        'TestMCPHostCleanupStallDoesNotBlockDeadlinesOrReleaseOwners': 'Stalled cleanup retains owner quota while another owner expires',
    },
    'rust': {PREFIX + name: claim for name, claim in (
        ('bounded_frame_reader_handles_benign_fragmentation_and_incomplete_frame_timeout',
         'Benign fragmented input completes; incomplete input times out and closes the socket'),
        ('framed_io_checks_original_clock_deadline_even_when_wall_time_remains',
         'Original trusted-clock deadline closes the socket despite remaining wall time'),
        ('owner_close_interrupts_native_client_receive_while_server_handler_remains_charged',
         'Owner close interrupts receive without client delivery; blocked server handler remains charged'),
        ('listener_shutdown_keeps_worker_quota_until_handler_dependencies_are_destroyed',
         'Listener shutdown retains worker quota until handler dependencies finish cleanup'),
    )},
}


def owner_contract():
    value = validate_owner_contract(load_owner_contract(OWNER_CONTRACT.read_bytes()))
    cores = value.get('cores')
    if set(cores or {}) != set(PINS):
        raise ValueError('owner admission core inventory')
    for language, pin in PINS.items():
        if cores[language].get('revision') != pin:
            raise ValueError('owner admission revision mismatch: ' + language)
    return value


OWNER_CONTRACT_CASES = {language: core['tests'] for language, core in owner_contract()['cores'].items()}
SIGNATURE_CONTRACT_CASES = {language: {test: boundary for boundary, test in core['tests'].items()}
                            for language, core in signature_contract()['cores'].items()}


def setup_contract():
    value = json.loads(SETUP_CONTRACT.read_text())
    if value.get('kind') != 'mcp-setup-case-contract' or set(value.get('cores', {})) != set(PINS):
        raise ValueError('setup case contract identity')
    for language, pin in PINS.items():
        if value['cores'][language].get('revision') != pin:
            raise ValueError('setup case revision mismatch: ' + language)
    return value


SETUP_VALUE = setup_contract()
SETUP_CONTRACT_CASES = {language: {} for language in PINS}
for assessment in SETUP_VALUE['assessments']:
    for requirement in assessment['requirements']:
        SETUP_CONTRACT_CASES[requirement['language']].setdefault(requirement['test'], []).append(assessment['id'])
GO_TEST_PACKAGES = SETUP_VALUE['cores']['go']['test_packages']


def unique(values):
    return tuple(dict.fromkeys(values))


CASES = {language: unique(names + tuple(SCHEDULES[language]) + tuple(OWNER_CONTRACT_CASES[language])
                          + tuple(SIGNATURE_CONTRACT_CASES[language])
                          + tuple(SETUP_CONTRACT_CASES[language]))
         for language, names in CASES.items()}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def run(command, cwd, log, timeout, env=None):
    start = time.monotonic()
    result = {'command': command, 'status': 'ERROR', 'exit_code': None,
              'log': log.name, 'cwd': str(cwd)}
    with log.open('xb') as output:
        try:
            p = subprocess.Popen(command, cwd=cwd, env=env, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            try:
                result['exit_code'] = p.wait(timeout=timeout)
                result['status'] = 'PASS' if p.returncode == 0 else 'FAIL'
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait()
                result['status'] = 'TIMEOUT'
        except OSError as e:
            result['error'] = str(e)
    result.update(log_sha256=digest(log), duration_seconds=round(time.monotonic()-start, 3))
    return result


def observed(language, name, text, code):
    """Zero selected tests, skips, duplicate records and failures never pass."""
    if code != 0:
        return False
    if language == 'go':
        starts = re.findall(r'^=== RUN   (\S+)\s*$', text, re.M)
        ends = re.findall(r'^\s*--- (PASS|FAIL|SKIP): (\S+) \(', text, re.M)
        expected = lambda value: value == name or value.startswith(name + '/')
        return (starts and starts[0] == name and len(starts) == len(set(starts))
                and all(expected(value) for value in starts)
                and len(ends) == len(starts)
                and all(status == 'PASS' and expected(value) for status, value in ends)
                and sum(value == name for _, value in ends) == 1 and text.endswith('PASS\n'))
    records = re.findall(r'^test (\S+) \.\.\. (\S+)\s*$', text, re.M)
    return records == [(name, 'ok')] and bool(re.search(
        r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', text, re.M))


def snapshot(repo, language, output, target):
    archive = output / (language + '-source.tar')
    with archive.open('xb') as f:
        subprocess.run(['git', '-C', str(repo), 'archive', '--format=tar', PINS[language]],
                       stdout=f, check=True, timeout=30)
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            path = target / member.name
            if (not path.resolve().is_relative_to(target.resolve())
                    or not (member.isdir() or member.isfile())):
                raise ValueError('unsupported archive entry')
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src, path.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                path.chmod(member.mode & 0o777)
    return {'revision': PINS[language], 'archive': archive.name,
            'archive_sha256': digest(archive)}


def execute(language, repo, output, work):
    source = work / language
    source.mkdir()
    subject = snapshot(repo, language, output, source)
    expected_files = SETUP_VALUE['cores'][language]['files']
    actual_files = {name: digest(source / name) for name in expected_files}
    if actual_files != expected_files:
        raise ValueError('setup case source drift: ' + language)
    subject['setup_case_files'] = actual_files
    binary = work / (language + '-mcp-tests')
    env = os.environ.copy()
    env['CARGO_TARGET_DIR'] = str(work / 'rust-target')
    if language == 'go':
        command = ['go', 'test', '-mod=readonly', '-race', '-c', '-o', str(binary), './pkg/agent/guard010']
    else:
        command = ['cargo', 'test', '--offline', '--lib', '--all-features', '--no-run', '--message-format=json']
    build = run(command, source, output / (language + '-build.log'), 600, env)
    subject.update(build=build, cases=[])
    if build['status'] != 'PASS':
        return subject
    go_hpke_binary = None
    if language == 'go':
        go_hpke_binary = work / 'go-hpke-tests'
        hpke_build = run(['go', 'test', '-mod=readonly', '-race', '-c', '-o',
                          str(go_hpke_binary), './pkg/agent/hpke'], source,
                         output / 'go-hpke-build.log', 600, env)
        subject['hpke_build'] = hpke_build
        if hpke_build['status'] != 'PASS':
            return subject
        subject['hpke_executable_sha256'] = digest(go_hpke_binary)
    if language == 'rust':
        artifacts = []
        for line in (output / build['log']).read_text().splitlines():
            if not line.startswith('{'):
                continue
            item = json.loads(line)
            if (item.get('reason') == 'compiler-artifact' and item.get('executable')
                    and item.get('profile', {}).get('test')
                    and item.get('target', {}).get('name') == 'sage_crypto_core'):
                artifacts.append(Path(item['executable']))
        if len(artifacts) != 1:
            raise ValueError('expected exactly one Rust core test executable')
        binary = artifacts[0]
    subject['executable_sha256'] = digest(binary)
    lock = source / ('go.sum' if language == 'go' else 'Cargo.lock')
    dependency = output / (language + '-dependencies.lock')
    dependency.write_bytes(lock.read_bytes())
    subject['dependencies'] = {'file': dependency.name, 'sha256': digest(dependency)}
    for index, name in enumerate(CASES[language]):
        selected_binary = (go_hpke_binary if language == 'go' and
                           (name.startswith('TestCompletion010') or GO_TEST_PACKAGES.get(name) == 'hpke') else binary)
        command = ([str(selected_binary), '-test.run=^' + name + '$', '-test.v', '-test.timeout=25s']
                   if language == 'go' else [str(binary), name, '--exact', '--test-threads=1', '--color=never'])
        directory = (source / ('pkg/agent/hpke' if selected_binary == go_hpke_binary
                               else 'pkg/agent/guard010') if language == 'go' else source)
        row = run(command, directory, output / f'{language}-{index}.log', 30, env)
        row['test'] = name
        row['execution_status'] = row['status']
        row['evidence_kind'] = 'pinned-core-assertions'
        if name in SCHEDULES[language]: row['schedule_assertion'] = SCHEDULES[language][name]
        if name in OWNER_CONTRACT_CASES[language]:
            row['owner_admission_boundaries'] = OWNER_CONTRACT_CASES[language][name]
        if name in SIGNATURE_CONTRACT_CASES[language]:
            row['signature_boundary'] = SIGNATURE_CONTRACT_CASES[language][name]
        if name in SETUP_CONTRACT_CASES[language]:
            row['setup_cases'] = SETUP_CONTRACT_CASES[language][name]
        row['status'] = ('PASS' if row['status'] == 'PASS' and observed(
            language, name, (output / row['log']).read_text(), row['exit_code']) else 'FAIL')
        subject['cases'].append(row)
    return subject


def successful(subjects):
    return set(subjects) == set(CASES) and all(
        subjects[lang]['build']['status'] == 'PASS'
        and (lang != 'go' or subjects[lang].get('hpke_build', {}).get('status') == 'PASS')
        and [r['test'] for r in subjects[lang]['cases']] == list(names)
        and all(r['status'] == 'PASS' for r in subjects[lang]['cases'])
        and all(r.get('owner_admission_boundaries') == OWNER_CONTRACT_CASES[lang][r['test']]
                for r in subjects[lang]['cases'] if r['test'] in OWNER_CONTRACT_CASES[lang])
        and all(r.get('signature_boundary') == SIGNATURE_CONTRACT_CASES[lang][r['test']]
                for r in subjects[lang]['cases'] if r['test'] in SIGNATURE_CONTRACT_CASES[lang])
        and all(r.get('setup_cases') == SETUP_CONTRACT_CASES[lang][r['test']]
                for r in subjects[lang]['cases'] if r['test'] in SETUP_CONTRACT_CASES[lang])
        for lang, names in CASES.items())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('go', 'rust', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    output = a.output.resolve()
    repos = [a.go.resolve(strict=True), a.rust.resolve(strict=True)]
    if any(output.is_relative_to(root) for root in [ROOT, *repos]):
        p.error('output must be new and outside Inspector and core repositories')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'runner.py').write_bytes(Path(__file__).read_bytes())
    (output / 'owner-admission-contract.json').write_bytes(OWNER_CONTRACT.read_bytes())
    (output / 'signature-boundary-contract.json').write_bytes(SIGNATURE_CONTRACT.read_bytes())
    (output / 'setup-case-contract.json').write_bytes(SETUP_CONTRACT.read_bytes())
    report = dict(kind='mcp-core-runtime-tests', status='FAIL',
                  conformance='NOT_ESTABLISHED', interoperability='NOT_RUN',
                  catalog=dict(NOT_RUN=71), mandatory_children='NOT_PROMOTED',
                  owner_admission_contract_sha256=digest(OWNER_CONTRACT),
                  signature_boundary_contract_sha256=digest(SIGNATURE_CONTRACT),
                  setup_case_contract_sha256=digest(SETUP_CONTRACT),
                  scope='Pinned private core assertions for owner, admission, signature and authenticated MCP setup cases; no protocol conformance claim',
                  runner_sha256=digest(Path(__file__)), subjects={})
    try:
        report['inspector_revision'] = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        report['inspector_dirty'] = bool(subprocess.check_output(
            ['git', 'status', '--porcelain'], cwd=ROOT, text=True))
        with tempfile.TemporaryDirectory(prefix='sage-mcp-runtime-') as tmp:
            for lang, repo in zip(('go', 'rust'), repos):
                report['subjects'][lang] = execute(lang, repo, output, Path(tmp))
        report['status'] = 'PASS' if successful(report['subjects']) else 'FAIL'
    except Exception as e:
        report['error'] = str(e)
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
