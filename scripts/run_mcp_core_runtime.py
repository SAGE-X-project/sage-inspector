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

ROOT = Path(__file__).resolve().parents[1]
PINS = {'go': '872307563416f144cc863d26b594b0ce7da1f2bd',
        'rust': '8d91b2f85fb887f827bff752171315a57fd694ce'}
PREFIX = 'hpke::completion010::tests::mcp_admission_tests::mcp_reply_tests::mcp_transport_tests::'
CASES = {
    'go': ('TestMCPHostConnectionRuntime', 'TestMCPHostConnectionRetainsBlockedHandshake',
           'TestMCPHostConnectionRetainsSocketCleanup'),
    'rust': tuple(PREFIX + name for name in (
        'owned_tcp_listener_completes_real_handshake_setup_and_protected_exchange',
        'handshake_timeout_shuts_socket_but_retains_factory_and_fixed_worker_capacity',
        'failed_handshake_keeps_connection_slot_until_endpoint_cleanup_finishes')),
}


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
        ends = re.findall(r'^--- (PASS|FAIL|SKIP): (\S+) \(', text, re.M)
        return starts == [name] and ends == [('PASS', name)] and text.endswith('PASS\n')
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
        command = ([str(binary), '-test.run=^' + name + '$', '-test.v', '-test.timeout=25s']
                   if language == 'go' else [str(binary), name, '--exact', '--test-threads=1', '--color=never'])
        directory = source / 'pkg/agent/guard010' if language == 'go' else source
        row = run(command, directory, output / f'{language}-{index}.log', 30, env)
        row['test'] = name
        row['status'] = ('PASS' if row['status'] == 'PASS' and observed(
            language, name, (output / row['log']).read_text(), row['exit_code']) else 'FAIL')
        subject['cases'].append(row)
    return subject


def successful(subjects):
    return set(subjects) == set(CASES) and all(
        subjects[lang]['build']['status'] == 'PASS'
        and [r['test'] for r in subjects[lang]['cases']] == list(names)
        and all(r['status'] == 'PASS' for r in subjects[lang]['cases'])
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
    report = dict(kind='mcp-core-runtime-tests', status='FAIL',
                  conformance='NOT_ESTABLISHED', interoperability='NOT_RUN',
                  catalog=dict(NOT_RUN=71), mandatory_children='NOT_PROMOTED',
                  scope='Private core test assertions; no independent wire or journal audit',
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
