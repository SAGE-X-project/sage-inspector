"""Record Inspector contract tests separately from actual core evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
UNIT = (
    'test_session_expiry.py', 'test_recovery_inspection.py',
    'test_session_close_inspection.py', 'test_protocol_binding_inspection.py',
    'test_guard_gate_inspection.py', 'test_verification_report.py',
    'test_registry_source010.py', 'test_guard_integration.py',
)
RUNTIME = (
    ('test_guard_integration_runtime.py', ()),
    ('test_registry_source_runtime.py', ()),
    ('test_recovery_runtime.py', ('scenario',)),
    ('test_session_close_runtime.py', ('scenario',)),
    ('test_protocol_binding_runtime.py', ('primitive', 'scenario')),
    ('test_guard_gate_runtime.py', ('scenario',)),
)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_command(command, directory, label, timeout=300):
    """Bound a local test process group and preserve logs even after failure."""
    log = directory / (label + '.log')
    started = time.monotonic()
    result = dict(command=command, status='ERROR', exit_code=None, log=log.name)
    with log.open('xb') as stream:
        try:
            process = subprocess.Popen(command, cwd=ROOT, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                result['exit_code'] = process.wait(timeout=timeout)
                result['status'] = 'PASS' if process.returncode == 0 else 'FAIL'
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                result['status'] = 'TIMEOUT'
                result['reason'] = 'test process exceeded time limit'
        except OSError as error:
            result['reason'] = str(error)
    result.update(duration_seconds=round(time.monotonic() - started, 3),
                  log_sha256=sha256(log))
    return result


def summarize(results, expected):
    # Missing, skipped, or interrupted commands cannot yield success.
    return 'PASS' if expected > 0 and len(results) == expected and all(
        r['status'] == 'PASS' and r['exit_code'] == 0 for r in results
    ) else 'FAIL'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', required=True, type=Path)
    parser.add_argument('--primitive', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path,
                        help='fresh directory for test report and logs')
    args = parser.parse_args()
    binaries = {name: getattr(args, name).resolve() for name in ('scenario', 'primitive')}
    for binary in binaries.values():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error('required executable is unavailable: ' + str(binary))
    directory = args.output.resolve()
    if directory == ROOT or ROOT / 'docs/evidence' in (directory, *directory.parents):
        parser.error('test output must be separate from archived core evidence')
    try:
        directory.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error('output directory already exists')
    commands = [(name, 'unit', [sys.executable, str(ROOT/'scripts'/name)]) for name in UNIT]
    commands += [(name, 'scripted-cli', [sys.executable, str(ROOT/'scripts'/name),
                  *(str(binaries[key]) for key in keys)]) for name, keys in RUNTIME]
    report = dict(
        schema_version=1, kind='inspector-test-run', status='RUNNING',
        conformance='NOT_ESTABLISHED', actual_core_execution=False,
        purpose='Inspector contract tests with fixed observations and local scripted peers',
        started_at=datetime.now(timezone.utc).isoformat(),
        inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip(),
        working_tree_dirty=bool(subprocess.check_output(['git','status','--porcelain'], cwd=ROOT)),
        python=platform.python_version(), platform=platform.platform(),
        executables={key: dict(path=str(path), sha256=sha256(path)) for key,path in binaries.items()},
        input_hashes={str(p.relative_to(ROOT)): sha256(p) for folder in ('scripts','vectors/0.10.0')
                      for p in sorted((ROOT/folder).rglob('*')) if p.is_file() and '__pycache__' not in p.parts},
        expected_commands=len(commands), results=[],
    )
    output = directory/'report.json'

    def save():
        temporary = directory/'report.tmp'
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(output)

    save()
    for name, category, command in commands:
        result = run_command(command, directory, Path(name).stem)
        result.update(test_file=name, category=category)
        report['results'].append(result)
        save()
        print(name + ': ' + result['status'], flush=True)
    report.update(status=summarize(report['results'], len(commands)),
                  finished_at=datetime.now(timezone.utc).isoformat())
    save()
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
