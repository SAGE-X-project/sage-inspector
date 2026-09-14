"""Collect a bounded legacy API diagnostic, retaining failed process evidence."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate(stdout, stderr, returncode, timed_out, mode):
    # A race detector/process failure is never converted to a successful rejection.
    if timed_out:
        return dict(status='FAIL', reason='TIMEOUT', completed_rounds=0, overlapping_rounds=0)
    if returncode != 0:
        reason = 'DATA_RACE' if 'WARNING: DATA RACE' in stderr else 'PROCESS_FAILURE'
        return dict(status='FAIL', reason=reason, completed_rounds=0, overlapping_rounds=0)
    try:
        from integrate_evidence import decode
        rows = [decode(line) for line in stdout.splitlines()]
        expected = [(d, n) for d in ('c2s', 's2c') for n in range(1 if mode == 'control' else 16)]
        if len(rows) != len(expected):
            raise ValueError('round count')
        overlap = 0
        for row, (direction, number) in zip(rows, expected):
            if (row['mode'], row['direction'], row['round'], row['participants']) != (mode, direction, number, 9):
                raise ValueError('round identity')
            workers = row['workers']
            if len(workers) != 8:
                raise ValueError('worker count')
            closing = row['close']
            observations = workers + [closing, row['fresh_control'], row['after_close']]
            for item in observations:
                if set(item) != {'index', 'started_ns', 'finished_ns', 'verdict', 'plaintext_hex'}:
                    raise ValueError('observation fields')
                if any(type(item[k]) is not int for k in ('index', 'started_ns', 'finished_ns')) or not 0 < item['started_ns'] <= item['finished_ns']:
                    raise ValueError('invalid time')
            if closing['index'] != 8 or closing['verdict'] != 'ACCEPT' or closing['plaintext_hex'] != '':
                raise ValueError('close result')
            fresh, after = row['fresh_control'], row['after_close']
            if fresh['index'] != 8 or fresh['verdict'] != 'ACCEPT' or fresh['plaintext_hex'] != '09':
                raise ValueError('positive control')
            if after['index'] != 8 or after['verdict'] != 'REJECT' or after['plaintext_hex'] != '' or after['started_ns'] < max(x['finished_ns'] for x in workers + [closing]):
                raise ValueError('post-close control')
            hit = False
            for i, item in enumerate(workers):
                if item['index'] != i or item['started_ns'] < fresh['finished_ns']:
                    raise ValueError('worker identity/order')
                if item['verdict'] == 'ACCEPT':
                    if item['plaintext_hex'] != bytes([i+1]).hex() or item['started_ns'] >= closing['finished_ns']:
                        raise ValueError('invalid acceptance')
                elif item['verdict'] != 'REJECT' or item['plaintext_hex'] != '' or mode == 'control':
                    raise ValueError('invalid rejection')
                if mode == 'control' and item['finished_ns'] > closing['started_ns']:
                    raise ValueError('unordered control')
                hit |= item['started_ns'] < closing['finished_ns'] and closing['started_ns'] < item['finished_ns']
            overlap += hit
        if stderr:
            raise ValueError('unexpected stderr')
        status = 'PASS' if mode == 'control' or overlap == len(rows) else 'INCOMPLETE'
        return dict(status=status, reason='BOUNDED_OBSERVATION' if status == 'PASS' else 'MISSING_CLOSE_OVERLAP', completed_rounds=len(rows), overlapping_rounds=overlap)
    except (ValueError, KeyError, TypeError):
        return dict(status='FAIL', reason='INVALID_OBSERVATION', completed_rounds=0, overlapping_rounds=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    probe = args.probe.resolve()
    lock = json.loads((ROOT/'docs/evidence/core-source-lock.json').read_text())
    for core in lock['cores']:
        repo = ROOT.parent/core['repository']
        if subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip() != core['revision']:
            raise ValueError('core revision changed')
        for path, digest in core['source_file_sha256'].items():
            if sha(repo/path) != digest:
                raise ValueError('core source changed: '+path)
    build = subprocess.check_output(['go', 'version', '-m', str(probe)], text=True)
    if '\tbuild\t-race=true' not in build:
        raise ValueError('probe must be built with -race')
    binary_hash = sha(probe)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, GORACE='halt_on_error=0 exitcode=66', GOMAXPROCS='8')
    runs = []
    for mode in ('control', 'race'):
        if sha(probe) != binary_hash:
            raise ValueError('probe changed')
        timeout = False
        try:
            result = subprocess.run([str(probe), '-mode', mode], capture_output=True, timeout=30, env=env)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, timeout = error.stdout or b'', error.stderr or b'', None, True
        for label, data in [('stdout', stdout), ('stderr', stderr)]:
            (args.output_dir/(mode+'.'+label)).write_bytes(data)
        verdict = evaluate(stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace'), code, timeout, mode)
        runs.append(dict(mode=mode, returncode=code, timed_out=timeout, **verdict))
    report = dict(schema_version=1, protocol_version='0.10.0', conformance='NOT_ESTABLISHED',
                  scope='Legacy Go close/receive API safety diagnostic; not a normative protocol verdict',
                  created=datetime.now(timezone.utc).isoformat(), environment=platform.platform(),
                  executable_sha256=binary_hash, go_build_info=build,
                  environment_controls={k:env[k] for k in ('GORACE','GOMAXPROCS')},
                  core_revisions={c['repository']:c['revision'] for c in lock['cores']}, runs=runs,
                  go_status='FAIL' if any(r['status']=='FAIL' for r in runs) else 'INCOMPLETE' if any(r['status']=='INCOMPLETE' for r in runs) else 'PASS',
                  rust_status='UNSUPPORTED', rust_reason='close(&mut self) requires exclusive ownership; manager removal does not close retained Arc handles')
    (args.output_dir/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('go_status','rust_status','conformance')}))
    return 1 if report['go_status']=='FAIL' else 3

if __name__ == '__main__':
    sys.exit(main())
