"""Observe reviewed pinned ADK tests; test success is not protocol conformance."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import subprocess

from inspect_intent_issuance import canonical, require
from inspect_public_mcp_host import decode, strict_json
from inspect_root_capture_parity import ROOT, NORMATIVE_REVISION, check_source, sha

ADK_REVISION = '57f37e1c870d7bf1c5c6fdbd60efa1e62a6fcb6e'
GO_REVISION = 'f1a840bbc9c717564bd035e19c73f437a61e4a00'
GO_MODULE = {'Path': 'github.com/sage-x-project/sage',
             'Version': 'v1.5.3-0.20261008045438-f1a840bbc9c7',
             'Sum': 'h1:6zvAv5S9cF2FyKd0ixXNK5MKjuLa3jd8uSF2Cb8LyTY=',
             'GoModSum': 'h1:eXQo+9uD8oeOTlANkMsO+Yq5xDEMQKgAqk6lZ3GePy8='}
CATALOG = ROOT / 'verification/0.10.0/adk-runtime/catalog.json'
CATALOG_SHA256 = '90787e76fdd12948b19dce7a4cc9f93f485a9e3019ec512a9a63c686186ad2ad'
REPORT = ROOT / 'docs/evidence/adk-runtime.json'
SCOPE = {'test_execution': 'PINNED_ADK_TESTS_PASSED', 'registry': 'LOCAL_FIXTURE',
         'measurement': 'SYNTHETIC_PROVIDER', 'key_custody': 'FIXTURE',
         'hop_participants': 'CO_LOCATED_FIXTURE', 'effect': 'INERT_ARITHMETIC',
         'independent_protocol_oracle': 'NOT_RUN', 'deployed_host': 'NOT_RUN',
         'deployed_registry': 'NOT_RUN', 'full_conformance': 'NOT_ESTABLISHED'}
MAX_TRACE = 4 * 1024 * 1024


def catalog():
    raw = CATALOG.read_bytes()
    require(sha(raw) == CATALOG_SHA256, 'reviewed runtime catalog drift')
    value = strict_json(raw)
    require(value['adk_revision'] == ADK_REVISION, 'ADK catalog revision')
    return value


def source_at(root, review):
    root = check_source(root, ADK_REVISION)
    require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'],
            cwd=root, text=True).strip(), 'untracked ADK build inputs')
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')[:-1]
    require(sorted(tracked) == sorted(review['source_sha256']) and
            {p: sha((root / p).read_bytes()) for p in tracked} == review['source_sha256'],
            'complete tracked ADK source drift')
    # Ignored build sources could affect a compiler despite a clean Git status.
    ignored = subprocess.check_output(['git', 'ls-files', '--others', '--ignored',
                                      '--exclude-standard', '-z'], cwd=root).decode().split('\0')[:-1]
    require(not any(Path(p).suffix in ('.go', '.s', '.c', '.h', '.syso') for p in ignored),
            'ignored compiler inputs')
    return root


def command(group):
    names = sorted({name for tests in group['tests'].values() for name in tests})
    return ['go', 'test', '-json', '-race', '-count=1', '-parallel=1', '-timeout=180s',
            '-run', '^(' + '|'.join(names) + ')$', *group['packages']]


def trace_rows(hexadecimal):
    require(type(hexadecimal) is str and len(hexadecimal) <= MAX_TRACE * 2 and
            len(hexadecimal) % 2 == 0 and re.fullmatch('[0-9a-f]*', hexadecimal), 'bounded test trace hex')
    raw = bytes.fromhex(hexadecimal)
    require(raw and raw.endswith(b'\n'), 'complete test trace framing')
    rows = [strict_json(row) for row in raw.splitlines()]
    require(len(rows) <= 30000 and all(type(row) is dict for row in rows), 'bounded test events')
    return raw, rows


def check_trace(observation, group):
    require(type(observation) is dict and set(observation) == {'id', 'command', 'returncode',
            'stdout_hex', 'stdout_sha256', 'stderr_hex', 'stderr_sha256', 'module', 'modules_verified'},
            'closed ADK test observation')
    require(observation['id'] == group['id'] and observation['command'] == command(group) and
            type(observation['returncode']) is int and observation['returncode'] == 0 and
            observation['module'] == GO_MODULE and observation['modules_verified'] is True,
            'actual selected command and verified pinned module')
    raw, rows = trace_rows(observation['stdout_hex']); stderr = decode(observation['stderr_hex'])
    require(sha(raw) == observation['stdout_sha256'] and sha(stderr) == observation['stderr_sha256'] and
            not stderr, 'raw test logs and clean stderr')
    packages, tests = {}, {}
    for row in rows:
        action, package, name = row.get('Action'), row.get('Package'), row.get('Test')
        require(set(row) <= {'Time', 'Action', 'Package', 'Test', 'Elapsed', 'Output'} and
                {'Time', 'Action', 'Package'} <= set(row) and type(row['Time']) is str and
                bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}T[^\s]{8,40}', row['Time'])) and
                package in group['tests'] and action in ('start', 'run', 'output', 'pass', 'pause', 'cont'),
                'selected package events without failure or skip')
        if 'Elapsed' in row:
            require(type(row['Elapsed']) in (int, float) and math.isfinite(row['Elapsed']) and
                    0 <= row['Elapsed'] <= 180, 'bounded test duration')
        if action == 'start':
            require(name is None and package not in packages and 'Output' not in row,
                    'one package start')
            packages[package] = 'running'; continue
        require(packages.get(package) == 'running', 'event only within running package')
        if name is None:
            require(action in ('output', 'pass'), 'package event type')
            if action == 'pass':
                require('Elapsed' in row and 'Output' not in row and
                        all(state == 'passed' for (p, _), state in tests.items() if p == package),
                        'package completion after all tests')
                packages[package] = 'passed'
        else:
            require(type(name) is str and 1 <= len(name) <= 2048 and '\n' not in name and
                    name.split('/')[0] in group['tests'][package], 'selected test identity')
            identity = package, name
            if action == 'run':
                require(identity not in tests and 'Output' not in row, 'one actual test run')
                if '/' in name:
                    parents = [(n, state) for (p, n), state in tests.items()
                               if p == package and name.startswith(n + '/')]
                    require(parents and max(parents, key=lambda item: len(item[0]))[1]
                            in ('running', 'paused'), 'child test within actual parent: ' + name)
                tests[identity] = 'running'
            elif action == 'pause':
                require(tests.get(identity) == 'running', 'pause follows run'); tests[identity] = 'paused'
            elif action == 'cont':
                require(tests.get(identity) == 'paused', 'continue follows pause'); tests[identity] = 'running'
            elif action == 'pass':
                require(tests.get(identity) == 'running' and 'Elapsed' in row and 'Output' not in row and
                        all(state == 'passed' for (p, n), state in tests.items()
                            if p == package and n.startswith(name + '/')), 'one test completion after children')
                tests[identity] = 'passed'
            else:
                require(action == 'output' and tests.get(identity) in ('running', 'paused'),
                        'output inside actual test')
        if action == 'output':
            require(type(row.get('Output')) is str and row['Output'] and
                    '(cached)' not in row['Output'] and 'WARNING: DATA RACE' not in row['Output'],
                    'fresh noncached race-clean test output')
    require(set(packages) == set(group['tests']) and all(s == 'passed' for s in packages.values()),
            'all selected packages complete')
    for package, required in group['tests'].items():
        require({n for p, n in tests if p == package and '/' not in n} == set(required),
                'all reviewed top-level tests executed')
        for parent, children in group['children'].items():
            if parent in required:
                require({n for p, n in tests if p == package and n.startswith(parent + '/')} ==
                        {parent + '/' + child for child in children}, 'all reviewed native scenarios executed')
    require(all(state == 'passed' for state in tests.values()), 'all observed tests complete')
    return {'top_level_tests': sum(len(names) for names in group['tests'].values()),
            'leaf_tests': sum(not any(p == q and other.startswith(name + '/') for q, other in tests)
                              for p, name in tests), 'packages': len(packages)}


def module_at(directory, env):
    done = subprocess.run(['go', 'list', '-m', '-json', GO_MODULE['Path']], cwd=directory,
                          env=env, capture_output=True, timeout=60, check=True)
    module = strict_json(done.stdout)
    require('Replace' not in module and {k: module.get(k) for k in GO_MODULE} == GO_MODULE,
            'exact public Go dependency without replacement')
    verified = subprocess.run(['go', 'mod', 'verify'], cwd=directory, env=env,
                              capture_output=True, timeout=90, check=True)
    require(verified.stdout == b'all modules verified\n' and not verified.stderr, 'module cache integrity')
    return GO_MODULE.copy()


def inspect(adk_root):
    review = catalog(); root = source_at(adk_root, review)
    env = os.environ.copy()
    env.update(GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOPROXY='off', GOWORK='off')
    compiler = subprocess.check_output(['go', 'version'], env=env, text=True).strip()
    require(bool(re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)', compiler)),
            'pinned native Go compiler')
    cases = []
    for group in review['groups']:
        directory = root / group['directory']; module = module_at(directory, env)
        run = subprocess.run(command(group), cwd=directory, env=env, capture_output=True, timeout=240)
        observation = {'id': group['id'], 'command': command(group), 'returncode': run.returncode,
                       'stdout_hex': run.stdout.hex(), 'stdout_sha256': sha(run.stdout),
                       'stderr_hex': run.stderr.hex(), 'stderr_sha256': sha(run.stderr),
                       'module': module, 'modules_verified': True}
        try:
            check_trace(observation, group)
        except ValueError as error:
            raise ValueError(str(error) + ': ' + run.stderr.decode(errors='replace')[-1500:] +
                             run.stdout.decode(errors='replace')[-2500:]) from error
        source_at(root, review); module_at(directory, env)
        cases.append(observation)
    source_at(root, review); catalog()
    report = {'schema_version': 1, 'kind': 'pinned-adk-test-observation', 'protocol_version': '0.10.0',
              'normative_source_revision': NORMATIVE_REVISION, 'adk_revision': ADK_REVISION,
              'go_revision': GO_REVISION, 'catalog_sha256': CATALOG_SHA256,
              'source_sha256': review['source_sha256'], 'compiler': compiler,
              'status': 'PINNED_ADK_TESTS_PASSED', 'scope': SCOPE.copy(), 'cases': cases}
    check_report(report)
    return report


def check_report(report):
    review = catalog()
    require(type(report) is dict and set(report) == {'schema_version', 'kind', 'protocol_version',
            'normative_source_revision', 'adk_revision', 'go_revision', 'catalog_sha256',
            'source_sha256', 'compiler', 'status', 'scope', 'cases'}, 'closed ADK runtime report')
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and
            report['kind'] == 'pinned-adk-test-observation' and report['protocol_version'] == '0.10.0' and
            report['normative_source_revision'] == NORMATIVE_REVISION and report['adk_revision'] == ADK_REVISION and
            report['go_revision'] == GO_REVISION and report['catalog_sha256'] == CATALOG_SHA256 and
            report['source_sha256'] == review['source_sha256'] and
            type(report['compiler']) is str and re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)', report['compiler']) and
            report['status'] == 'PINNED_ADK_TESTS_PASSED' and report['scope'] == SCOPE,
            'reviewed source and bounded runtime scope')
    require(type(report['cases']) is list and len(report['cases']) == len(review['groups']),
            'all three ordered execution groups')
    results = [check_trace(case, group) for case, group in zip(report['cases'], review['groups'])]
    return {'top_level_tests': sum(r['top_level_tests'] for r in results),
            'leaf_tests': sum(r['leaf_tests'] for r in results), 'groups': len(results)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adk-root', type=Path); parser.add_argument('--report', type=Path, default=REPORT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output and not args.adk_root:
        parser.error('fresh execution required for output')
    report = inspect(args.adk_root) if args.adk_root else strict_json(args.report.read_bytes())
    summary = check_report(report)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(summary, status=report['status'])))


if __name__ == '__main__':
    main()
