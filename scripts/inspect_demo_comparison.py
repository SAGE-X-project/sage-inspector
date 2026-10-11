"""Observe the pinned sage-demo comparison of one workload with and without SAGE.

The demo runs a scripted agent that asks a tool host for one mock transfer,
once over unprotected MCP JSON-RPC and once through the sage-adk guardhost
caller and receiver, with the same relay fault in each scenario. This observer
builds the pinned demo, runs setup and every scenario in both modes as
separate processes, and checks every report against its own expectation of
what the ledger, the agent and the relay must show. It does not trust the
demo's own verdict fields. The SAGE run uses a synthetic Registry Source, an
accept-all measurement and one account, so the result is not Registry,
measurement, deployment or conformance evidence. Fresh observation needs a
clean pinned demo checkout and Linux arm64; it takes about seven minutes
because of the 360-second replay quarantine.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

from inspect_intent_issuance import require
from inspect_public_mcp_host import strict_json
from inspect_root_capture_parity import ROOT, NORMATIVE_REVISION, check_source, sha

DEMO_REVISION = 'c7e64adf486f394b2c9bdbefc4d95a83a742a831'
ADK_MODULE = 'v0.0.0-20261010085535-c7890e1ba443'
CORE_MODULE = 'v1.5.3-0.20261009164347-40809355bd4d'
COMPILER = 'go version go1.26.8 linux/arm64'
REPORT = ROOT / 'docs/evidence/demo-comparison.json'
STATUS = 'BOUNDED_DEMO_COMPARISON_OBSERVED'
SCOPE = {'workload': 'SCRIPTED_AGENT_MOCK_TRANSFER',
         'baseline': 'UNPROTECTED_MCP_JSON_RPC_LOOPBACK_TCP',
         'protected': 'ADK_GUARDHOST_PRIVATE_NATIVE_MCP_LOOPBACK_TCP',
         'faults': 'DEMO_RELAY_ON_LOOPBACK_ONLY',
         'processes': 'SEPARATE_PROCESSES_ONE_ACCOUNT_ONE_KERNEL',
         'signing_custody': 'SIGNER_PROCESSES_SAME_ACCOUNT',
         'policy_approval': 'EPHEMERAL_DEMO_OPERATOR_KEY',
         'registry': 'SYNTHETIC_FILE_SOURCE',
         'measurement': 'ACCEPT_ALL_FIXTURE',
         'refusal_stage': 'NOT_DISTINGUISHED_BY_HOST_ERROR',
         'provider_bindings': 'IDENTITY_AND_MEASUREMENT_NOT_BOUND',
         'deployed_host_controls': 'NOT_RUN',
         'universal_security_claim': 'NONE',
         'full_conformance': 'NOT_ESTABLISHED'}

MODES = ('baseline', 'sage')
SCENARIOS = ('normal', 'tamper-args', 'replay', 'unapproved', 'forge-result')
NORMAL_CALLS = 10
OPENING = 1000
CURRENCY = 'DEMO'
CAROL = 'did:sage:web:agent.example:carol'
MALLORY = 'did:sage:web:agent.example:mallory'
APPROVED = {'amount': 10, 'currency': CURRENCY, 'to': CAROL}
SUBSTITUTED = {'amount': 990, 'currency': CURRENCY, 'to': MALLORY}
FORGED = {'balance': 1000, 'transfer_id': 't-000999'}
# Observed with the pinned core and recorded by the demo: the frame that
# carries the call and the first frame that carries the result.
CALL_FRAME = {'baseline': 2, 'sage': 4}
RESULT_FRAME = {'baseline': 1, 'sage': 4}
QUARANTINE_MS = 360000
MAX_REPORT = 512 * 1024
DEMO_KEYS = {'name', 'mode', 'scenario', 'started', 'revisions', 'requested', 'calls', 'accepted',
             'relay_frames', 'fault_changed', 'ledger', 'harms', 'expected', 'as_expected',
             'mismatches', 'latency', 'notes'}
SYNTHETIC_NOTES = ('Registry Source is a local file', 'measurement accepts any snapshot',
                   'one account on one kernel', 'one error code for every refusal',
                   'not a conformance verdict')


def runs():
    """Every run the observation makes, in order."""
    return [(m, n, NORMAL_CALLS if n == 'normal' else 1) for m in MODES for n in SCENARIOS]


def demo(binary, args, timeout):
    done = subprocess.run([str(binary)] + args, capture_output=True, timeout=timeout)
    require(done.returncode == 0, 'demo ' + args[0] + ' exit: ' +
            done.stdout.decode(errors='replace')[-2000:] + done.stderr.decode(errors='replace')[-2000:])
    return done.stdout.decode()


def module_version(root, env, path):
    done = subprocess.run(['go', 'list', '-m', '-json', path], cwd=root, env=env,
                          capture_output=True, check=True, timeout=60)
    module = strict_json(done.stdout)
    require('Replace' not in module, 'pinned public module without replacement: ' + path)
    return module.get('Version')


def inspect(demo_root):
    require(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64'), 'Linux arm64 host')
    root = check_source(demo_root, DEMO_REVISION)
    require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'],
            cwd=root, text=True).strip(), 'untracked demo build inputs')
    env = os.environ.copy()
    env.update(GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOWORK='off', CGO_ENABLED='0')
    compiler = subprocess.check_output(['go', 'version'], env=env, text=True).strip()
    require(compiler == COMPILER, 'pinned native Go compiler')
    require(module_version(root, env, 'github.com/sage-x-project/sage-adk') == ADK_MODULE and
            module_version(root, env, 'github.com/sage-x-project/sage') == CORE_MODULE, 'pinned modules')
    with tempfile.TemporaryDirectory() as temp:
        binary = Path(temp) / 'demo'
        subprocess.run(['go', 'build', '-mod=readonly', '-o', str(binary), './cmd/demo'],
                       cwd=root, env=env, check=True, timeout=600)
        binary_sha = sha(binary.read_bytes())
        # Signer sockets live in the demo directory, so its path must be short.
        short = Path(tempfile.mkdtemp(prefix='sd.', dir='/tmp'))
        try:
            directory = short / 'd'
            demo(binary, ['setup', '-dir', str(directory)], 900)
            for mode, scenario, calls in runs():
                demo(binary, ['run', '-dir', str(directory), '-mode', mode, '-scenario', scenario,
                              '-calls', str(calls)], 300)
            compare = demo(binary, ['compare', '-dir', str(directory)], 60)
            reports = {p.stem: strict_json(p.read_bytes()) for p in (directory / 'reports').glob('*.json')}
        finally:
            shutil.rmtree(short)
    check_source(root, DEMO_REVISION)
    setup = reports.pop('setup', None)
    require(setup is not None and len(reports) == len(runs()), 'one report per run and a setup report')
    ordered = sorted(reports.values(), key=lambda r: r.get('name', ''))
    by_run = {(r.get('mode'), r.get('scenario')): r for r in ordered}
    report = {'schema_version': 1, 'kind': 'demo-comparison', 'protocol_version': '0.10.0',
              'normative_source_revision': NORMATIVE_REVISION, 'demo_revision': DEMO_REVISION,
              'adk_module': ADK_MODULE, 'core_module': CORE_MODULE, 'compiler': compiler,
              'kernel': platform.release(), 'binary_sha256': binary_sha, 'setup': setup,
              'runs': [by_run.get((m, n)) for m, n, _ in runs()], 'compare': compare,
              'status': STATUS, 'scope': dict(SCOPE)}
    check_report(report)
    return report


def entry(index, transfer):
    return {'id': 't-%06d' % index, 'amount': transfer['amount'], 'currency': CURRENCY, 'to': transfer['to']}


def results(ledger):
    """The result the tool returns after each ledger entry."""
    balance, out = OPENING, []
    for e in ledger:
        balance -= e['amount']
        out.append({'balance': balance, 'transfer_id': e['id']})
    return out


def check_common(r, mode, scenario, calls):
    require(type(r) is dict, 'demo report object')
    keys = set(r) - {'replay', 'setup'}
    require(keys == DEMO_KEYS, 'closed demo report: ' + ','.join(sorted(set(r) ^ DEMO_KEYS)))
    require(r['mode'] == mode and r['scenario'] == scenario, 'report for the run')
    require(r['revisions'] == {'spec': NORMATIVE_REVISION, 'adk': ADK_MODULE, 'core': CORE_MODULE,
                               'demo': DEMO_REVISION, 'go': 'go1.26.8'}, 'clean pinned revisions in the report')
    requested = SUBSTITUTED if scenario == 'unapproved' else APPROVED
    require(r['requested'] == requested, 'requested transfer')
    require(type(r['calls']) is list and len(r['calls']) == calls, 'call count')
    for c in r['calls']:
        require(type(c) is dict and set(c) <= {'result', 'error', 'elapsed_ms'} and
                type(c.get('elapsed_ms')) in (int, float) and c['elapsed_ms'] >= 0 and
                (('result' in c) != ('error' in c)), 'call outcome')
    require(type(r['ledger']) is list and type(r['relay_frames']) is list and
            type(r['fault_changed']) is list and type(r['harms']) is list, 'report lists')
    notes = r['notes']
    require(type(notes) is list and all(type(n) is str for n in notes), 'notes')
    if mode == 'sage':
        require(all(any(s in n for n in notes) for s in SYNTHETIC_NOTES), 'stated synthetic limits')
    require(r['as_expected'] is True and r['mismatches'] == [], 'demo reports no mismatch')
    for f in r['relay_frames']:
        require(type(f) is dict and set(f) == {'requests', 'responses'} and
                all(type(v) is int and v >= 0 for v in f.values()), 'relay frames')
    for c in r['fault_changed']:
        require(type(c) is dict and set(c) == {'direction', 'index'} and
                c['direction'] in ('request', 'response') and type(c['index']) is int, 'fault change')


def check_run(r, mode, scenario, calls):
    """Check one run against this observer's own expectation."""
    check_common(r, mode, scenario, calls)
    accepted = [c['result'] for c in r['calls'] if 'result' in c]
    refused = [c for c in r['calls'] if 'error' in c]
    ledger, changed, frames = r['ledger'], r['fault_changed'], r['relay_frames']
    first = frames[0] if frames else {'requests': 0, 'responses': 0}
    replay = r.get('replay')
    require(scenario == 'replay' or replay is None, 'replay outcome only in replay')
    harmed = bool(r['harms'])
    if scenario == 'normal':
        want = [entry(i + 1, APPROVED) for i in range(calls)]
        require(ledger == want and accepted == results(want) and not refused and not changed and not harmed,
                mode + ' normal: every call ran once and was accepted with its own result')
    elif scenario == 'tamper-args':
        require(changed == [{'direction': 'request', 'index': CALL_FRAME[mode]}], mode + ' tamper-args: call frame changed')
        if mode == 'baseline':
            require(ledger == [entry(1, SUBSTITUTED)] and accepted == results(ledger) and harmed,
                    'baseline tamper-args: the substituted transfer ran')
        else:
            require(ledger == [] and refused and not accepted and not harmed and
                    first['responses'] >= CALL_FRAME[mode], 'sage tamper-args: refused after reaching the call frame')
    elif scenario == 'replay':
        require(not changed and type(replay) is dict and set(replay) == {'answered_frames'}, mode + ' replay outcome')
        if mode == 'baseline':
            want = [entry(1, APPROVED), entry(2, APPROVED)]
            require(ledger == want and replay['answered_frames'] == 2 and accepted == results(want)[:1] and harmed,
                    'baseline replay: the resent call ran again')
        else:
            want = [entry(1, APPROVED)]
            require(ledger == want and replay['answered_frames'] == 0 and accepted == results(want) and not harmed,
                    'sage replay: the resent connection got no answer')
    elif scenario == 'unapproved':
        require(not changed, mode + ' unapproved: no fault')
        if mode == 'baseline':
            require(ledger == [entry(1, SUBSTITUTED)] and accepted == results(ledger) and harmed,
                    'baseline unapproved: the unapproved transfer ran')
        else:
            require(ledger == [] and refused and not accepted and not harmed and
                    all(f['requests'] == 0 for f in frames), 'sage unapproved: refused before any request frame')
    elif scenario == 'forge-result':
        require(changed and all(c['direction'] == 'response' and c['index'] >= RESULT_FRAME[mode] for c in changed) and
                ledger == [entry(1, APPROVED)], mode + ' forge-result: the call ran once and a result frame changed')
        if mode == 'baseline':
            require(changed == [{'direction': 'response', 'index': RESULT_FRAME[mode]}] and
                    accepted == [FORGED] and harmed, 'baseline forge-result: the agent accepted the forged result')
        else:
            require(refused and not accepted and not harmed, 'sage forge-result: the agent refused the result')
    require(harmed == (mode == 'baseline' and scenario != 'normal'), 'harm only in baseline fault runs')


def check_report(report):
    require(type(report) is dict and set(report) == {'schema_version', 'kind', 'protocol_version',
            'normative_source_revision', 'demo_revision', 'adk_module', 'core_module', 'compiler', 'kernel',
            'binary_sha256', 'setup', 'runs', 'compare', 'status', 'scope'}, 'closed comparison report')
    require(len(json.dumps(report)) <= MAX_REPORT, 'bounded report')
    require(report['schema_version'] == 1 and type(report['schema_version']) is int and
            report['kind'] == 'demo-comparison' and report['protocol_version'] == '0.10.0' and
            report['normative_source_revision'] == NORMATIVE_REVISION and report['demo_revision'] == DEMO_REVISION and
            report['adk_module'] == ADK_MODULE and report['core_module'] == CORE_MODULE and
            report['compiler'] == COMPILER and report['status'] == STATUS and report['scope'] == SCOPE,
            'pinned revisions and bounded comparison scope')
    require(type(report['kernel']) is str and re.fullmatch(r'[0-9][0-9A-Za-z.+_-]{0,63}', report['kernel']),
            'kernel release')
    require(type(report['binary_sha256']) is str and re.fullmatch('[0-9a-f]{64}', report['binary_sha256']),
            'binary hash')
    setup = report['setup']
    check_run(setup, 'sage', 'normal', 1)
    require(setup['name'] == 'setup' and type(setup.get('setup')) is dict and
            set(setup['setup']) == {'quarantine_wait_ms', 'total_ms'} and
            setup['setup']['quarantine_wait_ms'] >= QUARANTINE_MS and
            setup['setup']['total_ms'] >= setup['setup']['quarantine_wait_ms'],
            'setup waited out the replay quarantine before its warm-up call')
    require(type(report['runs']) is list and len(report['runs']) == len(runs()), 'every run')
    for r, (mode, scenario, calls) in zip(report['runs'], runs()):
        check_run(r, mode, scenario, calls)
        require('setup' not in r, 'setup cost only in the setup report')
    compare = report['compare']
    require(type(compare) is str and len(compare) < 8192 and
            not any(s in compare for s in ('DIFFERS', 'not run', 'setup failed')) and
            'not a conformance verdict' in compare, 'comparison output')
    latency = {m: report['runs'][MODES.index(m) * len(SCENARIOS)]['latency'] for m in MODES}
    for value in latency.values():
        require(type(value) is dict and set(value) == {'min_ms', 'median_ms', 'max_ms'} and
                0 <= value['min_ms'] <= value['median_ms'] <= value['max_ms'], 'latency summary')
    return {'status': report['status'], 'demo_revision': report['demo_revision'][:12], 'runs': len(report['runs']),
            'baseline_harmed': sum(bool(r['harms']) for r in report['runs'][:len(SCENARIOS)]),
            'sage_harmed': sum(bool(r['harms']) for r in report['runs'][len(SCENARIOS):]),
            'normal_median_ms': {m: latency[m]['median_ms'] for m in MODES},
            'setup_wait_ms': setup['setup']['quarantine_wait_ms']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo-root', type=Path)
    parser.add_argument('--report', type=Path, default=REPORT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output and not args.demo_root:
        parser.error('fresh execution required for output')
    report = inspect(args.demo_root) if args.demo_root else strict_json(args.report.read_bytes())
    summary = check_report(report)
    if args.output:
        with open(args.output, 'x') as out:
            out.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
