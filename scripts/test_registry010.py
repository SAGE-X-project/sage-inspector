"""Safe local core execution with synthetic trusted sources and real durable journals.

No network resolver, remote target, host bypass or full-record proof claim.
"""
import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import platform
import select
import subprocess
import tempfile
from test_record010_adapters import PINS

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if ROOT / 'docs/evidence' in (output, *output.parents):
        parser.error('preserve historical evidence')
    output.mkdir(parents=True, exist_ok=False)
    fixture_path = ROOT / 'vectors/0.10.0/registry010.json'
    fixture = json.loads(fixture_path.read_text())
    programs = {name: getattr(args, name).resolve() for name in PINS}
    report = dict(kind='registry010-core-bindings', status='RUNNING', conformance='NOT_ESTABLISHED',
                  source='synthetic trusted Source and Clock; no live finality or proof measurement',
                  fixture_sha256=digest(fixture_path), platform=platform.platform(),
                  inspector_revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  subjects={}, scenarios=[], restarts=[], controls=[], raw=[])

    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    def execute(name, label, journal, mode, requests, expected=None, invalid=False):
        envelopes = [dict(id=str(i), request=q) for i, q in enumerate(requests)]
        wire = ''.join(json.dumps(q) + '\n' for q in envelopes)
        raw = dict(id=label, subject=name, mode=mode, input=envelopes,
                   input_sha256=hashlib.sha256(wire.encode()).hexdigest())
        report['raw'].append(raw)
        save()
        try:
            p = subprocess.run([str(programs[name]), str(journal), mode], input=wire,
                               capture_output=True, text=True, timeout=15)
            raw.update(exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr)
        except subprocess.TimeoutExpired as error:
            raw.update(timeout=True, stdout=str(error.stdout), stderr=str(error.stderr))
            raise
        finally:
            save()
        if invalid:
            assert p.returncode == 2 and not p.stdout, raw
        else:
            assert p.returncode == 0, raw
            actual = [json.loads(line) for line in p.stdout.splitlines()]
            assert len(actual) == len(requests) == len(expected), raw
            for i, (a, e) in enumerate(zip(actual, expected)):
                assert a == dict(id=str(i), **e), (label, i, a, e)
        raw['status'] = 'PASS'
        save()
        return label

    try:
        for name, program in programs.items():
            repo = ROOT.parent / ('sage' if name == 'go' else 'rs-sage-core')
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
            assert revision == PINS[name], (name, 'unreviewed core revision')
            assert not subprocess.check_output(['git', 'diff', 'HEAD', '--'], cwd=repo), 'changed core source'
            copied = repo / ('pkg/agent/registry010/testdata/gate.json' if name == 'go' else 'tests/fixtures/registry010.json')
            assert digest(copied) == digest(fixture_path), 'unit/runtime fixture mismatch'
            report['subjects'][name] = dict(revision=revision, executable_sha256=digest(program))
        assert len(fixture['cases']) == 39
        assert sum(len(c['steps']) for c in fixture['cases']) == 107
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            for name in programs:
                for case in fixture['cases']:
                    label = name + '-' + case['id']
                    execute(name, label, tmp / label, 'create', [s['request'] for s in case['steps']],
                            [s['expected'] for s in case['steps']])
                    report['scenarios'].append(label)
            base = copy.deepcopy(next(c for c in fixture['cases'] if c['id'] == 'kem-required')['steps'][0]['request'])
            did = base['did']
            inspect = dict(action='inspect', did=did)
            accept = dict(verdict='ACCEPT', output={})
            reject = dict(verdict='REJECT', output={})
            for writer, reader in itertools.product(programs, repeat=2):
                for terminal in (False, True):
                    label = f'{writer}-to-{reader}-' + ('tombstone' if terminal else 'rollback')
                    state = tmp / label
                    first = copy.deepcopy(base)
                    first.pop('signing_url'); first.pop('require_kem'); first['action'] = 'observe'
                    first['snapshot'].update(version='3', state='deactivated' if terminal else 'active', digest='33' * 32)
                    execute(writer, label + '-write', state, 'create', [first],
                            [dict(verdict='ACCEPT', output=dict(state=first['snapshot']['state'], version='3'))])
                    later = copy.deepcopy(base)
                    later['snapshot'].update(version='4' if terminal else '2', digest='44' * 32)
                    execute(reader, label + '-read', state, 'reopen', [later, inspect],
                            [reject, dict(verdict='ACCEPT', output=dict(highest_finalized_version='3', tombstone=terminal))])
                    report['restarts'].append(label)
            for name in programs:
                # A second process holds the real core journal lock while another attempts to open it.
                state = tmp / (name + '-exclusive')
                holder = subprocess.Popen([str(programs[name]), str(state), 'create'], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    holder.stdin.write(json.dumps(dict(id='ready', request=inspect)) + '\n'); holder.stdin.flush()
                    # A bounded subprocess consumes one readiness line; communicate below bounds cleanup.
                    readable, _, _ = select.select([holder.stdout], [], [], 10)
                    assert readable, 'writer did not become ready'
                    ready = holder.stdout.readline()
                    report['raw'].append(dict(id=name+'-lock-holder', subject=name, stdout=ready,
                                              input=[dict(id='ready', request=inspect)]))
                    assert json.loads(ready)['verdict'] == 'ACCEPT'
                    execute(name, name + '-second-writer', state, 'reopen', [], invalid=True)
                    report['controls'].append(name + '-second-writer')
                finally:
                    try:
                        tail, stderr = holder.communicate(timeout=10)
                        report['raw'].append(dict(id=name+'-lock-holder-close', stdout=tail, stderr=stderr, exit_code=holder.returncode))
                        assert holder.returncode == 0
                    except subprocess.TimeoutExpired:
                        holder.kill(); holder.communicate(); raise
                execute(name, name + '-clean-reopen', state, 'reopen', [dict(action='restart')], [accept])
                report['controls'].append(name + '-clean-reopen')
                for kind in ('missing', 'partial', 'blank'):
                    state = tmp / (name + '-' + kind)
                    if kind != 'missing':
                        state.write_bytes(b'sage-registry-watermarks|0.10.0\n' + (b'{"scope":' if kind == 'partial' else b'\n'))
                    execute(name, name + '-' + kind, state, 'reopen', [], invalid=True)
                    report['controls'].append(name + '-' + kind)
                for i, q in enumerate([{}, dict(action='observe'), dict(action='restart', expected={}),
                                       dict(base, times=[]), dict(base, clock_ok=None)]):
                    label = f'{name}-malformed-{i}'
                    execute(name, label, tmp / label, 'create', [q], invalid=True)
                    report['controls'].append(label)
                label = name + '-management-unsupported'
                execute(name, label, tmp / label, 'create', [dict(action='mutate')],
                        [dict(verdict='UNSUPPORTED', output={})])
                report['controls'].append(label)
        report['status'] = 'PASS'
    except Exception as error:
        report.update(status='FAIL', reason=str(error))
        raise
    finally:
        save()
    print('78 scenarios / 214 steps, 8 process restart combinations and 22 controls passed')


if __name__ == '__main__':
    main()
