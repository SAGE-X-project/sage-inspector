"""Bounded real-core dispatch commitments; inert fixture sinks, no external tools."""
import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import platform
import subprocess
import tempfile
from test_record010_adapters import PINS
from test_guard_reservations010 import validate_journal, validate_reply

ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def expected_effect(envelope, instance):
    i = json.loads(envelope)['intent']
    return dict(instance=instance, envelope_hex=envelope.hex(),
                arguments_hex=json.dumps(i['arguments'], sort_keys=True, separators=(',', ':')).encode().hex(),
                tool=i['tool'], manifest_digest=i['manifest_digest'], intent_digest=sha(envelope))


def observation(ok=True, created=False, committed=False, state='', digest='', effects=None):
    return dict(ok=ok, created=created, committed=committed, state=state,
                intent_digest=digest, effects=[] if effects is None else effects)


def scenarios(f):
    env = bytes.fromhex(f['envelope_hex'])
    old, new = expected_effect(env, 'old'), expected_effect(env, 'new')
    config = dict(action='configure', input=f, instance='old')
    replace = dict(config, instance='new')
    dispatch = dict(action='dispatch', envelope_hex=f['envelope_hex'])
    retire = dict(action='retire')
    empty, denied = observation(), observation(ok=False)
    accepted = observation(created=True, committed=True, state='EXECUTING', digest=sha(env), effects=[old])
    retry = dict(accepted, created=False, committed=False)
    cases = [
        ('duplicate', [config, dispatch, dispatch], [empty, accepted, retry], ['RESERVED', 'EXECUTING']),
        ('retire-first', [config, retire, dispatch], [empty, empty, denied], []),
        ('dispatch-first', [config, dispatch, retire, dispatch],
         [empty, accepted, observation(effects=[old]), observation(ok=False, effects=[old])], ['RESERVED', 'EXECUTING']),
        ('replace-first', [config, replace, dispatch], [empty, empty, dict(accepted, effects=[new])], ['RESERVED', 'EXECUTING']),
        ('replace-after', [config, dispatch, replace, dispatch],
         [empty, accepted, observation(effects=[old]), retry], ['RESERVED', 'EXECUTING']),
        ('retire-replace', [config, retire, replace, dispatch], [empty, empty, denied, denied], []),
    ]
    for key, value in [('active_key', False), ('policy_allow', False), ('clock_trusted', False), ('now', 1700000300)]:
        q = copy.deepcopy(config)
        q['input'][key] = value
        cases.append((key, [q, dispatch], [empty, denied], []))
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('go', 'rust', 'output'):
        p.add_argument('--'+name, required=True, type=Path)
    p.add_argument('--development', action='store_true')
    args = p.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT/'docs/evidence'):
        p.error('preserve historical evidence')
    output.mkdir(parents=True, exist_ok=False)
    (output/'raw').mkdir()
    (output/'journals').mkdir()
    programs = {name: getattr(args, name).resolve(strict=True) for name in PINS}
    fixture_bytes = (ROOT/'vectors/0.10.0/guard-records.json').read_bytes()
    f = next(c['input'] for c in json.loads(fixture_bytes)['cases'] if c['id']=='intent-valid')
    envelope = bytes.fromhex(f['envelope_hex'])
    report = dict(kind='guard-dispatch-bindings', status='RUNNING', conformance='NOT_ESTABLISHED',
                  scope='Actual core serialized gate and inert bounded sink; not a deployed loader, tool execution, signed completion, host isolation or full lifecycle certification.',
                  development=args.development, platform=platform.platform(), fixture_sha256=sha(fixture_bytes),
                  inspector_revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  subjects={}, scenarios=[], restarts=[], controls=[], processes=0, files={})

    def save():
        (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')

    def retain(name, raw):
        (output/name).write_bytes(raw)
        report['files'][name] = sha(raw)
        save()

    def execute(name, label, path, mode, commands, expected, missing=False):
        wire = ''.join(json.dumps(q)+'\n' for q in commands)
        proc = subprocess.run([str(programs[name]), str(path), mode], input=wire, text=True, capture_output=True, timeout=20)
        report['processes'] += 1
        record = dict(subject=name, mode=mode, input=commands, input_sha256=sha(wire.encode()),
                      exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        retain('raw/'+label+'.json', (json.dumps(record, indent=2)+'\n').encode())
        if proc.returncode != (2 if missing else 0) or proc.stderr:
            raise ValueError('adapter failure: '+label)
        validate_reply([json.loads(line) for line in proc.stdout.splitlines()], expected)

    def snapshot(path, label, states):
        raw = path.read_bytes()
        retain('journals/'+label+'.journal', raw)
        validate_journal(raw, envelope, states)

    try:
        for name, pin in PINS.items():
            source = ROOT.parent/('sage' if name=='go' else 'rs-sage-core')
            actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
            if not args.development and actual != pin:
                raise ValueError('checkout does not match pin: '+name)
            report['subjects'][name] = dict(revision=actual, adapter_sha256=sha(programs[name].read_bytes()))
        with tempfile.TemporaryDirectory(prefix='guard-dispatch-') as tmp:
            root = Path(tmp)
            for name in programs:
                for label, commands, expected, states in scenarios(f):
                    label = name+'-'+label
                    path = root/label
                    execute(name, label, path, 'create', commands, expected)
                    snapshot(path, label, states)
                    report['scenarios'].append(dict(id=label, status='PASS'))
                label = name+'-missing'
                path = root/label
                execute(name, label, path, 'reopen', [dict(action='configure', input=f, instance='old')], [], True)
                if path.exists():
                    raise ValueError('lost ledger recreated')
                report['controls'].append(dict(id=label, status='PASS'))
            for writer, reader in itertools.product(programs, repeat=2):
                label = writer+'-to-'+reader
                path = root/label
                _, commands, expected, states = scenarios(f)[0]
                execute(writer, label+'-create', path, 'create', commands, expected)
                snapshot(path, label+'-before', states)
                recovered = observation(state='UNKNOWN', digest=sha(envelope))
                execute(reader, label+'-recover', path, 'reopen', commands, [observation(), recovered, recovered])
                snapshot(path, label+'-after', ['RESERVED', 'EXECUTING', 'UNKNOWN'])
                report['restarts'].append(dict(id=label, status='PASS'))
        report['status'] = 'PASS'
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as e:
        report.update(status='FAIL', error=str(e))
    save()
    print(json.dumps(dict(status=report['status'], processes=report['processes'], report=str(output/'report.json'))))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
