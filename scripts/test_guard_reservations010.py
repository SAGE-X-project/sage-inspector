"""Real signed Guard reservation and cross-core recovery with owned local files."""
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

ROOT = Path(__file__).resolve().parents[1]
HEADER = b'sage-execution-ledger|0.10.0\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_journal(raw, envelope, states):
    if not raw.startswith(HEADER) or not raw.endswith(b'\n'):
        raise ValueError('journal framing')
    rows = [json.loads(line) for line in raw[len(HEADER):].splitlines()]
    if len(rows) != len(states):
        raise ValueError('unexpected reservation or transition')
    intent = json.loads(envelope)['intent']
    for row, state in zip(rows, states):
        expected = {key: intent[key] for key in ('issuer', 'recipient', 'call_id', 'nonce', 'expires')}
        expected.update(intent_hex=envelope.hex(), state=state, result_hex='')
        if row != expected:
            raise ValueError('identity, exact envelope or state mismatch')


def validate_reply(observed, expected):
    if observed != expected:
        raise ValueError(f'reservation observation mismatch: {observed}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for field in ('go', 'rust', 'output'):
        p.add_argument('--' + field, required=True, type=Path)
    p.add_argument('--development', action='store_true')
    args = p.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT/'docs/evidence'):
        p.error('preserve historical evidence')
    output.mkdir(parents=True, exist_ok=False)
    (output/'raw').mkdir()
    (output/'journals').mkdir()
    programs = {name: getattr(args, name).resolve(strict=True) for name in PINS}
    fixture_path = ROOT/'vectors/0.10.0/guard-records.json'
    fixture = json.loads(fixture_path.read_bytes())
    f = next(c['input'] for c in fixture['cases'] if c['id'] == 'intent-valid')
    envelope = bytes.fromhex(f['envelope_hex'])
    accepted = dict(ok=True, created=True, state='RESERVED', intent_digest=sha(envelope))
    retry = dict(accepted, created=False)
    recovered = dict(retry, state='UNKNOWN')
    denied = dict(ok=False, created=False, state='', intent_digest='')
    command = dict(action='reserve', input=f)
    report = dict(kind='guard-reservation-bindings', status='RUNNING', conformance='NOT_ESTABLISHED',
                  scope='Actual Guard verification and durable reservation only; no dispatch, signed pending/terminal publication, client consumption or host isolation.',
                  development=args.development, platform=platform.platform(),
                  fixture_sha256=sha(fixture_path.read_bytes()),
                  inspector_revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  subjects={}, scenarios=[], restarts=[], controls=[], files={}, processes=0)

    def save():
        (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')

    def retain(path, data):
        (output/path).write_bytes(data)
        report['files'][path] = sha(data)
        save()

    def execute(name, label, path, mode, requests, expected, missing=False):
        wire=''.join(json.dumps(q)+'\n' for q in requests)
        result = subprocess.run([str(programs[name]), str(path), mode], input=wire,
                                text=True, capture_output=True, timeout=20)
        report['processes'] += 1
        record=dict(subject=name, mode=mode, input=requests, input_sha256=sha(wire.encode()),
                    exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
        retain('raw/'+label+'.json', (json.dumps(record, indent=2)+'\n').encode())
        if result.returncode != (2 if missing else 0) or result.stderr:
            raise ValueError('adapter execution failed: '+label)
        observed=[json.loads(line) for line in result.stdout.splitlines()]
        validate_reply(observed, expected)

    def snapshot(path, label, states):
        data=path.read_bytes()
        retain('journals/'+label+'.journal', data)
        validate_journal(data, envelope, states)

    try:
        for name, revision in PINS.items():
            source=ROOT.parent/('sage' if name=='go' else 'rs-sage-core')
            actual=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
            if not args.development and actual != revision:
                raise ValueError('checkout does not match pin: '+name)
            report['subjects'][name]=dict(revision=actual, adapter_sha256=sha(programs[name].read_bytes()))
        with tempfile.TemporaryDirectory(prefix='guard-reservation-') as tmp:
            root=Path(tmp)
            for name in programs:
                pretty=copy.deepcopy(command)
                pretty['input']['envelope_hex']=json.dumps(json.loads(envelope), indent=2).encode().hex()
                path=root/(name+'-retry')
                execute(name,name+'-retry',path,'create',[command,command,pretty],[accepted,retry,retry])
                snapshot(path,name+'-retry',['RESERVED'])
                report['scenarios'].append(dict(id=name+'-retry',status='PASS'))
                controls=[]
                for key, value in [('active_key',False),('policy_allow',False),('clock_trusted',False),('now',1700000300)]:
                    q=copy.deepcopy(command);q['input'][key]=value;controls.append(q)
                path=root/(name+'-current-authority')
                execute(name,name+'-current-authority',path,'create',[command]+controls+[command],[accepted]+[denied]*4+[retry])
                snapshot(path,name+'-current-authority',['RESERVED'])
                report['scenarios'].append(dict(id=name+'-current-authority',status='PASS'))
                path=root/(name+'-initial-denial')
                execute(name,name+'-initial-denial',path,'create',controls,[denied]*4)
                snapshot(path,name+'-initial-denial',[])
                report['scenarios'].append(dict(id=name+'-initial-denial',status='PASS'))
                path=root/(name+'-missing')
                execute(name,name+'-missing',path,'reopen',[command],[],missing=True)
                if path.exists():raise ValueError('missing state recreated')
                report['controls'].append(dict(id=name+'-missing',status='PASS'))
            for writer, reader in itertools.product(programs, repeat=2):
                label=writer+'-to-'+reader;path=root/label
                execute(writer,label+'-create',path,'create',[command,command],[accepted,retry])
                snapshot(path,label+'-before',['RESERVED'])
                execute(reader,label+'-recover',path,'reopen',[command,command],[recovered,recovered])
                snapshot(path,label+'-after',['RESERVED','UNKNOWN'])
                report['restarts'].append(dict(id=label,status='PASS'))
        report['status']='PASS'
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        report.update(status='FAIL',error=str(error))
    save()
    print(json.dumps(dict(status=report['status'],processes=report['processes'],report=str(output/'report.json'))))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
