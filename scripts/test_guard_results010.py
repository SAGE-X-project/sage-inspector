"""Actual signed result publication with inert sinks and owned local journals."""
import argparse
import copy
import itertools
import json
from pathlib import Path
import platform
import subprocess
import tempfile
from test_record010_adapters import PINS
from test_guard_dispatch010 import expected_effect, observation, sha
from test_guard_reservations010 import HEADER, validate_reply

ROOT = Path(__file__).resolve().parents[1]


def expected(*, ok=True, effects=None, signs=0, state='', created=False, committed=False, digest='', status='', output=None, time=1700000000):
    r = observation(ok, created, committed, state, digest, effects)
    r.update(signs=signs, result_hex='')
    return r, dict(status=status, output={} if output is None else output, created=time)


def validate_observations(rows, wants, envelope):
    if len(rows) != len(wants):
        raise ValueError('response count')
    audit = []
    for row, (want, result) in zip(rows, wants):
        row = copy.deepcopy(row)
        raw = row.get('result_hex', '')
        if result['status']:
            if not raw:
                raise ValueError('missing signed response')
            audit.append(dict(result, envelope_hex=raw, intent_hex=envelope.hex()))
            row['result_hex'] = ''
        validate_reply(row, want)
    return audit


def validate_storage(raw, envelope, states):
    if not raw.startswith(HEADER) or not raw.endswith(b'\n'):
        raise ValueError('storage framing')
    rows = [json.loads(line) for line in raw[len(HEADER):].splitlines()]
    if len(rows) != len(states):
        raise ValueError('storage transition count')
    intent = json.loads(envelope)['intent']
    audit = []
    for row, (state, status, output, created) in zip(rows, states):
        want = {k: intent[k] for k in ('issuer', 'recipient', 'call_id', 'nonce', 'expires')}
        want.update(state=state, intent_hex=envelope.hex(), result_hex='')
        if status:
            result = row.get('result_hex', '')
            if not result:
                raise ValueError('terminal missing signed bytes')
            audit.append(dict(envelope_hex=result, intent_hex=envelope.hex(), status=status, output=output, created=created))
            row = dict(row, result_hex='')
        validate_reply(row, want)
    return audit


def state(name, status='', output=None, created=1700000000):
    return name, status, {} if output is None else output, created


def scenarios(f):
    envelope = bytes.fromhex(f['envelope_hex'])
    effect = [expected_effect(envelope, 'old')]
    config = dict(action='configure', input=f, instance='old')
    dispatch = dict(action='dispatch', envelope_hex=f['envelope_hex'])
    reject = dict(dispatch, action='reject')
    reply = dict(action='reply')
    finish = dict(action='finish', output={'value': 'ok'})
    sign = dict(action='signer', now=1700000000, active=True)
    empty = expected()
    def e(**kw): return expected(effects=effect, **kw)
    def d(name='EXECUTING', new=False, **kw):
        return e(state=name, created=new, committed=new, digest=sha(envelope), **kw)
    running = [state('RESERVED'), state('EXECUTING')]
    complete = running+[state('COMPLETED', 'completed', finish['output'])]
    cases = [
        ('pending-once', [config, dispatch, reply, finish, reply, dispatch, reply, finish, dispatch, reply],
         [empty, d(new=True), e(signs=1,status='pending'), e(signs=2), e(ok=False,signs=2), d('COMPLETED',signs=2), e(signs=2,status='completed',output=finish['output']), e(signs=2), d('COMPLETED',signs=2), e(signs=2,status='completed',output=finish['output'])], complete),
        ('completed', [config,dispatch,finish,reply],
         [empty,d(new=True),e(signs=1),e(signs=1,status='completed',output=finish['output'])],complete),
        ('rejected', [config,reject,reply,dispatch,reply],
         [empty,expected(created=True,state='REJECTED',digest=sha(envelope),signs=1),expected(signs=1,status='rejected'),expected(state='REJECTED',digest=sha(envelope),signs=1),expected(signs=1,status='rejected')],[state('REJECTED','rejected')]),
        ('rejection-conflict', [config,dispatch,reject,finish,reply],
         [empty,d(new=True),e(ok=False),e(signs=1),e(signs=1,status='completed',output=finish['output'])],complete),
        ('signer-recovery', [config,dispatch,dict(sign,fail=True),finish,reply,sign,finish,reply,dispatch,reply],
         [empty,d(new=True),e(),e(ok=False,signs=1),e(ok=False,signs=2),e(signs=2),e(signs=3),e(ok=False,signs=3),d('COMPLETED',signs=3),e(signs=3,status='completed',output=finish['output'])],complete),
    ]
    for label, change in [('revoked',{'active':False}),('expired',{'now':1700000300})]:
        cases.append((label,[config,dispatch,finish,dict(sign,**change),reply,finish],
                      [empty,d(new=True),e(signs=1),e(signs=1),e(ok=False,signs=1),e(ok=False,signs=1)],complete))
    late=copy.deepcopy(config);late['input']['now']=1700000301
    cases.append(('accepted-late',[config,dispatch,late,dict(sign,now=1700000301),finish,reply,dispatch],
                  [empty,d(new=True),e(),e(),e(signs=1),e(signs=1,status='completed',output=finish['output'],time=1700000301),e(ok=False,signs=1)],running+[state('COMPLETED','completed',finish['output'],1700000301)]))
    return cases


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('go','rust','output'):p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--development',action='store_true')
    a=p.parse_args();output=a.output.resolve()
    if output.is_relative_to(ROOT/'docs/evidence'):p.error('preserve historical evidence')
    output.mkdir(parents=True,exist_ok=False)
    for d in ('raw','journals'): (output/d).mkdir()
    programs={n:getattr(a,n).resolve(strict=True) for n in PINS}
    fixture_bytes=(ROOT/'vectors/0.10.0/guard-records.json').read_bytes()
    cases=json.loads(fixture_bytes)['cases']
    f=next(c['input'] for c in cases if c['id']=='intent-valid')
    public=next(c['input']['public_key_hex'] for c in cases if c['id']=='result-completed-valid')
    envelope=bytes.fromhex(f['envelope_hex']);audit=[]
    report=dict(kind='guard-result-bindings',status='RUNNING',conformance='NOT_ESTABLISHED',development=a.development,
                scope='Actual signed results, single local response permits and durable first terminals; inert sink only. Client consumption, MCP mapping and host isolation are not established.',
                platform=platform.platform(),fixture_sha256=sha(fixture_bytes),
                inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),subjects={},scenarios=[],restarts=[],files={},processes=0)
    def save(): (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    def retain(path,raw):
        (output/path).write_bytes(raw);report['files'][path]=sha(raw);save()
    def execute(subject,label,path,mode,commands,wants,states):
        wire=''.join(json.dumps(q)+'\n' for q in commands)
        proc=subprocess.run([str(programs[subject]),str(path),mode],input=wire,text=True,capture_output=True,timeout=20)
        report['processes']+=1
        record=dict(subject=subject,mode=mode,input=commands,input_sha256=sha(wire.encode()),exit_code=proc.returncode,stdout=proc.stdout,stderr=proc.stderr)
        retain('raw/'+label+'.json',(json.dumps(record,indent=2)+'\n').encode())
        if proc.returncode or proc.stderr:raise ValueError('adapter failure '+label)
        rows=[json.loads(line) for line in proc.stdout.splitlines()]
        audit.extend(validate_observations(rows,wants,envelope))
        raw=path.read_bytes();retain('journals/'+label+'.journal',raw)
        audit.extend(validate_storage(raw,envelope,states))
        return rows,raw
    try:
        for name,pin in PINS.items():
            source=ROOT.parent/('sage' if name=='go' else 'rs-sage-core')
            revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
            if not a.development and revision!=pin:raise ValueError('core pin mismatch '+name)
            report['subjects'][name]=dict(revision=revision,adapter_sha256=sha(programs[name].read_bytes()))
        with tempfile.TemporaryDirectory(prefix='guard-results-') as tmp:
            root=Path(tmp)
            for name in programs:
                for label,commands,wants,states in scenarios(f):
                    label=name+'-'+label
                    rows,_=execute(name,label,root/label,'create',commands,wants,states)
                    if label.endswith('pending-once') and rows[6]['result_hex']!=rows[9]['result_hex']:raise ValueError('terminal refreshed')
                    report['scenarios'].append(dict(id=label,status='PASS'))
            for writer,reader in itertools.product(programs,repeat=2):
                for outcome in ('completed','rejected','unknown'):
                    label=writer+'-to-'+reader+'-'+outcome;path=root/label
                    if outcome=='unknown':
                        _,commands,wants,states=scenarios(f)[1];commands=commands[:2];wants=wants[:2];states=states[:2]
                    else:
                        _,commands,wants,states=next(c for c in scenarios(f) if c[0]==outcome)
                    rows,before=execute(writer,label+'-write',path,'create',commands,wants,states)
                    if outcome=='unknown':states+= [state('UNKNOWN'),state('UNKNOWN','unknown')]
                    config=dict(action='configure',input=f,instance='old');dispatch=dict(action='dispatch',envelope_hex=f['envelope_hex']);reply=dict(action='reply')
                    signs=1 if outcome=='unknown' else 0
                    wants=[expected(),expected(state=outcome.upper(),digest=sha(envelope)),expected(signs=signs,status=outcome,output={'value':'ok'} if outcome=='completed' else {}),expected(signs=signs,state=outcome.upper(),digest=sha(envelope)),expected(signs=signs,status=outcome,output={'value':'ok'} if outcome=='completed' else {})]
                    recovered,after=execute(reader,label+'-read',path,'reopen',[config,dispatch,reply,dispatch,reply],wants,states)
                    if recovered[2]['result_hex']!=recovered[4]['result_hex']:raise ValueError('recovery refreshed terminal')
                    if outcome!='unknown' and (before!=after or recovered[2]['result_hex']!=rows[-1]['result_hex']):raise ValueError('first terminal not preserved')
                    if outcome=='unknown':
                        wants=[(dict(w,signs=0),r) for w,r in wants]
                        repeated,last=execute(writer,label+'-again',path,'reopen',[config,dispatch,reply,dispatch,reply],wants,states)
                        if last!=after or repeated[2]['result_hex']!=recovered[2]['result_hex']:raise ValueError('signed UNKNOWN changed')
                    report['restarts'].append(dict(id=label,status='PASS'))
        raw=(json.dumps(dict(public_key_hex=public,cases=audit),indent=2)+'\n').encode();retain('signature-input.json',raw)
        proc=subprocess.run(['node',str(ROOT/'scripts/check_guard_results010.js')],input=raw,capture_output=True,timeout=20)
        retain('signature-audit.json',(json.dumps(dict(exit_code=proc.returncode,stdout=proc.stdout.decode(),stderr=proc.stderr.decode()),indent=2)+'\n').encode())
        if proc.returncode:raise ValueError('independent signature audit failed')
        report.update(status='PASS',signature_checks=len(audit))
    except (ValueError,OSError,KeyError,subprocess.TimeoutExpired) as e:report.update(status='FAIL',error=str(e))
    save();print(json.dumps(dict(status=report['status'],processes=report['processes'],report=str(output/'report.json'))))
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
