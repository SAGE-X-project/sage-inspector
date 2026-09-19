"""Bounded client consumption, polling, real signed exchanges and durable restarts."""
import argparse
import copy
import itertools
import json
from pathlib import Path
import platform
import subprocess
import tempfile
from test_record010_adapters import PINS
from test_guard_dispatch010 import sha
from test_guard_results010 import scenarios as server_scenarios, validate_observations as validate_server, validate_storage as validate_server_storage

ROOT=Path(__file__).resolve().parents[1]
HEADER=b'sage-guard-client|0.10.0\n'


def observation(**kw):
    return dict(dict(ok=True,id='',intent_hex='',status='',first=False,ignored=False,output_hex='',handoffs=0),**kw)


def outer(n):return f'00000000-0000-4000-8000-{n:012d}'


def event(kind, id='', at=0, intent_hex='', result_hex=''):
    return dict(kind=kind,id=id,at=at,intent_hex=intent_hex,result_hex=result_hex)


def verify_rows(raw, expected):
    if not raw.startswith(HEADER) or not raw.endswith(b'\n'):raise ValueError('journal framing')
    rows=[json.loads(line) for line in raw[len(HEADER):].splitlines()]
    if rows!=expected:raise ValueError('journal identity, consumption or polling mismatch')


def verify_observations(rows, expected):
    if rows!=expected:raise ValueError('client response, output or invocation mismatch')


def config(v,utc=1700000000000):
    return dict(action='open',input=v['input'],public_key_hex=v['public_key_hex'],utc=utc,mono=0)


def case_commands(v,case):
    commands=[config(v)];expected=[observation()]
    journal=[event('open',intent_hex=v['input']['envelope_hex'])]
    utc=1700000000000;active=set()
    for q in case['steps']:
        q=copy.deepcopy(q);want=q.pop('expected')
        if q['action']=='tick':utc=q['utc']
        if q['action']=='begin' and want['ok']:
            active.add(q['id']);journal.append(event('send',q['id'],utc))
        if q['action'] in ('accept','failed') and q['id'] in active:
            active.remove(q['id']);journal.append(event('close',q['id']))
        if q['action']=='accept':
            q['envelope_hex']=v['results'][q.pop('result')]
            if want['first']:journal.append(event('terminal',q['id'],result_hex=q['envelope_hex']))
        commands.append(q);expected.append(want)
    return commands,expected,journal


def recovery(v,terminal):
    raw=v['input']['envelope_hex'];result=v['results']['completed'];id1,id2=outer(1),outer(2)
    begin=lambda id:dict(action='begin',id=id)
    accepted=lambda id:observation(id=id,intent_hex=raw)
    done=observation(status='completed',first=True,output_hex=b'{"value":"ok"}'.hex())
    write=[config(v),begin(id1)]
    wants=[observation(),accepted(id1)]
    journal=[event('open',intent_hex=raw),event('send',id1,1700000000000)]
    if terminal:write.append(dict(action='accept',id=id1,envelope_hex=result));wants.append(done);journal.extend([event('close',id1),event('terminal',id1,result_hex=result)])
    else:write.append(dict(action='failed',id=id1));wants.append(observation());journal.append(event('close',id1))
    write.append(dict(action='close'));wants.append(observation())
    read=[config(v,1700000001000),begin(id2)]
    expected=[observation(),observation(ok=False)]
    after=copy.deepcopy(journal)
    if terminal:
        read.extend([dict(action='accept',id=id1,envelope_hex=result),dict(action='close')]);expected.extend([observation(ok=False),observation()])
    else:
        read.extend([dict(action='tick',utc=1700000001000,mono=999),begin(id2),dict(action='tick',utc=1700000001000,mono=1000),begin(id1),begin(id2),dict(action='accept',id=id2,envelope_hex=result),dict(action='close')])
        expected.extend([observation(),observation(ok=False),observation(),observation(ok=False),accepted(id2),done,observation()])
        after.extend([event('send',id2,1700000001000),event('close',id2),event('terminal',id2,result_hex=result)])
    for index in range(1,len(wants)):wants[index]['handoffs']=1
    if not terminal:
        for index in range(6,len(expected)):expected[index]['handoffs']=1
    return (write,wants,journal),(read,expected,after)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('go','rust','go-server','rust-server','output'):p.add_argument('--'+n,required=True,type=Path)
    p.add_argument('--development',action='store_true');a=p.parse_args();out=a.output.resolve()
    if out.is_relative_to(ROOT/'docs/evidence'):p.error('preserve historical evidence')
    out.mkdir(parents=True,exist_ok=False)
    for d in ('raw','journals'):(out/d).mkdir()
    programs={n:getattr(a,n).resolve(strict=True) for n in PINS}
    servers={n:getattr(a,n+'_server').resolve(strict=True) for n in PINS}
    fixture=(ROOT/'vectors/0.10.0/guard-client.json').read_bytes();v=json.loads(fixture)
    report=dict(kind='guard-client-bindings',status='RUNNING',conformance='NOT_ESTABLISHED',development=a.development,
                scope='Real client APIs and durable per-operation state with controlled trusted time, inert server sinks, no production transport or host isolation certification.',
                fixture_sha256=sha(fixture),platform=platform.platform(),inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),subjects={},scenarios=[],exchanges=[],restarts=[],controls=[],files={},processes=0)
    audit=[]
    def save():(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    def retain(path,raw):(out/path).write_bytes(raw);report['files'][path]=sha(raw);save()
    def execute(name,label,path,mode,commands,wants,journal,server=False,missing=False):
        wire=''.join(json.dumps(q)+'\n' for q in commands)
        proc=subprocess.run([str((servers if server else programs)[name]),str(path),mode],input=wire,text=True,capture_output=True,timeout=20)
        report['processes']+=1
        record=dict(subject=name,server=server,mode=mode,input=commands,input_sha256=sha(wire.encode()),exit_code=proc.returncode,stdout=proc.stdout,stderr=proc.stderr)
        retain('raw/'+label+'.json',(json.dumps(record,indent=2)+'\n').encode())
        if proc.returncode!=(2 if missing else 0) or proc.stderr:raise ValueError('adapter failure '+label)
        rows=[json.loads(line) for line in proc.stdout.splitlines()]
        if missing:
            if rows or path.exists():raise ValueError('missing client state recreated')
            return rows
        raw=path.read_bytes();retain('journals/'+label+'.journal',raw)
        if server:
            audit.extend(validate_server(rows,wants,bytes.fromhex(v['input']['envelope_hex'])))
            audit.extend(validate_server_storage(raw,bytes.fromhex(v['input']['envelope_hex']),journal))
        else:
            verify_observations(rows,wants);verify_rows(raw,journal)
            if commands[-1]['action']=='close' and path.with_name(path.name+'.lock').exists()==wants[-1]['ok']:raise ValueError('client lock release/poison mismatch')
        return rows
    try:
        for name,pin in PINS.items():
            source=ROOT.parent/('sage' if name=='go' else 'rs-sage-core');revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
            if not a.development and revision!=pin:raise ValueError('pin mismatch '+name)
            report['subjects'][name]=dict(revision=revision,adapter_sha256=sha(programs[name].read_bytes()),server_sha256=sha(servers[name].read_bytes()))
        with tempfile.TemporaryDirectory(prefix='guard-client-') as temp:
            root=Path(temp)
            for name in PINS:
                for case in v['cases']:
                    label=name+'-'+case['id'];commands,wants,journal=case_commands(v,case)
                    execute(name,label,root/label,'create',commands,wants,journal);report['scenarios'].append(dict(id=label,status='PASS'))
                label=name+'-missing';execute(name,label,root/label,'reopen',[config(v)],[],[],missing=True);report['controls'].append(dict(id=label,status='PASS'))
            for server,client in itertools.product(PINS,repeat=2):
                label=server+'-to-'+client;_,commands,wants,journal=server_scenarios(v['input'])[0]
                rows=execute(server,label+'-server',root/(label+'-server'),'create',commands,wants,journal,server=True)
                actual=copy.deepcopy(v);actual['results']['pending']=rows[2]['result_hex'];actual['results']['completed']=rows[6]['result_hex']
                case=next(c for c in v['cases'] if c['id']=='poll-boundary');commands,wants,journal=case_commands(actual,case)
                execute(client,label+'-client',root/(label+'-client'),'create',commands,wants,journal)
                report['exchanges'].append(dict(id=label,status='PASS'))
            for writer,reader in itertools.product(PINS,repeat=2):
                for terminal in (False,True):
                    label=writer+'-to-'+reader+('-terminal' if terminal else '-unresolved');path=root/label
                    write,read=recovery(v,terminal)
                    execute(writer,label+'-write',path,'create',*write)
                    execute(reader,label+'-read',path,'reopen',*read)
                    report['restarts'].append(dict(id=label,status='PASS'))
        raw=(json.dumps(dict(public_key_hex=v['public_key_hex'],cases=audit),indent=2)+'\n').encode();retain('signature-input.json',raw)
        proc=subprocess.run(['node',str(ROOT/'scripts/check_guard_results010.js')],input=raw,capture_output=True,timeout=20)
        retain('signature-audit.json',(json.dumps(dict(exit_code=proc.returncode,stdout=proc.stdout.decode(),stderr=proc.stderr.decode()),indent=2)+'\n').encode())
        if proc.returncode:raise ValueError('server signature audit')
        report.update(status='PASS',signature_checks=len(audit))
    except (OSError,ValueError,KeyError,subprocess.TimeoutExpired) as e:report.update(status='FAIL',error=str(e))
    save();print(json.dumps(dict(status=report['status'],processes=report['processes'],report=str(out/'report.json'))));return 0 if report['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
