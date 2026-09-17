"""Run bounded local 0.10.0 seed/ACK calls; no network or handshake certification."""
import argparse
import copy
import json
import platform
import subprocess
from pathlib import Path
from test_record010_adapters import ROOT, PINS, digest


def cases():
    fixture = json.loads((ROOT / 'vectors/0.10.0/hpke-schedule.json').read_text())
    assert sum(c['id'].startswith('schedule-') for c in fixture['cases']) == 3
    result = []
    def add(case, op, data, verdict='REJECT', output=None, malformed=False):
        result.append(dict(id=case, operation='sage.hpke.schedule010.' + op,
                           input=data, expected=dict(verdict=verdict, output=output or {}),
                           malformed=malformed))
    for c in fixture['cases']:
        if not c['id'].startswith('schedule-'):
            continue
        o = c['expected']['output']; label = c['id']
        combine = {k:o[k] for k in ('exporter_hex','ss_e2e_hex','th_hex')}
        ack = {k:o[k] for k in ('seed_hex','th_hex')}
        verify = dict(ack, ack_tag_hex=o['ack_tag_hex'])
        add(label+'-combine','combine',combine,'ACCEPT',{'seed_hex':o['seed_hex']})
        add(label+'-ack','ack',ack,'ACCEPT',{'ack_tag_hex':o['ack_tag_hex']})
        add(label+'-verify','verify',verify,'ACCEPT',{'valid':True})
        for byte in range(32):
            tag=bytearray.fromhex(o['ack_tag_hex']);tag[byte]^=1
            add(label+'-changed-tag-'+str(byte),'verify',dict(verify,ack_tag_hex=tag.hex()))
        th=bytearray.fromhex(o['th_hex']);th[0]^=1
        add(label+'-changed-th','verify',dict(verify,th_hex=th.hex()))
        seed=bytearray.fromhex(o['seed_hex']);seed[0]^=1
        add(label+'-changed-seed','verify',dict(verify,seed_hex=seed.hex()))
    # Exercise each length contract at the core boundary, not in an adapter filter.
    for op, base in [('combine',combine),('ack',ack),('verify',verify)]:
        for name in base:
            for n in (0,1,31,33,64):
                add(op+'-'+name+'-length-'+str(n),op,dict(base,**{name:'01'*n}))
        for name in base:
            for tag,value in [('null',None),('type',1),('hex','zz')]:
                add(op+'-'+name+'-'+tag,op,dict(base,**{name:value}),malformed=True)
        missing=copy.deepcopy(base);missing.pop(next(iter(base)))
        add(op+'-missing',op,missing,malformed=True)
        add(op+'-extra',op,dict(base,unexpected=True),malformed=True)
    add('zero-e2e','combine',dict(combine,ss_e2e_hex='00'*32))
    assert len({c['id'] for c in result}) == len(result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go',type=Path,required=True)
    parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    if ROOT/'docs/evidence' in (output,*output.parents):
        parser.error('keep fresh results outside archived evidence')
    output.mkdir(parents=True,exist_ok=False)
    report=dict(kind='hpke010-schedule-bindings',status='RUNNING',conformance='NOT_ESTABLISHED',
                scope='Seed and ACK primitives only; no authenticated completion or state transitions',
                inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                script_sha256=digest(Path(__file__)),
                inspector_tracked_changes=bool(subprocess.check_output(['git','diff','HEAD','--'],cwd=ROOT)),
                fixture_sha256=digest(ROOT/'vectors/0.10.0/hpke-schedule.json'),
                python=platform.python_version(),platform=platform.platform(),subjects={},results=[])
    def save():
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        for name in PINS:
            repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core')
            revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            assert revision==PINS[name], 'review a new core revision before testing'
            assert not subprocess.check_output(['git','diff','HEAD','--'],cwd=repo), 'tracked core source changed'
            exe=getattr(args,name).resolve()
            report['subjects'][name]=dict(revision=revision,executable_sha256=digest(exe))
            for c in cases():
                q=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',
                       case_id=c['id'],operation=c['operation'],input=c['input'])
                p=subprocess.run([str(exe)],input=json.dumps(q),text=True,capture_output=True,timeout=15)
                result=dict(subject=name,request=q,expected=c['expected'],malformed=c['malformed'],
                            exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr)
                report['results'].append(result)
                if c['malformed']:
                    assert p.returncode==2 and not p.stdout, result
                else:
                    assert p.returncode==0, result
                    actual=json.loads(p.stdout)
                    expected=dict(schema_version=1,case_id=c['id'],**c['expected'])
                    assert json.dumps(actual,sort_keys=True)==json.dumps(expected,sort_keys=True), result
                result['status']='PASS'
        report['status']='PASS'
        report['counts']={name:{'core_calls':sum(r['subject']==name and not r['malformed'] for r in report['results']),
                               'control_errors':sum(r['subject']==name and r['malformed'] for r in report['results'])} for name in PINS}
        print(json.dumps(report['counts']))
    except Exception:
        report['status']='ERROR'
        raise
    finally:
        save()


if __name__=='__main__':
    main()
