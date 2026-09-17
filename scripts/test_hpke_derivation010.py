"""Bounded local fixed-vector and cross-core cryptographic derivation tests."""
import argparse
import copy
import json
from pathlib import Path
import selectors
import subprocess
from test_record010_adapters import ROOT, PINS, digest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go',type=Path,required=True)
    parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();output=args.output.resolve()
    if ROOT/'docs/evidence' in (output,*output.parents):parser.error('preserve archived evidence')
    output.mkdir(parents=True,exist_ok=False)
    path=ROOT/'vectors/0.10.0/hpke-derivation010.json';fixture=json.loads(path.read_text())
    assert len(fixture['cases'])==60
    assert fixture['source_sha256']==digest(ROOT/fixture['source_path'])
    report=dict(kind='hpke-derivation010-runtime',status='RUNNING',conformance='NOT_ESTABLISHED',
                scope='Domains, DH and seed/ACK derivation only; no signatures, authority or session establishment',
                fixture_sha256=digest(path),script_sha256=digest(Path(__file__)),
                inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                inspector_tracked_changes=bool(subprocess.check_output(['git','diff','HEAD','--'],cwd=ROOT)),
                subjects={},vectors=[],exchanges=[],controls=[])
    executables={n:getattr(args,n).resolve() for n in PINS}
    def equal(a,b):return json.dumps(a,sort_keys=True)==json.dumps(b,sort_keys=True)
    class Peer:
        def __init__(self,name,log):
            self.p=subprocess.Popen([str(executables[name])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
            self.name=name;self.log=log;self.count=0
        def call(self,op,data):
            self.count+=1;q=dict(id=str(self.count),operation=op,input=data)
            self.p.stdin.write(json.dumps(q)+'\n');self.p.stdin.flush()
            with selectors.DefaultSelector() as sel:
                sel.register(self.p.stdout,selectors.EVENT_READ)
                assert sel.select(15), 'adapter response timeout'
            raw=self.p.stdout.readline();assert raw, 'adapter ended before response'
            self.log.append(dict(subject=self.name,request=q,stdout=raw))
            o=json.loads(raw);assert set(o)=={'id','verdict','output'} and o['id']==q['id']
            return o
        def close(self):
            self.p.stdin.close()
            try: code=self.p.wait(timeout=15)
            except subprocess.TimeoutExpired:self.p.kill();self.p.wait();raise
            stderr=self.p.stderr.read();self.p.stdout.close();self.p.stderr.close()
            assert code==0,(self.name,code,stderr)
    try:
        for name,exe in executables.items():
            repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core')
            revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            assert revision==PINS[name], 'review a new revision before testing'
            assert not subprocess.check_output(['git','diff','HEAD','--'],cwd=repo),'tracked core changed'
            core_fixture=repo/('pkg/agent/hpke/testdata/derivation010.json' if name=='go' else 'tests/fixtures/hpke-derivation010.json')
            assert digest(core_fixture)==digest(path),'core fixture differs'
            report['subjects'][name]=dict(revision=revision,executable_sha256=digest(exe))
            for c in fixture['cases']:
                log=[];entry=dict(subject=name,case_id=c['id'],status='ERROR',calls=log);report['vectors'].append(entry)
                peer=Peer(name,log)
                try:
                    actual=peer.call(c['operation'],c['input'])
                    assert actual['verdict']==('REJECT' if c['expected'] is None else 'ACCEPT')
                    assert equal(actual['output'],c['expected'] or {}),(c['id'],actual)
                finally:peer.close()
                entry['status']='PASS'
        b=fixture['cases'][0]['input']['binding_hex'];private=fixture['cases'][1]['input']['kem_private_hex']
        seen=set()
        for sender in PINS:
            for receiver in PINS:
                for mode in ['valid','changed-ctx','zero-ephS','duplicate-v','extra']:
                    log=[];entry=dict(sender=sender,receiver=receiver,mode=mode,status='ERROR',calls=log);report['exchanges'].append(entry)
                    s=Peer(sender,log);r=Peer(receiver,log)
                    try:
                        started=s.call('start',dict(binding_hex=b,kem_private_hex=private));assert started['verdict']=='ACCEPT'
                        init=started['output']['initiation_hex'];m=json.loads(bytes.fromhex(init))
                        for k in ['enc','ephC']:
                            assert m[k] not in seen,'repeated ephemeral public key';seen.add(m[k])
                        responded=r.call('respond-fresh',dict(initiation_hex=init,kem_private_hex=private));assert responded['verdict']=='ACCEPT'
                        transcript=bytes.fromhex(responded['output']['transcript_hex'])
                        if mode!='valid':
                            t=json.loads(transcript)
                            if mode=='changed-ctx':t['ctx']='22222222-2222-4222-8222-222222222222'
                            if mode=='zero-ephS':t['ephS']='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                            if mode=='extra':t['extra']='x'
                            transcript=json.dumps(t,separators=(',',':')).encode()
                            if mode=='duplicate-v':transcript=transcript[:-1]+b',"v":"0.10.0"}'
                        finished=s.call('finish',dict(transcript_hex=transcript.hex()))
                        if mode=='valid':
                            assert finished['verdict']=='ACCEPT' and equal(finished['output'],responded['output'])
                        else:assert finished['verdict']=='REJECT' and finished['output']=={}
                    finally:
                        try:s.close()
                        finally:r.close()
                    entry['status']='PASS'
        # Invalid local controls are process errors, not authenticated peer rejection.
        for name,exe in executables.items():
            controls=[dict(id='x',operation='domains',input={'binding_hex':v}) for v in [None,1,'zz']]
            controls.extend([dict(id='x',operation='domains',input={}),dict(id='x',operation='domains',input={'binding_hex':b,'extra':'00'}),dict(id='x',operation='finish',input={'transcript_hex':'00'})])
            for q in controls:
                p=subprocess.run([str(exe)],input=json.dumps(q)+'\n',text=True,capture_output=True,timeout=15)
                assert p.returncode==2 and p.stdout==''
                report['controls'].append(dict(subject=name,request=q,exit_code=p.returncode,stderr=p.stderr,status='PASS'))
        report['status']='PASS';report['counts']=dict(vectors=len(report['vectors']),exchanges=len(report['exchanges']),control_errors=len(report['controls']))
        print(json.dumps(report['counts']))
    except Exception:
        report['status']='ERROR';raise
    finally:
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
