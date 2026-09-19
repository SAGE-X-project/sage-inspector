"""Protected local RPC flow through actual Guard dispatch and durable consumption."""
import argparse,contextlib,itertools,json,select,subprocess,tempfile
from pathlib import Path
from test_completion010 import Actor,canonical,decode
from test_guard_rpc010 import check_client,check_request,check_response
from test_guard_dispatch010 import expected_effect
from test_guard_client010 import event,verify_rows
from test_guard_results010 import validate_storage,state
from test_record010_adapters import PINS
from test_mcp_session010 import sha,check_exchange
ROOT=Path(__file__).resolve().parents[1]
VERSION='2025-06-18'
UTC=1700000000
NODE="""const c=require('crypto'),fs=require('fs'),q=JSON.parse(fs.readFileSync(0,'utf8'));const k=c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(q.public,'hex')]),format:'der',type:'spki'});if(!c.verify(null,Buffer.from(q.message_hex,'hex'),k,Buffer.from(q.signature_hex,'hex')))process.exit(1);"""

def require(value,reason):
    if not value:raise ValueError(reason)
def check_effect(row,intent):
    require(row['effects']==[expected_effect(intent,'old')],'exactly one authorized inert effect required')
def check_dispatch(row,intent,first):
    check_effect(row,intent)
    require(row['ok'] and row['committed']==first and row['created']==first and row['state']==('EXECUTING' if first else 'COMPLETED'),'dispatch/reuse mismatch')

class GuardProcess:
    def __init__(self,program,path,mode,label,log):
        self.label,self.log=label,log
        self.p=subprocess.Popen([str(program),str(path),mode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    def call(self,q):
        self.log(dict(actor=self.label,request=q));self.p.stdin.write(canonical(q).decode()+'\n');self.p.stdin.flush()
        require(select.select([self.p.stdout],[],[],15)[0],'Guard timeout')
        line=self.p.stdout.readline();self.log(dict(actor=self.label,stdout=line));return json.loads(line)
    def close(self):
        self.p.stdin.close()
        try:self.p.wait(timeout=15)
        except subprocess.TimeoutExpired:self.p.kill();self.p.wait();raise
        tail=self.p.stdout.read();err=self.p.stderr.read();self.p.stdout.close();self.p.stderr.close()
        self.log(dict(actor=self.label,exit_code=self.p.returncode,stdout_tail=tail,stderr=err))
        require(not self.p.returncode and not tail and not err,'Guard exit mismatch')
class Session(Actor):
    def call(self,action,expected='ACCEPT',**controls):
        return super().call(action,expected,**dict(dict(unix=UTC),**controls))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for lang in PINS:
        for part in ('session','server','client'):p.add_argument('--'+lang+'-'+part,type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
    require(not out.is_relative_to(ROOT/'docs/evidence'),'preserve historical evidence');out.mkdir(parents=True,exist_ok=False)
    fixture=(ROOT/'vectors/0.10.0/guard-rpc.json').read_bytes();v=json.loads(fixture);intent=bytes.fromhex(v['input']['envelope_hex']);envelope=json.loads(intent)
    alice=envelope['intent']['issuer'];bob=envelope['intent']['recipient'];pubs={alice:v['input']['public_key_hex'],bob:v['public_key_hex']}
    programs={lang:{part:getattr(a,lang+'_'+part).resolve(strict=True) for part in ('session','server','client')} for lang in PINS}
    r=dict(kind='guard-session-flow',status='RUNNING',conformance='NOT_ESTABLISHED',lifecycle={'NOT_RUN':37},fixture_sha256=sha(fixture),subjects={},inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),scope='Trusted local orchestration; inert effects; controlled authorities; in-memory session replay; trusted MCP version. No host isolation, live registry or reconnect certification.',processes=0,exchanges=[],restarts=[],files={})
    audit=[];result_audit=[];raw=(out/'raw.jsonl').open('x')
    def log(v):
        raw.write(json.dumps(v)+'\n');raw.flush()
        if 'exit_code' in v:require(not v['exit_code'] and not v['stdout_tail'] and not v['stderr'],'process failure')
    def retain(name,data):(out/name).write_bytes(data);r['files'][name]=sha(data)
    def verify(message,sig,public):
        q=dict(message_hex=message.hex(),signature_hex=sig.hex(),public=public)
        subprocess.run(['node','-e',NODE],input=json.dumps(q),text=True,check=True,capture_output=True,timeout=10);audit.append(q)
    def outer(wire,reply=False):
        obj=json.loads(bytes.fromhex(wire));sig=decode(obj.pop('signature'));verify((b'sage-wire-response|0.10.0\n' if reply else b'sage-wire-request|0.10.0\n')+canonical(obj),sig,pubs[obj['did']])
    def signature_result(proof):
        result_audit.append(proof);e=json.loads(bytes.fromhex(proof['envelope_hex']));verify(b'sage-tool-result|0.10.0\0'+canonical(e['result']),decode(e['proof']),pubs[bob])
    try:
        for lang in PINS:
            repo=ROOT.parent/('sage' if lang=='go' else 'rs-sage-core');revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            require(revision==PINS[lang],'core revision mismatch');require(not subprocess.check_output(['git','diff','HEAD','--'],cwd=repo),'modified core source')
            r['subjects'][lang]=dict(revision=revision,binaries={part:sha(binary.read_bytes()) for part,binary in programs[lang].items()})
        retain('fixture.json',fixture)
        with tempfile.TemporaryDirectory() as directory:
            tmp=Path(directory)
            for client,server in itertools.product(PINS,repeat=2):
                label=client+'-to-'+server;cp=tmp/(label+'-client');sp=tmp/(label+'-server');ap=tmp/(label+'-a');bp=tmp/(label+'-b')
                config=dict(action='open_rpc',mcp_version=VERSION,input=v['input'],public_key_hex=v['public_key_hex'],utc=UTC*1000,mono=0)
                with contextlib.ExitStack() as stack:
                    def own(obj):stack.callback(obj.close);r['processes']+=1;return obj
                    c=own(GuardProcess(programs[client]['client'],cp,'create',label+'-client',log));s=own(GuardProcess(programs[server]['server'],sp,'create',label+'-server',log))
                    a1=own(Session(label+'-a','alice',ap,programs[client]['session'],log,profile='guard-fixture'));b=own(Session(label+'-b','bob',bp,programs[server]['session'],log,profile='guard-fixture'))
                    check_client(c.call(config),handoffs=0);require(s.call(dict(action='configure',instance='old',input=v['input']))['ok'],'configure');require(s.call(dict(action='rpc_setup',mcp_version=VERSION))['ok'],'RPC setup')
                    hq=a1.call('start')['wire_hex'];hr=b.call('respond',wire_hex=hq)['wire_hex'];a1.call('complete',wire_hex=hr);outer(hq);outer(hr,True)
                    complete=json.loads(decode(json.loads(bytes.fromhex(hr))['data']));sig=decode(complete.pop('sigB64'));verify(b'sage-hpke-complete|0.10.0\n'+canonical(complete),sig,pubs[bob])
                    verify(b'sage-execution-intent|0.10.0\0'+canonical(envelope['intent']),decode(envelope['proof']),pubs[alice])
                    ids=[];proof=None
                    for slot,status in enumerate(('pending','completed')):
                        id=f'00000000-0000-4000-8000-{101+slot:012d}';ids.append(id)
                        if slot:check_client(c.call(dict(action='tick',utc=(UTC+1)*1000,mono=1000)))
                        request=check_client(c.call(dict(action='begin',id=id)),rpc=True,id=id,intent=intent.hex(),handoffs=slot+1);check_request(request,id,intent)
                        clock=dict(unix=UTC+slot,mono_ms=slot*1000)
                        rq=a1.call('mcp-seal',target=VERSION,message_id=id,wire_hex=request,**clock)['wire_hex'];opened=b.call('mcp-open',target=VERSION,wire_hex=rq,**clock)
                        require(opened==dict(rpc_id=id,rpc_hex=request),'request handoff changed')
                        b.call('mcp-open','REJECT',target=VERSION,wire_hex=rq,**clock)
                        d=s.call(dict(action='rpc_dispatch',id=opened['rpc_id'],envelope_hex=opened['rpc_hex'],slot=slot));check_dispatch(d,intent,slot==0)
                        reply=s.call(dict(action='rpc_reply',slot=slot));require(reply['ok'],'reply');check_effect(reply,intent);reply=reply['rpc_hex'];proof=check_response(reply,id,status);signature_result(dict(proof,intent_hex=intent.hex()))
                        rs=b.call('mcp-reply',message_id=id,wire_hex=reply,**clock)['wire_hex'];got=a1.call('mcp-open-reply',message_id=id,wire_hex=rs,**clock)['wire_hex']
                        row=dict(pair=label,rpc_id=id,status=status,rpc_hex=request,received_rpc_hex=opened['rpc_hex'],reply_rpc_hex=reply,opened_reply_hex=got,request_wire_hex=rq,response_wire_hex=rs)
                        check_exchange(row,envelope,alice,bob);outer(rq);outer(rs,True)
                        check_client(c.call(dict(action='accept_rpc',id=id,mcp_version=VERSION,envelope_hex=got)),status=status,first=bool(slot),handoffs=slot+1)
                        check_client(c.call(dict(action='accept_rpc',id=id,mcp_version=VERSION,envelope_hex=got)),ok=False,handoffs=slot+1)
                        a1.call('mcp-open-reply','REJECT',message_id=id,wire_hex=rs,**clock)
                        if not slot:
                            done=s.call(dict(action='finish',output={'value':'ok'}));require(done['ok'],'finish');check_effect(done,intent)
                        duplicate=s.call(dict(action='rpc_reply',slot=slot));require(not duplicate['ok'],'repeated RPC reply');check_effect(duplicate,intent)
                        row.update(dispatch=d,consumption='PASS');r['exchanges'].append(row)
                    check_client(c.call(dict(action='close')),handoffs=2)
                states=[state('RESERVED'),state('EXECUTING'),state('COMPLETED','completed',{'value':'ok'})]
                for proof_row in validate_storage(sp.read_bytes(),intent,states):signature_result(proof_row)
                events=[event('open',intent_hex=intent.hex()),event('send',ids[0],UTC*1000),event('close',ids[0]),event('send',ids[1],(UTC+1)*1000),event('close',ids[1]),event('terminal',ids[1],result_hex=proof['envelope_hex'])]
                verify_rows(cp.read_bytes(),events);before=cp.read_bytes()
                with contextlib.ExitStack() as stack:
                    recovered=GuardProcess(programs[client]['client'],cp,'reopen',label+'-reopened',log);r['processes']+=1;stack.callback(recovered.close)
                    check_client(recovered.call(dict(config,utc=(UTC+2)*1000)),handoffs=0)
                    check_client(recovered.call(dict(action='begin',id='00000000-0000-4000-8000-000000000103')),ok=False,handoffs=0)
                    check_client(recovered.call(dict(action='accept_rpc',id=ids[1],mcp_version=VERSION,envelope_hex=reply)),ok=False,handoffs=0)
                    check_client(recovered.call(dict(action='close')),handoffs=0)
                require(cp.read_bytes()==before,'terminal state rewritten on restart');r['restarts'].append(dict(pair=label,status='PASS',journal_sha256=sha(before)))
                for name,path in [('client',cp),('server',sp),('session-a',ap),('session-b',bp)]:
                    require(not path.with_name(path.name+'.lock').exists(),'journal lock retained');retain(label+'-'+name+'.journal',path.read_bytes())
        checks=dict(public_key_hex=v['public_key_hex'],cases=result_audit);retain('result-signatures.json',canonical(checks))
        completed=subprocess.run(['node',str(ROOT/'scripts/check_guard_results010.js')],input=canonical(checks),capture_output=True,timeout=20)
        retain('result-audit.json',canonical(dict(exit_code=completed.returncode,stdout=completed.stdout.decode(),stderr=completed.stderr.decode())))
        require(completed.returncode==0,'independent result semantic verification')
        retain('signature-audit.json',canonical(audit));require(len(audit)==44 and r['processes']==20 and len(r['exchanges'])==8 and len(r['restarts'])==4,'coverage mismatch')
        r.update(status='PASS',signature_checks=len(audit),dispatch='PASS',durable_client_consumption='PASS')
    except Exception as e:r.update(status='FAIL',error=str(e));raise
    finally:
        raw.close();r['files']['raw.jsonl']=sha((out/'raw.jsonl').read_bytes());(out/'report.json').write_text(json.dumps(r,indent=2)+'\n')
    print('PASS: 20 processes, 8 protected exchanges, 4 durable client restarts, 44 independent signature checks')
if __name__=='__main__':main()
