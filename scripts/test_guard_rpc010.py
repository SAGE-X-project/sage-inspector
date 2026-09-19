"""Bounded real RPC dispatch/client processes and four cross-language exchanges."""
import argparse,copy,hashlib,itertools,json,select,subprocess,tempfile
from pathlib import Path
from test_record010_adapters import PINS
from test_guard_client010 import observation,event,verify_rows
from test_guard_results010 import validate_storage,state
from test_guard_dispatch010 import expected_effect
ROOT=Path(__file__).resolve().parents[1]
def wire(x):return json.dumps(x,ensure_ascii=False,separators=(',',':'),sort_keys=True)
def sha(b):return hashlib.sha256(b).hexdigest()
def check_request(raw,id,intent):
    v=json.loads(bytes.fromhex(raw))
    expected=dict(jsonrpc='2.0',id=id,method='tools/call',params=dict(name='sage_secure_call',arguments=dict(envelope=json.loads(intent))))
    if v!=expected:raise ValueError('client emitted wrong protected request')
def check_response(raw,id,status):
    v=json.loads(bytes.fromhex(raw))
    if set(v)!={'jsonrpc','id','result'} or v['jsonrpc']!='2.0' or v['id']!=id:raise ValueError('response identity')
    m=v['result'];e=m['structuredContent']
    if m!={'structuredContent':e,'content':[{'type':'text','text':wire(e)}],'isError':status!='completed'} or e['result']['status']!=status:raise ValueError('response mapping')
    return dict(envelope_hex=wire(e).encode().hex(),status=status,output={} if status=='pending' else {'value':'ok'},created=1700000000)
def check_client(o,*,ok=True,status='',first=False,handoffs=1,rpc=False,id='',intent=''):
    o=copy.deepcopy(o);raw=o.pop('rpc_hex','')
    if bool(raw)!=rpc:raise ValueError('wire observation')
    expected=observation(ok=ok,status=status,first=first,handoffs=handoffs,id=id,intent_hex=intent,output_hex=b'{"value":"ok"}'.hex() if first and status=='completed' else '')
    if o!=expected:raise ValueError('client delivery or invocation count')
    return raw

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('go','rust','go-client','rust-client','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--development',action='store_true');a=p.parse_args();out=a.output.resolve()
    if out.is_relative_to(ROOT/'docs/evidence'):p.error('preserve historical evidence')
    out.mkdir(parents=True,exist_ok=False)
    raw=(ROOT/'vectors/0.10.0/guard-rpc.json').read_bytes();v=json.loads(raw);intent=bytes.fromhex(v['input']['envelope_hex']);id=v['id'];version='2025-06-18'
    programs={n:getattr(a,n).resolve(strict=True) for n in PINS};clients={n:getattr(a,n+'_client').resolve(strict=True) for n in PINS}
    report=dict(kind='guard-rpc-bindings',status='RUNNING',conformance='NOT_ESTABLISHED',lifecycle=dict(NOT_RUN=37),development=a.development,fixture_sha256=sha(raw),inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),subjects={},requests=[],responses=[],exchanges=[],processes=0,files={})
    audit=[]
    def retain(name,b):(out/name).write_bytes(b);report['files'][name]=sha(b)
    class Process:
        def __init__(self,name,label,client,path):
            self.label,self.path=label,path;self.commands=[];self.output=[]
            self.p=subprocess.Popen([str((clients if client else programs)[name]),str(path),'create'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            report['processes']+=1
        def __enter__(self):return self
        def call(self,q):
            self.commands.append(q);self.p.stdin.write(wire(q)+'\n');self.p.stdin.flush()
            if not select.select([self.p.stdout],[],[],20)[0]:raise ValueError('bounded RPC timeout')
            line=self.p.stdout.readline();self.output.append(line)
            if not line:raise ValueError('adapter exited early')
            return json.loads(line)
        def __exit__(self,typ,value,tb):
            self.p.stdin.close()
            try:self.p.wait(timeout=20)
            except subprocess.TimeoutExpired:self.p.kill();self.p.wait();raise
            tail=self.p.stdout.read();err=self.p.stderr.read();self.p.stdout.close();self.p.stderr.close()
            record=dict(input=self.commands,input_sha256=sha(''.join(wire(q)+'\n' for q in self.commands).encode()),stdout=''.join(self.output)+tail,stderr=err,exit_code=self.p.returncode)
            retain(self.label+'.json',(json.dumps(record,indent=2)+'\n').encode())
            if self.path.exists():retain(self.label+'.journal',self.path.read_bytes())
            if typ is None and (self.p.returncode or tail or err or self.path.with_name(self.path.name+'.lock').exists()):raise ValueError('process exit/lock mismatch')
    config=dict(action='configure',instance='old',input=v['input'])
    client_config=dict(action='open_rpc',mcp_version=version,input=v['input'],public_key_hex=v['public_key_hex'],utc=1700000000000,mono=0)
    valid=next(q['wire_hex'] for q in v['requests'] if q['id']=='valid')
    def effects(o,count):
        if o['effects']!=([expected_effect(intent,'old')] if count else []):raise ValueError('unauthorized or repeated tool effect')
    try:
        if len(v['requests'])!=27 or len(v['responses'])!=22:raise ValueError('fixture membership')
        for n,pin in PINS.items():
            repo=ROOT.parent/('sage' if n=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            if not a.development and pin!=rev:raise ValueError('core revision mismatch')
            report['subjects'][n]=dict(revision=rev,adapter_sha256=sha(programs[n].read_bytes()),client_sha256=sha(clients[n].read_bytes()))
        with tempfile.TemporaryDirectory(prefix='guard-rpc-') as tmp:
            temp=Path(tmp)
            for n in PINS:
                for index,q in enumerate(v['requests']):
                    label=f'{n}-request-{index}';path=temp/label
                    with Process(n,label,False,path) as s:
                        if not s.call(config)['ok']:raise ValueError('setup')
                        setup=s.call(dict(action='rpc_setup',mcp_version=q['version']))
                        if setup['ok']!=(q['version']==version):raise ValueError('unsupported setup')
                        o=s.call(dict(action='rpc_dispatch',id=id,envelope_hex=q['wire_hex']))
                        if o['ok']!=q['accept'] or o['committed']!=q['accept'] or o['created']!=q['accept']:raise ValueError('request verdict')
                        effects(o,int(q['accept']))
                        retry=s.call(dict(action='rpc_dispatch',id=id,envelope_hex=valid))
                        if retry['ok']:raise ValueError('failed or accepted ID reused')
                        effects(retry,int(q['accept']))
                    validate_storage(path.read_bytes(),intent,[state('RESERVED'),state('EXECUTING')] if q['accept'] else [])
                    report['requests'].append(dict(subject=n,id=q['id'],status='PASS',evidence=label+'.json'))
                for index,q in enumerate(v['responses']):
                    label=f'{n}-response-{index}';path=temp/label
                    with Process(n,label,True,path) as c:
                        check_client(c.call(client_config),handoffs=0)
                        request=check_client(c.call(dict(action='begin',id=id)),rpc=True,id=id,intent=intent.hex());check_request(request,id,intent)
                        o=c.call(dict(action='accept_rpc',id=id,mcp_version=q['version'],envelope_hex=q['wire_hex']))
                        check_client(o,ok=q['accept'],status='completed' if q['accept'] else '',first=q['accept'])
                        check_client(c.call(dict(action='accept',id=id,envelope_hex=v['result_hex'])),ok=False)
                        check_client(c.call(dict(action='close')))
                    events=[event('open',intent_hex=intent.hex()),event('send',id,1700000000000),event('close',id)]
                    if q['accept']:events.append(event('terminal',id,result_hex=v['result_hex']))
                    verify_rows(path.read_bytes(),events)
                    report['responses'].append(dict(subject=n,id=q['id'],status='PASS',evidence=label+'.json'))
            for server,client in itertools.product(PINS,repeat=2):
                label=server+'-to-'+client;sp=temp/(label+'-server');cp=temp/(label+'-client');id2='00000000-0000-4000-8000-000000000102'
                with Process(server,label+'-server',False,sp) as s,Process(client,label+'-client',True,cp) as c:
                    check_client(c.call(client_config),handoffs=0);s.call(config);setup=s.call(dict(action='rpc_setup',mcp_version=version));assert setup['ok']
                    request=check_client(c.call(dict(action='begin',id=id)),rpc=True,id=id,intent=intent.hex());check_request(request,id,intent)
                    d=s.call(dict(action='rpc_dispatch',id=id,envelope_hex=request,slot=0));assert d['ok'] and d['committed'];effects(d,1)
                    pending=s.call(dict(action='rpc_reply',slot=0));assert pending['ok'];effects(pending,1);proof=check_response(pending['rpc_hex'],id,'pending');audit.append(dict(proof,intent_hex=intent.hex()))
                    check_client(c.call(dict(action='accept_rpc',id=id,mcp_version=version,envelope_hex=pending['rpc_hex'])),status='pending')
                    done=s.call(dict(action='finish',output={'value':'ok'}));assert done['ok'];effects(done,1)
                    again=s.call(dict(action='rpc_reply',slot=0));assert not again['ok'];effects(again,1)
                    check_client(c.call(dict(action='tick',utc=1700000001000,mono=1000)))
                    request=check_client(c.call(dict(action='begin',id=id2)),rpc=True,id=id2,intent=intent.hex(),handoffs=2);check_request(request,id2,intent)
                    d=s.call(dict(action='rpc_dispatch',id=id2,envelope_hex=request,slot=1));assert d['ok'] and not d['committed'] and d['state']=='COMPLETED';effects(d,1)
                    result=s.call(dict(action='rpc_reply',slot=1));assert result['ok'];effects(result,1);proof=check_response(result['rpc_hex'],id2,'completed');audit.append(dict(proof,intent_hex=intent.hex()))
                    check_client(c.call(dict(action='accept_rpc',id=id2,mcp_version=version,envelope_hex=result['rpc_hex'])),status='completed',first=True,handoffs=2)
                    check_client(c.call(dict(action='accept_rpc',id=id2,mcp_version=version,envelope_hex=result['rpc_hex'])),ok=False,handoffs=2)
                    check_client(c.call(dict(action='begin',id='00000000-0000-4000-8000-000000000103')),ok=False,handoffs=2)
                    check_client(c.call(dict(action='close')),handoffs=2)
                    assert not s.call(dict(action='rpc_reply',slot=1))['ok']
                audit.extend(validate_storage(sp.read_bytes(),intent,[state('RESERVED'),state('EXECUTING'),state('COMPLETED','completed',{'value':'ok'})]))
                verify_rows(cp.read_bytes(),[event('open',intent_hex=intent.hex()),event('send',id,1700000000000),event('close',id),event('send',id2,1700000001000),event('close',id2),event('terminal',id2,result_hex=proof['envelope_hex'])])
                audit.append(dict(proof,intent_hex=intent.hex()))
                report['exchanges'].append(dict(id=label,status='PASS'))
        evidence=dict(public_key_hex=v['public_key_hex'],cases=audit);retain('signatures.json',(json.dumps(evidence,indent=2)+'\n').encode())
        proof=subprocess.run(['node',str(ROOT/'scripts/check_guard_results010.js')],input=json.dumps(evidence),text=True,capture_output=True,timeout=20);retain('signature-audit.json',(json.dumps(dict(exit_code=proof.returncode,stdout=proof.stdout,stderr=proof.stderr))+'\n').encode())
        if proof.returncode:raise ValueError('independent proof verification')
        if report['processes']!=106 or len(audit)!=16 or len(report['files'])!=214:raise ValueError('coverage mismatch')
        report.update(status='PASS',independent_signature_checks=len(audit))
    except (OSError,ValueError,KeyError,AssertionError,subprocess.TimeoutExpired) as e:report.update(status='FAIL',error=str(e))
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));return report['status']!='PASS'
if __name__=='__main__':raise SystemExit(main())
