"""Safe loopback WSS exchanges through the real Go and Rust envelope APIs."""
import argparse,hashlib,itertools,json,socket,ssl,subprocess,tempfile,threading
from pathlib import Path
import wsproto,h11
from http_tls010 import certificates,listener
from websocket010 import Peer
from test_completion010 import Actor,ROOT,digest,independent,canonical,verify,decode
from test_record010_adapters import PINS
from test_http_handshake010 import observe

def wire(a,action,**kw):return bytes.fromhex(a.call(action,**kw)['wire_hex'])
def audit(data,key,request=None):
 w=json.loads(data);sig=decode(w.pop('signature'));domain=b'sage-wire-request|0.10.0\n' if request is None else b'sage-wire-response|0.10.0\n';verify(domain+canonical(w),sig,key)
 if request is not None:
  q=json.loads(request);assert w['message_id']==q['id'];assert decode(w['request_hash'])==hashlib.sha256(canonical(q)).digest()

def scenario(a,b,kind,server_context,client_context):
 sock=listener();port=sock.getsockname()[1];host='localhost:'+str(port);results={};request=wire(a,'start');audit(request,1);fragment=kind in ('fragmented','ping-fragmented');ping=kind=='ping-fragmented';negative=kind in ('untrusted-ca','wrong-hostname')
 def server():
  try:
   conn,_=sock.accept();conn.settimeout(5)
   with conn:
    with server_context.wrap_socket(conn,server_side=True) as secured:
     results['server_tls']=secured.version();peer=Peer(secured,False);peer.upgrade(host,False);results['upgrade']=True
     q=peer.receive();assert q==request
     if kind=='close-pending':
      peer.close();assert peer.receive() is None;results['server']=peer.evidence();return
     results['core_receives']=1;r=wire(b,'respond',wire_hex=q.hex());audit(r,2,q);peer.send(r,fragment,ping)
     q=peer.receive();assert q is not None;audit(q,1);assert b.call('record-open',wire_hex=q.hex())['plaintext_hex']==b'WSS request'.hex();results['core_receives']+=1
     code='operation_failed' if kind=='application-error' else '';r=wire(b,'response-seal',message_id=json.loads(q)['id'],success=not code,error=code,wire_hex=b'WSS result'.hex());audit(r,2,q);peer.send(r,fragment,ping)
     if kind=='reverse':
      q=wire(b,'record-seal',wire_hex=b'reverse request'.hex());audit(q,2);peer.send(q);r=peer.receive();audit(r,1,q);v=b.call('response-open',wire_hex=r.hex());assert v['plaintext_hex']==b'reverse result'.hex();results['core_receives']+=1
     assert peer.receive() is None;b.call('close');results['server']=peer.evidence()
  except Exception as exc:results['server_error']=type(exc).__name__+': '+str(exc)
 worker=threading.Thread(target=server,daemon=True);worker.start()
 try:
  context=ssl.create_default_context() if kind=='untrusted-ca' else client_context
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=5) as conn:
    with context.wrap_socket(conn,server_hostname='wrong.example' if kind=='wrong-hostname' else 'localhost') as secured:
     assert not negative,'untrusted TLS accepted';results.update(client_tls=secured.version(),alpn=secured.selected_alpn_protocol(),certificate_verified=context.verify_mode==ssl.CERT_REQUIRED,hostname_verified=context.check_hostname)
     peer=Peer(secured,True);peer.upgrade(host,True);peer.send(request,fragment,ping);r=peer.receive()
     if kind=='close-pending':
      assert r is None;a.call('pending-close');assert observe(a,0,0,'NONE')['pending']=='CLOSED'
     else:
      independent(request,r);a.call('complete',wire_hex=r.hex());q=wire(a,'record-seal',wire_hex=b'WSS request'.hex());audit(q,1);peer.send(q,fragment,ping);r=peer.receive();audit(r,2,q);v=a.call('response-open',wire_hex=r.hex());assert v==dict(message_id=json.loads(q)['id'],success=kind!='application-error',error='operation_failed' if kind=='application-error' else '',plaintext_hex=b'WSS result'.hex())
      if kind=='reverse':
       q=peer.receive();audit(q,2);assert a.call('record-open',wire_hex=q.hex())['plaintext_hex']==b'reverse request'.hex();r=wire(a,'response-seal',message_id=json.loads(q)['id'],success=True,error='',wire_hex=b'reverse result'.hex());audit(r,1,q);peer.send(r)
      peer.close();assert peer.receive() is None;a.call('close')
     results['client']=peer.evidence()
  except ssl.SSLCertVerificationError:
   if not negative:raise
   results['certificate_rejected']=True;a.call('pending-close')
 finally:
  sock.close();worker.join(15);assert not worker.is_alive(),'server did not stop'
 if negative:
  assert results.get('certificate_rejected') and not results.get('upgrade') and results.get('core_receives',0)==0;assert observe(a,0,0,'NONE')['pending']=='CLOSED';observe(b,0,0,'NONE')
 else:
  assert 'server_error' not in results,results
  assert results['client_tls']==results['server_tls']=='TLSv1.3' and results['alpn']=='http/1.1' and results['certificate_verified'] and results['hostname_verified']
  assert results['client']['sent']==results['server']['received'] and results['server']['sent']==results['client']['received']
  assert results['client']['close_code']==results['server']['close_code']==1000
  if kind=='close-pending':observe(b,0,0,'NONE');assert results.get('core_receives',0)==0
  else:
   count=2 if kind=='reverse' else 1;observe(a,1,count,'CLOSED');observe(b,1,count,'CLOSED');assert results['core_receives']==(3 if kind=='reverse' else 2)
  if fragment:assert results['client']['data_frames']>len(results['client']['received']) and results['server']['data_frames']>len(results['server']['received'])
  if ping:assert results['client']['pings']>0 and results['client']['pongs']>0 and results['server']['pings']>0 and results['server']['pongs']>0
 return results

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('go','rust','output'):p.add_argument('--'+n,type=Path,required=True)
 args=p.parse_args();out=args.output.resolve()
 if ROOT/'docs/evidence' in (out,*out.parents):p.error('preserve historical evidence')
 out.mkdir(parents=True,exist_ok=False);raw=(out/'raw.jsonl').open('w');lock=threading.Lock()
 def log(v):
  with lock:raw.write(json.dumps(v)+'\n');raw.flush()
 fixture=ROOT/'vectors/0.10.0/websocket010.json';f=json.loads(fixture.read_text());programs={n:getattr(args,n).resolve() for n in PINS}
 report=dict(kind='websocket010',status='RUNNING',conformance='NOT_ESTABLISHED',scope=f['scope'],fixture_sha256=digest(fixture),requirements_sha256=digest(ROOT/'scripts/requirements-websocket010.txt'),subjects={},scenarios=[],raw='raw.jsonl',inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),tls_runtime=ssl.OPENSSL_VERSION,wsproto=wsproto.__version__,h11=h11.__version__)
 def save():(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 save()
 try:
  assert wsproto.__version__=='1.3.2' and h11.__version__=='0.16.0'
  for name,program in programs.items():
   repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();diff=subprocess.check_output(['git','diff','HEAD','--'],cwd=repo);assert rev==PINS[name] and not diff
   report['subjects'][name]=dict(revision=rev,executable_sha256=digest(program))
  with tempfile.TemporaryDirectory() as directory:
   tmp=Path(directory);certdir=tmp/'certs';certdir.mkdir();server_context,client_context,cert_hash=certificates(certdir);report['test_certificate_sha256']=cert_hash
   for sender,receiver in itertools.product(programs,repeat=2):
    for kind in f['cases']:
     label=sender+'-to-'+receiver+'-'+kind;a=Actor(label+'-a','alice',tmp/(label+'-a'),programs[sender],log);b=Actor(label+'-b','bob',tmp/(label+'-b'),programs[receiver],log)
     try:result=scenario(a,b,kind,server_context,client_context);report['scenarios'].append(dict(id=label,status='PASS',evidence=result));save()
     finally:
      try:a.close()
      finally:b.close()
  report['status']='PASS'
 except Exception as exc:report.update(status='FAIL',reason=str(exc));raise
 finally:raw.close();report['raw_sha256']=digest(out/'raw.jsonl');save()
 print(str(len(report['scenarios']))+' authenticated WebSocket scenarios passed')
if __name__=='__main__':main()
