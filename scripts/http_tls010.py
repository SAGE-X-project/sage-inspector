"""Bounded loopback-only TLS fixture transport; never a production server."""
import hashlib,socket,ssl,subprocess,threading,time
from pathlib import Path
from test_http_session010 import b64,body

def parse(raw,target,response=False):
 head,content=raw.split(b'\r\n\r\n',1);lines=head.decode('ascii').split('\r\n');authority=target.split('/')[2]
 fields=[line.split(':',1) for line in lines[1:]];fields=[[k.lower(),v.strip(' \t')] for k,v in fields]
 assert int(dict(fields)['content-length'])==len(content)
 return dict(method='' if response else lines[0].split(' ')[0],target='' if response else 'https://'+authority+lines[0].split(' ')[1],authority='' if response else dict(fields)['host'],status=int(lines[0].split(' ')[1]) if response else 0,headers=fields,body=b64(content))
def render(m):
 content=body(m)
 if m['status']:first='HTTP/1.1 '+str(m['status'])+' SAGE';fields=[]
 else:first=m['method']+' '+('/'+m['target'].split('/',3)[3])+' HTTP/1.1';fields=[['Host',m['authority']]]
 fields += [[k,v] for k,v in m['headers'] if k.lower() not in ('host','content-length','connection')]
 fields += [['Content-Length',str(len(content))],['Connection','close']]
 return (first+'\r\n'+'\r\n'.join(k+': '+v for k,v in fields)+'\r\n\r\n').encode()+content

def receive(sock):
 deadline=time.monotonic()+5;header=bytearray()
 def read(n):
  left=deadline-time.monotonic();assert left>0,'HTTP timeout';sock.settimeout(left);b=sock.recv(n);assert b,'truncated HTTP';return b
 while not header.endswith(b'\r\n\r\n'):
  assert len(header)<36868,'HTTP header bound';header.extend(read(1))
 lengths=[line.split(b':',1)[1].strip() for line in bytes(header).split(b'\r\n')[1:] if line.lower().startswith(b'content-length:')]
 assert len(lengths)==1 and lengths[0].isdigit();length=int(lengths[0]);assert 0<=length<=32768
 content=bytearray()
 while len(content)<length:content.extend(read(length-len(content)))
 return bytes(header+content)

def certificates(directory):
 directory=Path(directory)
 def run(*args):subprocess.run(['openssl',*args],cwd=directory,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
 run('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=SAGE local test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
 run('req','-new','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=localhost')
 (directory/'server.ext').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
 run('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','1','-extfile','server.ext')
 server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.minimum_version=ssl.TLSVersion.TLSv1_3;server.load_cert_chain(directory/'server.pem',directory/'server.key');server.set_alpn_protocols(['http/1.1'])
 client=ssl.create_default_context(cafile=str(directory/'ca.pem'));client.minimum_version=ssl.TLSVersion.TLSv1_3;client.set_alpn_protocols(['http/1.1'])
 assert client.check_hostname and client.verify_mode==ssl.CERT_REQUIRED
 return server,client,hashlib.sha256((directory/'server.pem').read_bytes()).hexdigest()

def listener():
 s=socket.socket();s.bind(('127.0.0.1',0));s.listen(1);s.settimeout(5);return s

def exchange(listener,server_context,client_context,request,handler,expected_tls_failure=False,hostname='localhost'):
 """Exactly one connection and one message; all endpoints are loopback sockets."""
 result={};port=listener.getsockname()[1]
 def serve():
  try:
   conn,_=listener.accept();conn.settimeout(5)
   with conn:
    with server_context.wrap_socket(conn,server_side=True) as secured:
     result['server_tls']=secured.version();raw=receive(secured);result['received_sha256']=hashlib.sha256(raw).hexdigest();result['handler_calls']=1
     secured.sendall(handler(raw))
  except Exception as exc:result['server_error']=type(exc).__name__
 worker=threading.Thread(target=serve,daemon=True);worker.start()
 try:
  with socket.create_connection(('127.0.0.1',port),timeout=5) as conn:
   with client_context.wrap_socket(conn,server_hostname=hostname) as secured:
    assert not expected_tls_failure,'untrusted TLS accepted'
    result.update(client_tls=secured.version(),alpn=secured.selected_alpn_protocol(),certificate_verified=client_context.verify_mode==ssl.CERT_REQUIRED,hostname_verified=client_context.check_hostname)
    secured.sendall(request);response=receive(secured)
 except ssl.SSLCertVerificationError:
  if not expected_tls_failure:raise
  response=None;result['certificate_rejected']=True
 finally:
  worker.join(10);assert not worker.is_alive(),'server did not terminate'
 if expected_tls_failure:assert result.get('certificate_rejected') and result.get('handler_calls',0)==0
 else:
  assert 'server_error' not in result,result
  assert result['client_tls']==result['server_tls']=='TLSv1.3' and result['alpn']=='http/1.1' and result['certificate_verified'] and result['hostname_verified']
  assert result['received_sha256']==hashlib.sha256(request).hexdigest()
 return response,result
