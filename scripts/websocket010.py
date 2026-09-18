"""Bounded Inspector WebSocket fixture, not a production transport library."""
from collections import deque
import hashlib,json,time
from wsproto import WSConnection,ConnectionType
from wsproto.events import Request,AcceptConnection,TextMessage,BytesMessage,Ping,Pong,CloseConnection

MAX_MESSAGE=32768
class ProfileError(ValueError):pass

def validate_upgrade(event,host=None):
 if isinstance(event,Request):
  if event.host!=host or event.target!='/messages' or event.extensions or event.subprotocols:raise ProfileError('unexpected upgrade')
 elif isinstance(event,AcceptConnection):
  if event.extensions or event.subprotocol is not None:raise ProfileError('unexpected negotiation')
 else:raise ProfileError('missing upgrade')

class Reassembly:
 def __init__(self):self.parts=[];self.size=0;self.frames=0;self.closed=False
 def close(self):self.parts.clear();self.size=0;self.closed=True
 def feed(self,event):
  if self.closed:raise ProfileError('closed')
  if not isinstance(event,TextMessage):self.close();raise ProfileError('text required')
  value=event.data.encode('utf-8');self.size+=len(value);self.frames+=int(event.frame_finished)
  if self.size>MAX_MESSAGE or self.frames>64:self.close();raise ProfileError('message bound')
  self.parts.append(value)
  if not event.message_finished:return None
  data=b''.join(self.parts);self.parts=[];self.size=0;self.frames=0
  try:decoded=json.loads(data)
  except (ValueError,UnicodeError):self.close();raise ProfileError('one JSON envelope required')
  if not isinstance(decoded,dict):self.close();raise ProfileError('envelope object required')
  return data

class Peer:
 def __init__(self,sock,client):
  self.sock=sock;self.ws=WSConnection(ConnectionType.CLIENT if client else ConnectionType.SERVER);self.queue=deque();self.assembly=Reassembly();self.upgraded=False;self.raw_count=0;self.controls=0;self.messages=0;self.sent=[];self.received=[];self.close_code=None;self.pings=0;self.pongs=0;self.data_frames=0
 def send_event(self,event):self.sock.sendall(self.ws.send(event))
 def event(self,deadline):
  while not self.queue:
   left=deadline-time.monotonic()
   if left<=0:raise ProfileError('deadline')
   self.sock.settimeout(left);chunk=self.sock.recv(4096);self.raw_count+=len(chunk)
   if self.raw_count>(262144 if self.upgraded else 8192):raise ProfileError('connection bound')
   self.ws.receive_data(chunk or None);self.queue.extend(self.ws.events())
   if not chunk and not self.queue:raise ProfileError('unexpected EOF')
  return self.queue.popleft()
 def upgrade(self,host,client):
  if client:self.send_event(Request(host=host,target='/messages'))
  event=self.event(time.monotonic()+5);validate_upgrade(event,None if client else host)
  if not client:self.send_event(AcceptConnection())
  self.upgraded=True
 def send(self,data,fragment=False,ping=False):
  if len(data)>MAX_MESSAGE:raise ProfileError('outgoing bound')
  text=data.decode('utf-8');self.sent.append(hashlib.sha256(data).hexdigest())
  if fragment:
   at=max(1,len(text)//2);self.send_event(TextMessage(data=text[:at],message_finished=False))
   if ping:self.send_event(Ping(payload=b'fixture'))
   self.send_event(TextMessage(data=text[at:]))
  else:self.send_event(TextMessage(data=text))
 def receive(self):
  deadline=time.monotonic()+10
  while True:
   event=self.event(deadline)
   if isinstance(event,(Ping,Pong)):
    self.controls+=1
    if self.controls>32:raise ProfileError('control bound')
    if isinstance(event,Ping):self.pings+=1;self.send_event(event.response())
    else:self.pongs+=1
   elif isinstance(event,CloseConnection):
    self.assembly.close();self.close_code=event.code
    if self.ws.state.name=='REMOTE_CLOSING':self.send_event(event.response())
    if event.code!=1000:raise ProfileError('abnormal close')
    return None
   else:
    if isinstance(event,TextMessage):self.data_frames+=int(event.frame_finished)
    data=self.assembly.feed(event)
    if data is not None:
     self.messages+=1
     if self.messages>16:raise ProfileError('message count')
     self.received.append(hashlib.sha256(data).hexdigest());return data
 def close(self):self.send_event(CloseConnection(code=1000,reason=''))
 def evidence(self):return dict(sent=self.sent,received=self.received,close_code=self.close_code,pings=self.pings,pongs=self.pongs,raw_bytes=self.raw_count,data_frames=self.data_frames)
