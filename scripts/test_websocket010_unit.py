"""Offline event and byte parsing checks. No sockets or core processes."""
import unittest
from wsproto import WSConnection,ConnectionType
from wsproto.events import Request,AcceptConnection,TextMessage,BytesMessage,CloseConnection
from websocket010 import Reassembly,ProfileError,validate_upgrade,MAX_MESSAGE,Peer
from unittest.mock import patch
from wsproto.extensions import PerMessageDeflate

class WebSocketTests(unittest.TestCase):
 def test_fragment_waits_for_completion(self):
  r=Reassembly();self.assertIsNone(r.feed(TextMessage(data='{"a":',message_finished=False)));self.assertEqual(r.feed(TextMessage(data='1}')),b'{"a":1}')
 def test_exact_size(self):
  data='{"a":"'+'x'*(MAX_MESSAGE-8)+'"}';self.assertEqual(len(Reassembly().feed(TextMessage(data=data))),MAX_MESSAGE)
 def test_cumulative_size(self):
  r=Reassembly();r.feed(TextMessage(data='x'*MAX_MESSAGE,message_finished=False))
  with self.assertRaises(ProfileError):r.feed(TextMessage(data='x',message_finished=False))
  self.assertTrue(r.closed);self.assertEqual(r.size,0)
 def test_utf8_byte_size(self):
  with self.assertRaises(ProfileError):Reassembly().feed(TextMessage(data='é'*(MAX_MESSAGE//2+1)))
 def test_fragment_count(self):
  r=Reassembly()
  for _ in range(64):r.feed(TextMessage(data='',message_finished=False))
  with self.assertRaises(ProfileError):r.feed(TextMessage(data='',message_finished=False))
 def test_binary_rejected(self):
  with self.assertRaises(ProfileError):Reassembly().feed(BytesMessage(data=b'{}'))
 def test_one_object(self):
  for data in ['{}{}','[]','null','{"x":']:
   with self.assertRaises(ProfileError):Reassembly().feed(TextMessage(data=data))
 def test_close_discards_partial(self):
  r=Reassembly();r.feed(TextMessage(data='{',message_finished=False));r.close();self.assertEqual(r.parts,[])
  with self.assertRaises(ProfileError):r.feed(TextMessage(data='}'))
 def test_upgrade_policy(self):
  validate_upgrade(Request(host='localhost:1234',target='/messages'),'localhost:1234');validate_upgrade(AcceptConnection())
  for event in [Request(host='other',target='/messages'),Request(host='localhost:1234',target='/other'),Request(host='localhost:1234',target='/messages',extensions=['permessage-deflate']),AcceptConnection(subprotocol='other')]:
   with self.assertRaises(ProfileError):validate_upgrade(event,'localhost:1234')
 def connected(self):
  a=WSConnection(ConnectionType.CLIENT);b=WSConnection(ConnectionType.SERVER);b.receive_data(a.send(Request(host='localhost',target='/messages')));list(b.events());a.receive_data(b.send(AcceptConnection()));list(a.events());return a,b
 def test_real_parser_fragmented_utf8(self):
  a,b=self.connected();raw=a.send(TextMessage(data='{"x":"é',message_finished=False))+a.send(TextMessage(data='"}'));r=Reassembly();out=[]
  for byte in raw:
   b.receive_data(bytes([byte]))
   for event in b.events():
    v=r.feed(event)
    if v is not None:out.append(v)
  self.assertEqual(out,['{"x":"é"}'.encode()])
 def test_invalid_frames_offline(self):
  # Fixed minimal malformed frames; never sent to a socket.
  for raw in [bytes.fromhex('81027b7d'),bytes.fromhex('c18000000000'),bytes.fromhex('818100000000ff'),bytes.fromhex('808000000000')]:
   _,b=self.connected();b.receive_data(raw);events=list(b.events());self.assertTrue(any(isinstance(e,CloseConnection) and e.code in (1002,1007) for e in events));self.assertFalse(any(isinstance(e,TextMessage) for e in events))
 def test_negotiated_compression_rejected(self):
  with self.assertRaises(ProfileError):validate_upgrade(AcceptConnection(extensions=[PerMessageDeflate()]))
 def test_real_binary_parser_rejected(self):
  a,b=self.connected();b.receive_data(a.send(BytesMessage(data=b'{}')))
  with self.assertRaises(ProfileError):
   for event in b.events():Reassembly().feed(event)
 def test_two_messages_remain_separate(self):
  a,b=self.connected();b.receive_data(a.send(TextMessage(data='{"a":1}'))+a.send(TextMessage(data='{"b":2}')));r=Reassembly()
  self.assertEqual([r.feed(e) for e in b.events()],[b'{"a":1}',b'{"b":2}'])
 def test_deadline(self):
  with patch('websocket010.time.monotonic',return_value=11):
   with self.assertRaises(ProfileError):Peer(None,True).event(10)
 def test_upgrade_byte_bound(self):
  class Input:
   def settimeout(self,t):pass
   def recv(self,n):return b'x'*4096
  p=Peer(Input(),False);p.raw_count=8192
  with self.assertRaises(ProfileError):p.event(10**20)
 def test_abnormal_eof(self):
  class Input:
   def settimeout(self,t):pass
   def recv(self,n):return b''
  p=Peer(Input(),True);p.ws,_=self.connected();p.upgraded=True
  with self.assertRaises(ProfileError):p.receive()
if __name__=='__main__':unittest.main()
