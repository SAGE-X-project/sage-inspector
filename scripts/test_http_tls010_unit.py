"""Offline bounded framing checks for the loopback fixture transport."""
import unittest
from unittest.mock import patch
from http_tls010 import receive,parse,render
from test_http_session010 import b64
class SocketBytes:
 def __init__(self,b):self.b=b
 def settimeout(self,t):assert 0<t<=5
 def recv(self,n):out,self.b=self.b[:n],self.b[n:];return out
class TLSFixtureTests(unittest.TestCase):
 def message(self):return b'POST /messages HTTP/1.1\r\nHost: localhost:8443\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
 def test_exact_body(self):
  raw=self.message();m=parse(raw,'https://localhost:8443/messages');self.assertEqual(m['body'],b64(b'{}'));self.assertEqual(m['authority'],'localhost:8443');self.assertEqual(render(m).lower(),raw.lower())
 def test_uncombined_fields(self):
  raw=self.message().replace(b'Content-Length:',b'Signature: first\r\nSIGNATURE: second\r\nContent-Length:');m=parse(raw,'https://localhost:8443/messages');self.assertEqual([v for k,v in m['headers'] if k=='signature'],['first','second'])
 def test_single_message_only(self):
  raw=self.message();s=SocketBytes(raw+b'not another dispatch');self.assertEqual(receive(s),raw);self.assertEqual(s.b,b'not another dispatch')
 def test_truncated_body(self):
  with self.assertRaises(AssertionError):receive(SocketBytes(self.message()[:-1]))
 def test_duplicate_length(self):
  with self.assertRaises(AssertionError):receive(SocketBytes(self.message().replace(b'Content-Length:',b'Content-Length: 2\r\nContent-Length:')))
 def test_body_limit(self):
  with self.assertRaises(AssertionError):receive(SocketBytes(self.message().replace(b'Content-Length: 2',b'Content-Length: 32769')))
 def test_header_limit(self):
  with self.assertRaises(AssertionError):receive(SocketBytes(b'x'*36869))
 def test_absolute_timeout(self):
  with patch('http_tls010.time.monotonic',side_effect=[0,6]):
   with self.assertRaises(AssertionError):receive(SocketBytes(self.message()))
if __name__=='__main__':unittest.main()
