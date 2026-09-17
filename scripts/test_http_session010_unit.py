"""Independent signature-base and bounded mutation helper checks."""
import copy,unittest
from test_http_session010 import b64,headers,field,content_digest,signature_base,resign,mutate
from test_completion010 import verify
import base64

class HTTPOracleTests(unittest.TestCase):
 def message(self):
  m=dict(method='POST',target='https://agent.example/messages?x=1',authority='agent.example',status=0,body=b64(b'{}'),headers=[['content-type','application/json'],['x-sage-did','did:example:alice'],['x-sage-version','0.10.0'],['signature-input','sig1=("@method");created=100']]);field(m,'content-digest',content_digest(m));resign(m,1);return m
 def test_exact_request_base(self):
  m=self.message();self.assertEqual(signature_base(m),('\n'.join(['"@method": POST','"@target-uri": https://agent.example/messages?x=1','"@authority": agent.example','"content-type": application/json','"content-digest": sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:','"x-sage-did": did:example:alice','"x-sage-version": 0.10.0','"@signature-params": ("@method");created=100'])).encode())
 def test_exact_retained_request_signature(self):
  q=self.message();r=copy.deepcopy(q);r.update(method='',target='',authority='',status=200);data=signature_base(r,q).decode();self.assertIn('"signature";req: '+headers(q)['signature']+'\n',data);self.assertTrue(data.startswith('"@status": 200\n'));q2=copy.deepcopy(q);field(q2,'signature','different');self.assertNotEqual(signature_base(r,q),signature_base(r,q2))
 def test_signed_wrong_method_is_not_a_broken_signature(self):
  m=mutate(self.message(),'request-method',1);self.assertEqual(m['method'],'GET');sig=base64.b64decode(headers(m)['signature'][6:-1]);verify(signature_base(m),sig,1)
 def test_digest_mutation_preserves_old_digest(self):
  q=self.message();m=mutate(q,'body-digest',1);self.assertEqual(headers(q)['content-digest'],headers(m)['content-digest']);self.assertNotEqual(content_digest(m),headers(m)['content-digest']);self.assertEqual(q['body'],b64(b'{}'))
 def test_duplicate_occurrences_are_preserved(self):
  q=self.message();m=mutate(q,'duplicate-signature',1);self.assertEqual(sum(k.lower()=='signature' for k,v in m['headers']),2);self.assertEqual(len(m['headers']),len(q['headers'])+1)
if __name__=='__main__':unittest.main()
