"""Independent published RFC signature and profile vector helper checks."""
import copy,json,subprocess,unittest
from test_completion010 import ROOT
from test_http_serialization010 import instantiate
NODE="""const c=require('crypto'),fs=require('fs'),v=JSON.parse(fs.readFileSync(0,'utf8'));const key=c.createPublicKey({key:Buffer.from(v.public_key,'base64'),format:'der',type:'spki'});process.stdout.write(String(c.verify(null,Buffer.from(v.base),key,Buffer.from(v.signature,'base64'))));"""
class SerializationTests(unittest.TestCase):
 def example(self):return json.loads((ROOT/'vectors/0.10.0/rfc9421-ed25519.json').read_text())
 def verify(self,v):return subprocess.check_output(['node','-e',NODE],input=json.dumps(v),text=True,timeout=10)=='true'
 def test_published_ed25519_signature(self):self.assertTrue(self.verify(self.example()))
 def test_base_bytes_matter(self):
  for tail in ('\n',' '):
   v=self.example();v['base']+=tail;self.assertFalse(self.verify(v))
 def test_parameter_order_matters(self):
  v=self.example();v['base']=v['base'].replace(';created=1618884473;keyid="test-key-ed25519"',';keyid="test-key-ed25519";created=1618884473');self.assertFalse(self.verify(v))
 def test_template_preserves_serialization(self):
  self.assertEqual(instantiate('; nonce="x"; keyid="y";created=100',';keyid="new";nonce="fresh"'),'; nonce="fresh"; keyid="new";created=100')
 def test_fixture_contract(self):
  f=json.loads((ROOT/'vectors/0.10.0/http-serialization010.json').read_text());self.assertEqual(len(f['structured_fields']),34);self.assertEqual(len(f['uris']),17)
  self.assertEqual(len({c['id'] for c in f['structured_fields']}),34)
if __name__=='__main__':unittest.main()
