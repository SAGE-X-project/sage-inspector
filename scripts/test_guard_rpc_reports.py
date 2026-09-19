"""Offline controls for RPC identity, carriage and output-consumption evidence."""
import copy,json,unittest
from test_guard_rpc010 import ROOT,wire,check_request,check_response,check_client
from test_guard_client010 import observation
class RPCReports(unittest.TestCase):
    def setUp(self):
        self.v=json.loads((ROOT/'vectors/0.10.0/guard-rpc.json').read_text());self.id=self.v['id'];self.intent=bytes.fromhex(self.v['input']['envelope_hex'])
    def test_actual_shape_controls(self):
        check_request(self.v['requests'][0]['wire_hex'],self.id,self.intent)
        check_response(self.v['responses'][0]['wire_hex'],self.id,'completed')
    def test_wrong_request_mapping(self):
        base=json.loads(bytes.fromhex(self.v['requests'][0]['wire_hex']))
        for kind in ['id','tool','arguments','notification']:
            q=copy.deepcopy(base)
            if kind=='id':q['id']='other'
            if kind=='tool':q['params']['name']='read'
            if kind=='arguments':q['params']['arguments']['path']='unsigned'
            if kind=='notification':del q['id']
            with self.assertRaises(ValueError):check_request(wire(q).encode().hex(),self.id,self.intent)
    def test_wrong_response_mapping(self):
        base=json.loads(bytes.fromhex(self.v['responses'][0]['wire_hex']))
        for kind in ['id','flag','text','extra']:
            q=copy.deepcopy(base)
            if kind=='id':q['id']='other'
            if kind=='flag':q['result']['isError']=True
            if kind=='text':q['result']['content'][0]['text']='{}'
            if kind=='extra':q['extra']='unsigned'
            with self.assertRaises(ValueError):check_response(wire(q).encode().hex(),self.id,'completed')
    def test_unverified_output(self):
        o=observation(ok=False,handoffs=1,output_hex=b'{"value":"ok"}'.hex())
        with self.assertRaises(ValueError):check_client(o,ok=False)
    def test_duplicate_delivery(self):
        o=observation(status='completed',first=True,handoffs=1,output_hex=b'{"value":"ok"}'.hex())
        with self.assertRaises(ValueError):check_client(o,ok=False)
    def test_missing_actual_send(self):
        o=observation(id=self.id,intent_hex=self.intent.hex(),handoffs=1)
        with self.assertRaises(ValueError):check_client(o,rpc=True,id=self.id,intent=self.intent.hex())
if __name__=='__main__':unittest.main()
