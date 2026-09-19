"""Offline report integrity controls, not forged traffic or host bypass programs."""
import copy,json,unittest
from test_mcp_session010 import check_exchange,canonical,sha,encode,ALICE,BOB
class Reports(unittest.TestCase):
    def setUp(self):
        self.intent=dict(intent=dict(request_id='request',call_id='call'),proof='fixture')
        id='rpc';q=dict(jsonrpc='2.0',id=id,method='tools/call',params=dict(name='sage_secure_call',arguments=dict(envelope=self.intent)))
        e=dict(result=dict(intent_digest=sha(canonical(self.intent)),status='pending',issuer=BOB,recipient=ALICE,request_id='request',call_id='call'),proof='fixture')
        r=dict(jsonrpc='2.0',id=id,result=dict(structuredContent=e,content=[dict(type='text',text=canonical(e).decode())],isError=True))
        outer=dict(id='outer',did=ALICE,recipient=BOB,encoding='session')
        answer=dict(message_id='outer',did=BOB,recipient=ALICE,encoding='session',request_hash=encode(bytes.fromhex(sha(canonical(outer)))),success=False,error='unavailable')
        self.row=dict(rpc_id=id,status='pending',rpc_hex=canonical(q).hex(),received_rpc_hex=canonical(q).hex(),reply_rpc_hex=canonical(r).hex(),opened_reply_hex=canonical(r).hex(),request_wire_hex=canonical(outer).hex(),response_wire_hex=canonical(answer).hex())
    def test_expected(self):check_exchange(self.row,self.intent)
    def test_exact_bytes(self):
        for field in ('received_rpc_hex','opened_reply_hex'):
            row=copy.deepcopy(self.row);row[field]+='20'
            with self.assertRaises(ValueError):check_exchange(row,self.intent)
    def test_invocation_and_peer(self):
        for key,value in [('message_id','wrong'),('did',ALICE),('request_hash','wrong'),('success',True)]:
            row=copy.deepcopy(self.row);v=json.loads(bytes.fromhex(row['response_wire_hex']));v[key]=value;row['response_wire_hex']=canonical(v).hex()
            with self.assertRaises(ValueError):check_exchange(row,self.intent)
    def test_altered_request(self):
        row=copy.deepcopy(self.row);q=json.loads(bytes.fromhex(row['rpc_hex']));q['params']['name']='direct';row['rpc_hex']=row['received_rpc_hex']=canonical(q).hex()
        with self.assertRaises(ValueError):check_exchange(row,self.intent)
    def test_result_mapping(self):
        row=copy.deepcopy(self.row);r=json.loads(bytes.fromhex(row['reply_rpc_hex']));r['result']['content'][0]['text']='changed';row['reply_rpc_hex']=row['opened_reply_hex']=canonical(r).hex()
        with self.assertRaises(ValueError):check_exchange(row,self.intent)
if __name__=='__main__':unittest.main()
