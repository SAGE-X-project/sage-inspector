"""Pure evidence rejection controls and harmless fragmented socket-pair capture."""
import copy
import hashlib
import json
from pathlib import Path
import socket
import struct
import threading
import unittest
from unittest.mock import patch
import run_mcp_setup_interop as bridge


def sample():
    requests, responses = [], []
    for n in range(4):
        q = dict(did=bridge.ALICE, recipient=bridge.BOB, id=str(n), nonce='q'+str(n),
                 encoding='session', signature='AA',context_id='ctx',role='initiator',version='0.10.0',
                 kid=bridge.ALICE+'#signing-1',session_id='session')
        w = dict(did=bridge.BOB, recipient=bridge.ALICE, message_id=str(n), nonce='r'+str(n),
                 encoding='session', signature='AA',context_id='ctx',role='responder',version='0.10.0',
                 kid=bridge.BOB+'#signing-1',session_id='session',success=True, request_hash=bridge.encode(hashlib.sha256(bridge.canonical(q)).digest()))
        requests.append(bridge.canonical(q)); responses.append(bridge.canonical(w))
    return requests, responses


class BridgeTests(unittest.TestCase):
    @patch.object(bridge, 'verify')
    @patch.object(bridge, 'independent', return_value=({'ctx':'ctx'}, 'hash', 'session'))
    def test_exact_shape_and_correlations(self, handshake, verify):
        q, r = sample()
        self.assertEqual(bridge.validate(q,r)['frames'],8)
        self.assertEqual(verify.call_count,6)
        for mode in ('missing','identity','correlation','plaintext','nonce','duplicate-id','session','context','success'):
            requests,responses = copy.deepcopy((q,r))
            if mode == 'missing': requests.pop()
            else:
                target = json.loads(responses[2])
                key,value = {'identity':('did',bridge.ALICE),'correlation':('request_hash','other'),
                             'plaintext':('encoding','plain'),'nonce':('nonce','r1'),
                             'duplicate-id':('message_id','1'),'session':('session_id','other'),
                             'context':('context_id','other'),'success':('success',False)}[mode]
                target[key] = value;responses[2] = bridge.canonical(target)
            with self.assertRaises(ValueError,msg=mode): bridge.validate(requests,responses)

    @patch.object(bridge, 'independent', side_effect=ValueError('signature'))
    def test_signature_failure_propagates(self, _):
        with self.assertRaises(ValueError): bridge.validate(*sample())

    def test_fragmented_capture_preserves_exact_bytes(self):
        a,b = socket.socketpair();c,d = socket.socketpair()
        for s in (a,b,c,d): s.settimeout(2)
        frames,errors = [],[]
        task = threading.Thread(target=bridge.relay,args=(b,c,frames,errors));task.start()
        expected = [b'local one',b'two',b'three',b'four']
        try:
            for raw in expected:
                frame = struct.pack('!I',len(raw))+raw
                a.sendall(frame[:2]);a.sendall(frame[2:])
                self.assertEqual(bridge.exact(d,len(frame)),frame)
            task.join(2)
            self.assertFalse(task.is_alive());self.assertEqual(errors,[]);self.assertEqual(frames,expected)
        finally:
            for s in (a,b,c,d): s.close()
            task.join(2)

    def test_invalid_length_is_local_unit_input(self):
        class Header:
            def recv(self,n): return struct.pack('!I',0)
        class NoSend:
            def sendall(self,_): raise AssertionError('must not forward')
        frames,errors = [],[]
        bridge.relay(Header(),NoSend(),frames,errors)
        self.assertEqual(frames,[]);self.assertEqual(errors,['frame length'])


if __name__ == '__main__': unittest.main()
