"""Pure evidence rejection controls and harmless fragmented socket-pair capture."""
import copy
import hashlib
import json
from pathlib import Path
import socket
import struct
import threading
import tempfile
import time
import unittest
from unittest.mock import patch
import run_mcp_setup_interop as bridge


def sample():
    requests, responses = [], []
    for n in range(4):
        q = dict(did=bridge.ALICE, recipient=bridge.BOB, id=str(n), nonce='q'+str(n),
                 encoding='session', signature='AA',context_id='ctx',role='initiator',version='0.10.0',
                 kid=bridge.ALICE+'#signing-1',session_id='session')
        if n == 0: q['payload'] = bridge.encode(b'{}')
        w = dict(did=bridge.BOB, recipient=bridge.ALICE, message_id=str(n), nonce='r'+str(n),
                 encoding='session', signature='AA',context_id='ctx',role='responder',version='0.10.0',
                 kid=bridge.BOB+'#signing-1',session_id='session',success=True, request_hash=bridge.encode(hashlib.sha256(bridge.canonical(q)).digest()))
        if n == 0: w['data'] = bridge.encode(b'{}')
        requests.append(bridge.canonical(q)); responses.append(bridge.canonical(w))
    return requests, responses


class BridgeTests(unittest.TestCase):
    def test_pending_reply_waits_for_responder_settlement(self):
        import mcp_protected_support as flow
        raw = b'{"success":false,"error":"unavailable"}'
        wire = struct.pack('!I', len(raw)) + raw
        entered, release = threading.Event(), threading.Event()
        class Source:
            def __init__(self): self.remaining = wire
            def recv(self, n):
                result, self.remaining = self.remaining[:n], self.remaining[n:]
                return result
        class Target:
            def __init__(self): self.sent = []; self.closed = False
            def sendall(self, value): self.sent.append(value)
            def shutdown(self, _): self.closed = True
        def settled(path, processes, end):
            self.assertEqual(path.name, 'reply-settled')
            self.assertEqual(processes, ['server'])
            self.assertEqual(end, deadline)
            entered.set()
            if not release.wait(2): raise TimeoutError('unit rendezvous')
            return 'claimed-after-reply:1\n'
        frames, errors, target = [b'setup'] * 4, [], Target()
        deadline = time.monotonic() + 2
        with tempfile.TemporaryDirectory() as directory, patch.object(bridge, 'wait_file', side_effect=settled):
            callback = lambda value, index: bridge.settle_pending_reply(
                Path(directory), ['server'], deadline, value, index)
            task = threading.Thread(target=flow.relay,
                                    args=(Source(), target, frames, errors, callback))
            task.start()
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(target.sent, [])
                self.assertEqual(frames[-1], raw)
                release.set(); task.join(2)
                self.assertFalse(task.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(target.sent, [wire])
                self.assertTrue(target.closed)
            finally:
                release.set(); task.join(2)

    @patch.object(bridge, 'wait_file')
    def test_only_protected_pending_replies_need_marker(self, wait):
        for raw, index in [(b'not parsed for setup', 0),
                           (b'{"success":true}', 4),
                           (b'{"success":false,"error":"policy_denied"}', 4)]:
            bridge.settle_pending_reply(Path('fixture'), [], time.monotonic() + 2, raw, index)
        wait.assert_not_called()

    @patch.object(bridge, 'wait_file')
    def test_pending_reply_rejects_missing_or_invalid_settlement(self, wait):
        raw = b'{"success":false,"error":"unavailable"}'
        wait.return_value = 'claimed\n'
        with self.assertRaisesRegex(ValueError, 'scheduling marker'):
            bridge.settle_pending_reply(Path('fixture'), [], time.monotonic() + 2, raw, 4)
        for error in [TimeoutError('bridge rendezvous'), ValueError('bridge exited before rendezvous')]:
            wait.side_effect = error
            with self.assertRaises(type(error)):
                bridge.settle_pending_reply(Path('fixture'), [], time.monotonic() + 2, raw, 4)

    def test_later_pending_reply_waits_for_its_own_generation(self):
        class Alive:
            def poll(self): return None
        raw = b'{"success":false,"error":"unavailable"}'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'reply-settled'
            path.write_text('claimed-after-reply:1\n')
            with patch.object(bridge.time, 'sleep', side_effect=lambda _: path.write_text('claimed-after-reply:2\n')) as pause:
                bridge.settle_pending_reply(Path(directory), [Alive()], time.monotonic() + 2, raw, 5)
            pause.assert_called_once()
            path.write_text('claimed-after-reply:3\n')
            with self.assertRaisesRegex(ValueError, 'scheduling marker'):
                bridge.settle_pending_reply(Path(directory), [Alive()], time.monotonic() + 2, raw, 5)

    @patch.object(bridge, 'wait_file', return_value='claimed-after-reply:1\n')
    def test_stale_marker_cannot_hide_exit_or_deadline(self, wait):
        class Exited:
            def poll(self): return 0
        class Alive:
            def poll(self): return None
        raw = b'{"success":false,"error":"unavailable"}'
        with self.assertRaisesRegex(ValueError, 'exited before reply settlement'):
            bridge.settle_pending_reply(Path('fixture'), [Exited()], time.monotonic() + 2, raw, 5)
        with patch.object(bridge.time, 'monotonic', side_effect=[0, 2]), patch.object(bridge.time, 'sleep'):
            with self.assertRaisesRegex(TimeoutError, 'reply settlement'):
                bridge.settle_pending_reply(Path('fixture'), [Alive()], 1, raw, 5)

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

    @patch.object(bridge, 'independent')
    def test_ambiguous_handshake_rejected_before_signature_normalization(self, verifier):
        for index,field in ((0,'payload'),(1,'data')):
            q,r=sample();frames=(q,r)[index];value=json.loads(frames[0])
            value[field]=bridge.encode(b'{"nested":{"v":1,"v":2}}')
            frames[0]=bridge.canonical(value)
            with self.assertRaisesRegex(ValueError,'duplicate JSON key'):bridge.validate(q,r)
        verifier.assert_not_called()

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
