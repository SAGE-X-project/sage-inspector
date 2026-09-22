"""Independent observations for benign protected calls through native bridges."""
import hashlib
import json
import socket
import struct
from test_mcp_session010 import rpc_fixture
from test_completion010 import canonical, sign, encode, decode, verify, ALICE, BOB

OUTPUT = {'text':'inert public fixture'}


def intent():
    value = rpc_fixture()
    value['intent'].update(created=460, expires=760)
    value['proof'] = encode(sign(b'sage-execution-intent|0.10.0\0'+canonical(value['intent']),1))
    return canonical(value)


def relay(source, target, frames, errors):
    def exact(n):
        raw = bytearray()
        while len(raw) < n:
            part = source.recv(n-len(raw))
            if not part: raise EOFError('incomplete protected frame')
            raw.extend(part)
        return bytes(raw)
    try:
        while True:
            first = source.recv(1)
            if not first:
                target.shutdown(socket.SHUT_WR)
                return
            if len(frames) >= 8: raise ValueError('protected exchange limit')
            header = first+exact(3)
            length = struct.unpack('!I',header)[0]
            if not 1 <= length <= 32768: raise ValueError('frame length')
            raw = exact(length);frames.append(raw);target.sendall(header+raw)
    except Exception as error: errors.append(str(error))


def rows(path, header):
    lines = path.read_text().splitlines()
    if not lines or lines[0] != header: raise ValueError('journal header')
    return [json.loads(line) for line in lines[1:]]


def validate(directory, requests, responses, setup, *, effects=1, start=460000):
    if not __debug__: raise RuntimeError("signature verification requires Python assertions")
    original = (directory/'intent.json').read_bytes()
    env = json.loads(original);i = env['intent']
    verify(b'sage-execution-intent|0.10.0\0'+canonical(i),decode(env['proof']),1)
    client = json.loads((directory/'client.json').read_bytes())
    server = json.loads((directory/'server.json').read_bytes())
    count = len(requests)-4
    if not 1 <= count <= 4 or len(responses) != len(requests): raise ValueError('protected frame count')
    expected = dict(role='client',state='READY',status='completed',first_terminal=True,
                    output_hex=canonical(OUTPUT).hex(),attempts=count,repeat_denied=True)
    if client != expected or server != dict(role='server',state='READY',effects=effects): raise ValueError('delivery or effect observation')
    context = json.loads(requests[0])['context_id']
    nonces,ids = set(),set()
    for index,(request,response) in enumerate(zip(requests,responses)):
        q,w = json.loads(request),json.loads(response)
        for v in (q,w):
            if v['nonce'] in nonces or v['id'] in ids: raise ValueError('reused wire identity')
            nonces.add(v['nonce']);ids.add(v['id'])
        if index < 4: continue
        if (q['did'] != ALICE or q['recipient'] != BOB or w['did'] != BOB or w['recipient'] != ALICE
                or w['message_id'] != q['id'] or w['request_hash'] != encode(hashlib.sha256(canonical(q)).digest())):
            raise ValueError('protected correlation')
        if index == len(requests)-1:
            if w.get('success') is not True or w.get('error','') != '': raise ValueError('terminal transport status')
        elif w.get('success') is not False or w.get('error') != 'unavailable':
            raise ValueError('pending transport status')
        for v,key,role,domain in ((q,1,'initiator',b'sage-wire-request|0.10.0\n'),(w,2,'responder',b'sage-wire-response|0.10.0\n')):
            if (v['context_id'] != context or v['session_id'] != setup['session_id'] or v['encoding'] != 'session'
                    or v['version'] != '0.10.0' or v['role'] != role or v['kid'] != v['did']+'#signing-1'):
                raise ValueError('protected session binding')
            signed=dict(v);signature=decode(signed.pop('signature'));verify(domain+canonical(signed),signature,key)
    ledger = rows(directory/'server.journal','sage-execution-ledger|0.10.0')
    client_rows = rows(directory/'client.journal','sage-guard-client|0.10.0')
    execution = [r for r in ledger if r.get('state') == 'EXECUTING']
    completed = [r for r in ledger if r.get('state') == 'COMPLETED']
    if len(execution) != 1 or len(completed) != 1 or [row.get('state') for row in ledger] != ['RESERVED','EXECUTING','COMPLETED']: raise ValueError('execution transitions')
    for row in ledger:
        if (row['intent_hex'] != original.hex() or row['issuer'] != ALICE or row['recipient'] != BOB
                or row['call_id'] != i['call_id'] or row['nonce'] != i['nonce'] or row['expires'] != i['expires']):
            raise ValueError('execution intent binding')
    if len(client_rows) != 2*count+2 or client_rows[0] != dict(kind='open',id='',at=0,intent_hex=original.hex(),result_hex=''):
        raise ValueError('client journal shape')
    consumed = set()
    for n in range(count):
        sent,closed = client_rows[1+2*n:3+2*n]
        if (sent['kind'] != 'send' or sent['id'] in consumed or sent['at'] != start+1000*n
                or sent['intent_hex'] != '' or sent['result_hex'] != ''
                or closed != dict(kind='close',id=sent['id'],at=0,intent_hex='',result_hex='')):
            raise ValueError('client invocation consumption')
        consumed.add(sent['id'])
    if client_rows[-1].get('kind') != 'terminal' or client_rows[-1]['id'] != client_rows[-2]['id']:
        raise ValueError('terminal invocation')
    terminal = [r for r in client_rows if r.get('kind') == 'terminal']
    if len(terminal) != 1 or terminal[0]['result_hex'] != completed[0]['result_hex']: raise ValueError('terminal bytes differ')
    result = json.loads(bytes.fromhex(completed[0]['result_hex']));r=result['result']
    verify(b'sage-tool-result|0.10.0\0'+canonical(r),decode(result['proof']),2)
    if (r['issuer'] != BOB or r['recipient'] != ALICE or r['request_id'] != i['request_id']
            or r['call_id'] != i['call_id'] or r['intent_digest'] != hashlib.sha256(original).hexdigest()
            or r['status'] != 'completed' or r['output'] != OUTPUT
            or r['keyid'] != BOB+'#signing-1' or r['alg'] != 'ed25519' or r['version'] != '0.10.0'
            or not i['created'] <= r['created'] < r['expires'] <= i['expires']): raise ValueError('signed result binding')
    return dict(protected_exchanges=count,effects=effects,terminal_records=1,
                frames=2*len(requests),setup_signature_checks=setup['independent_signatures'],
                independent_signatures=setup['independent_signatures']+2*count+2,
                protected_signature_checks=2*count+2,execution_transitions=['RESERVED','EXECUTING','COMPLETED'])


def validate_recovery(directory, requests, responses, setup, mode):
    if mode not in ('server','client'): raise ValueError('recovery mode')
    before = (directory/'server.journal.before').read_bytes()
    if (directory/'server.journal').read_bytes() != before:
        raise ValueError('server journal changed after completed recovery')
    if mode == 'server':
        result = validate(directory, requests, responses, setup, effects=0, start=465000)
        if result['protected_exchanges'] != 1: raise ValueError('completed recovery did not reply immediately')
    else:
        if len(requests) != 4 or len(responses) != 4: raise ValueError('consumed client sent protected traffic')
        if json.loads((directory/'client.json').read_bytes()) != dict(role='client',state='READY',reopen_denied=True):
            raise ValueError('client reopen observation')
        if json.loads((directory/'server.json').read_bytes()) != dict(role='server',state='READY',effects=0):
            raise ValueError('reopened server effect observation')
        client_before = (directory/'client.journal.before').read_bytes()
        if (directory/'client.journal').read_bytes() != client_before:
            raise ValueError('consumed client journal changed')
        if len([r for r in rows(directory/'client.journal','sage-guard-client|0.10.0') if r.get('kind') == 'terminal']) != 1:
            raise ValueError('missing consumed terminal')
        result = dict(protected_exchanges=0,effects=0,terminal_records=1,frames=8,
                      independent_signatures=setup['independent_signatures'])
    result.update(recovery=mode,server_journal_unchanged=True)
    if mode == 'client': result['client_journal_unchanged'] = True
    return result
