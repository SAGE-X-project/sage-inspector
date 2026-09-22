"""Independent decryption and semantic binding for public native MCP fixture records."""
import json
from pathlib import Path
import subprocess

from mcp_evidence_json import loads as strict_json, equal as typed_equal
from test_completion010 import canonical, decode, verify, ALICE, BOB

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT/'scripts/check_mcp_record_plaintext.js'


def _secret(path):
    value = strict_json(path.read_bytes())
    if (set(value) != {'fixture','seed_hex','th_hex','session_id'}
            or value['fixture'] != 'public-test-only'
            or not isinstance(value['seed_hex'],str) or len(value['seed_hex']) != 64
            or not isinstance(value['th_hex'],str) or len(value['th_hex']) != 64
            or any(c not in '0123456789abcdef' for c in value['seed_hex']+value['th_hex'])
            or not isinstance(value['session_id'],str)):
        raise ValueError('invalid test-only session secret evidence')
    return value


def _jobs(secret, requests, responses):
    jobs=[]
    for direction, frames, field in ((0,requests,'payload'),(1,responses,'data')):
        for raw in frames[1:]:
            outer = strict_json(raw)
            wire = decode(outer[field])
            unsigned = dict(outer)
            for name in ('payload','data','signature'):
                unsigned.pop(name,None)
            jobs.append(dict(direction=direction,seed_hex=secret['seed_hex'],th_hex=secret['th_hex'],
                             wire_hex=wire.hex(),aad_hex=canonical(unsigned).hex()))
    return jobs


def decrypt(directory, requests, responses, setup):
    directory=Path(directory)
    client=_secret(directory/'crypto-client.json')
    server=_secret(directory/'crypto-server.json')
    if not typed_equal(client,server):
        raise ValueError('peer session secrets differ')
    if (client['th_hex'] != decode(setup['transcript_hash']).hex()
            or client['session_id'] != setup['session_id']):
        raise ValueError('session secret evidence does not match handshake')
    jobs=_jobs(client,requests,responses)
    completed=subprocess.run(['node',str(CHECKER)],input=json.dumps(jobs),text=True,
                             capture_output=True,timeout=15)
    if completed.returncode or completed.stderr:
        raise ValueError('independent record decryption failed')
    opened=strict_json(completed.stdout)
    expected=(len(requests)-1)+(len(responses)-1)
    if len(opened) != expected:
        raise ValueError('decrypted record inventory')
    split=len(requests)-1
    request_plain=[bytes.fromhex(v['plaintext_hex']) for v in opened[:split]]
    response_plain=[bytes.fromhex(v['plaintext_hex']) for v in opened[split:]]
    for direction, rows in ((0,opened[:split]),(1,opened[split:])):
        if any(v['direction'] != direction or v['sequence'] != str(n) for n,v in enumerate(rows)):
            raise ValueError('record direction or sequence')
    return request_plain,response_plain


def validate_plaintext(directory, requests, responses, setup):
    if not __debug__:
        raise RuntimeError('plaintext signature verification requires Python assertions')
    request_plain,response_plain=decrypt(directory,requests,responses,setup)
    q=[strict_json(v) for v in request_plain]
    w=[strict_json(v) for v in response_plain]
    if len(q) != len(w) or len(q) < 3:
        raise ValueError('plaintext exchange inventory')
    if ([v.get('method') for v in q[:3]] != ['initialize','notifications/initialized','tools/list']
            or w[1] != {} or q[0].get('id') != w[0].get('id') or q[2].get('id') != w[2].get('id')
            or w[0].get('result',{}).get('protocolVersion') != '2025-06-18'
            or not isinstance(w[2].get('result',{}).get('tools'),list)):
        raise ValueError('decrypted setup messages')
    if len(q) == 3:
        return dict(decrypted_records=6,decrypted_setup_exchanges=3,
                    decrypted_protected_exchanges=0,decrypted_result_signatures=0,
                    peer_secret_match=True)
    original=(Path(directory)/'intent.json').read_bytes()
    intent=strict_json(original)
    completed_rows=[]
    lines=(Path(directory)/'server.journal').read_text().splitlines()[1:]
    for line in lines:
        row=strict_json(line)
        if row.get('state') == 'COMPLETED':
            completed_rows.append(bytes.fromhex(row['result_hex']))
    inner_ids=set()
    signed_results=0
    for request,response in zip(q[3:],w[3:]):
        if (set(request) != {'jsonrpc','id','method','params'} or request['jsonrpc'] != '2.0'
                or request['method'] != 'tools/call' or request['id'] in inner_ids):
            raise ValueError('decrypted protected request')
        inner_ids.add(request['id'])
        params=request['params']
        if (set(params) != {'name','arguments'} or params['name'] != 'sage_secure_call'
                or set(params['arguments']) != {'envelope'}
                or not typed_equal(params['arguments']['envelope'],intent)):
            raise ValueError('decrypted intent differs from requested bytes')
        if set(response) != {'jsonrpc','id','result'} or response['jsonrpc'] != '2.0' or response['id'] != request['id']:
            raise ValueError('decrypted protected response correlation')
        result=response['result']
        if set(result) != {'content','isError','structuredContent'} or result['content'] != [{'type':'text','text':canonical(result['structuredContent']).decode()}]:
            raise ValueError('decrypted MCP result representation')
        envelope=result['structuredContent']
        if set(envelope) != {'result','proof'}:
            raise ValueError('decrypted result envelope')
        body=envelope['result']
        verify(b'sage-tool-result|0.10.0\0'+canonical(body),decode(envelope['proof']),2)
        expected_fields={'alg','call_id','created','expires','intent_digest','issuer','keyid',
                         'output','recipient','request_id','status','version'}
        requested=intent['intent']
        if (body.get('issuer') != BOB or body.get('recipient') != ALICE
                or body.get('intent_digest') != __import__('hashlib').sha256(original).hexdigest()
                or set(body) != expected_fields or body.get('request_id') != requested['request_id']
                or body.get('call_id') != requested['call_id'] or body.get('keyid') != BOB+'#signing-1'
                or body.get('alg') != 'ed25519' or body.get('version') != '0.10.0'
                or body.get('status') not in ('pending','completed')
                or type(body.get('created')) is not int or type(body.get('expires')) is not int
                or not requested['created'] <= body['created'] < body['expires'] <= requested['expires']
                or type(result['isError']) is not bool
                or result['isError'] != (body['status'] != 'completed')):
            raise ValueError('decrypted signed result binding')
        signed_results += 1
    if not completed_rows or canonical(w[-1]['result']['structuredContent']) != completed_rows[-1]:
        raise ValueError('decrypted terminal result differs from journal')
    return dict(decrypted_records=len(request_plain)+len(response_plain),
                decrypted_setup_exchanges=3,decrypted_protected_exchanges=len(q)-3,
                decrypted_result_signatures=signed_results,peer_secret_match=True)
