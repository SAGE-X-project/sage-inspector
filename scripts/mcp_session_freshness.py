"""Cross-session checks over already authenticated native MCP evidence."""
import hashlib
import itertools
from pathlib import Path
from mcp_evidence_json import loads
from test_completion010 import canonical, decode, encode

FIELDS = ('ctx','nonce','enc','ephC','ephS','kid','session_id','transcript_hash')
BINARY = {'nonce':16,'enc':32,'ephC':32,'ephS':32,'session_id':16,'transcript_hash':32}
PAIRS = tuple(a+'-to-'+b for a,b in itertools.product(('go','rust'),repeat=2))


def check_seeds(seeds):
    if any(not isinstance(seed,bytes) or len(seed) != 32 for seed in seeds):
        raise ValueError('invalid session seed evidence')
    if len(set(seeds)) != len(seeds):
        raise ValueError('reused session seed')
    return len(seeds)


def check_sessions(sessions):
    seen = {name:set() for name in FIELDS}
    public_keys = set()
    labels = set()
    for label,values in sessions:
        if label in labels: raise ValueError('duplicate session evidence label')
        labels.add(label)
        for name in FIELDS:
            value = values[name]
            if not isinstance(value,str) or not value: raise ValueError('missing session contribution: '+name)
            if name in BINARY:
                value = decode(value)
                if len(value) != BINARY[name]: raise ValueError('invalid session contribution size: '+name)
            if value in seen[name]: raise ValueError('reused session contribution: '+name)
            seen[name].add(value)
            if name in ('enc','ephC','ephS'):
                if value in public_keys: raise ValueError('reused ephemeral public key across roles')
                public_keys.add(value)
    if not labels: raise ValueError('empty session evidence')
    return dict(status='PASS',sessions=len(labels),distinct={k:len(v) for k,v in seen.items()},
                distinct_ephemeral_public_keys=len(public_keys))


def check_matrix(root, report):
    root = Path(root)
    baseline = report['pairs']
    if [p['pair'] for p in baseline] != list(PAIRS): raise ValueError('freshness baseline inventory')
    entries = [('baseline',p) for p in baseline]
    if 'restart' in report:
        expected = [(mode,pair) for mode in ('server','client') for pair in PAIRS]
        if [(p.get('recovery'),p['pair']) for p in report['restart']] != expected:
            raise ValueError('freshness recovery inventory')
        entries += [(p['recovery'],p) for p in report['restart']]
    sessions=[]
    seeds=[]
    secret_mode=None
    for mode,row in entries:
        if row['status'] != 'PASS': raise ValueError('freshness requires successful session checks')
        directory=root/row['pair'] if mode=='baseline' else root/('reopen-'+mode)/row['pair']
        frames=loads((directory/'frames.json').read_bytes())
        response=loads(bytes.fromhex(frames['responses'][0]))
        transcript=loads(decode(response['data']))['transcript']
        th=hashlib.sha256(canonical(transcript)).digest()
        values={k:transcript[k] for k in FIELDS if k in transcript}
        values.update(transcript_hash=encode(th),session_id=encode(hashlib.sha256(b'sage-session|0.10.0'+th).digest()[:16]))
        sessions.append((mode+'/'+row['pair'],values))
        secret_paths=[directory/'crypto-client.json',directory/'crypto-server.json']
        present=[path.exists() for path in secret_paths]
        if any(present) and not all(present): raise ValueError('incomplete session seed evidence')
        if secret_mode is None: secret_mode=all(present)
        if secret_mode != all(present): raise ValueError('inconsistent session seed inventory')
        if all(present):
            client,server=(loads(path.read_bytes()) for path in secret_paths)
            if client != server: raise ValueError('peer session secrets differ')
            try: seed=bytes.fromhex(client['seed_hex']);secret_th=bytes.fromhex(client['th_hex'])
            except (KeyError,TypeError,ValueError): raise ValueError('invalid session seed evidence')
            if client.get('fixture') != 'public-test-only' or secret_th != th or client.get('session_id') != values['session_id']:
                raise ValueError('session seed binding')
            seeds.append(seed)
    result=check_sessions(sessions)
    if secret_mode: result['distinct_session_seeds']=check_seeds(seeds)
    return result
