"""Ensure fixture audits fail on corrupt evidence, inverted verdicts and wrong causes."""
import copy
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
suite = json.loads((root/'vectors/0.10.0/http-boundaries.json').read_text())
proofs = json.loads((root/'docs/evidence/http-boundary-proofs.json').read_text())
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    def run(s, p):
        (directory/'suite.json').write_text(json.dumps(s))
        (directory/'proofs.json').write_text(json.dumps(p))
        return subprocess.run(['node', str(root/'scripts/check_http_boundaries.js'),
                               str(directory/'suite.json'), str(directory/'proofs.json')],
                              capture_output=True, text=True, timeout=30)
    result = run(suite, proofs)
    assert result.returncode == 0, result.stderr
    changed = copy.deepcopy(suite)
    changed['cases'][0]['expected']['verdict'] = 'REJECT'
    assert run(changed, proofs).returncode != 0
    changed = copy.deepcopy(proofs)
    changed['valid-request']['request_sha256'] = '0'*64
    assert run(suite, changed).returncode != 0
    changed = copy.deepcopy(proofs)
    changed['wrong-request-hash']['reason'] = 'outer-signature'
    assert run(suite, changed).returncode != 0
    changed = copy.deepcopy(suite)
    c = next(c for c in changed['cases'] if c['id'] == 'valid-request')
    wire = bytes.fromhex(c['input']['request_hex']).replace(b'"payload":"e30"', b'"payload":"e31"')
    c['input']['request_hex'] = wire.hex()
    updated = copy.deepcopy(proofs)
    updated['valid-request']['request_sha256'] = hashlib.sha256(wire).hexdigest()
    assert run(changed, updated).returncode != 0
    changed = copy.deepcopy(suite)
    next(c for c in changed['cases'] if c['id']=='created-minus-30')['input']['now_unix'] -= 1
    assert run(changed, proofs).returncode != 0
print('6 independent audit integrity checks passed')
