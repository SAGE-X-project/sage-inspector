"""Test-only native MCP setup bridges with passive bounded loopback capture."""
import argparse
import itertools
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

from run_mcp_core_runtime import ROOT, PREFIX, digest, run, snapshot, observed
from test_completion010 import independent, verify, canonical, decode, encode, ALICE, BOB
import hashlib

BRIDGES = ROOT / 'adapters/mcp-bridge'
TESTS = {'go': 'TestInspectorMCPBridge', 'rust': PREFIX + 'inspector_bridge::inspector_mcp_bridge'}


def build(language, repo, output, work):
    source = work / language
    source.mkdir()
    evidence = snapshot(repo, language, output, source)
    if language == 'go':
        bridge = BRIDGES / 'go_test.go.txt'
        target = source / 'pkg/agent/guard010/inspector_bridge_test.go'
    else:
        bridge = BRIDGES / 'rust.rs'
        target = source / 'src/hpke/completion010/inspector_bridge.rs'
        parent = source / 'src/hpke/completion010/mcp_transport_tests.rs'
        with parent.open('a') as f:
            f.write('\n#[path = "inspector_bridge.rs"]\nmod inspector_bridge;\n')
    target.write_bytes(bridge.read_bytes())
    (output / bridge.name).write_bytes(bridge.read_bytes())
    evidence['bridge_sha256'] = digest(bridge)
    env = os.environ.copy()
    env['CARGO_TARGET_DIR'] = str(work / 'target')
    binary = work / 'go-bridge'
    command = (['go','test','-mod=readonly','-race','-c','-o',str(binary),'./pkg/agent/guard010']
               if language == 'go' else ['cargo','test','--offline','--lib','--all-features','--no-run','--message-format=json'])
    evidence['build'] = run(command, source, output / (language+'-build.log'), 600, env)
    if evidence['build']['status'] != 'PASS':
        raise ValueError(language+' bridge build failed; see build log')
    if language == 'rust':
        artifacts = []
        for line in (output / 'rust-build.log').read_text().splitlines():
            if not line.startswith('{'): continue
            item = json.loads(line)
            if (item.get('reason') == 'compiler-artifact' and item.get('executable')
                    and item.get('profile',{}).get('test')
                    and item.get('target',{}).get('name') == 'sage_crypto_core'):
                artifacts.append(Path(item['executable']))
        if len(artifacts) != 1: raise ValueError('ambiguous Rust test executable')
        binary = artifacts[0]
    evidence['executable_sha256'] = digest(binary)
    dependency = output / (language+'-dependencies.lock')
    dependency.write_bytes((source / ('go.sum' if language == 'go' else 'Cargo.lock')).read_bytes())
    evidence['dependencies_sha256'] = digest(dependency)
    return (binary, source / 'pkg/agent/guard010' if language == 'go' else source), evidence


def exact(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n-len(out))
        if not chunk: raise EOFError('incomplete frame')
        out.extend(chunk)
    return bytes(out)


def relay(source, target, frames, errors):
    try:
        # Setup has one handshake plus three protected exchanges in each direction.
        for _ in range(4):
            header = exact(source,4)
            length = struct.unpack('!I',header)[0]
            if not 1 <= length <= 32768: raise ValueError('frame length')
            raw = exact(source,length)
            frames.append(raw)
            target.sendall(header+raw)
    except Exception as e:
        errors.append(str(e))


def validate(requests, responses):
    if not __debug__: raise RuntimeError("independent verifier requires Python assertions")
    if len(requests) != 4 or len(responses) != 4:
        raise ValueError('expected handshake plus three setup exchanges')
    transcript, th, sid = independent(requests[0],responses[0])
    ids, nonces = set(), set()
    for index,(request,response) in enumerate(zip(requests,responses)):
        q,w = json.loads(request),json.loads(response)
        if q['did'] != ALICE or q['recipient'] != BOB or w['did'] != BOB or w['recipient'] != ALICE:
            raise ValueError('peer identity')
        if (q.get('context_id') != transcript['ctx'] or w.get('context_id') != transcript['ctx']
                or q.get('role') != 'initiator' or w.get('role') != 'responder'
                or q.get('version') != '0.10.0' or w.get('version') != '0.10.0'
                or q.get('kid') != ALICE+'#signing-1' or w.get('kid') != BOB+'#signing-1'
                or w.get('success') is not True):
            raise ValueError('session context or signed metadata')
        if w['message_id'] != q['id'] or w['request_hash'] != encode(hashlib.sha256(canonical(q)).digest()):
            raise ValueError('request response correlation')
        if q['id'] in ids: raise ValueError('repeated outer id')
        ids.add(q['id'])
        for wire in (q,w):
            if wire['nonce'] in nonces: raise ValueError('repeated nonce')
            nonces.add(wire['nonce'])
        if index:
            if q['encoding'] != 'session' or w['encoding'] != 'session': raise ValueError('unprotected setup')
            if q.get('session_id') != sid or w.get('session_id') != sid: raise ValueError('session binding')
            for raw,key,domain in ((q,1,b'sage-wire-request|0.10.0\n'),(w,2,b'sage-wire-response|0.10.0\n')):
                signed = dict(raw); signature = decode(signed.pop('signature'))
                verify(domain+canonical(signed),signature,key)
    return dict(transcript_hash=th,session_id=sid,frames=8,independent_signatures=9)


def wait_file(path, processes, end):
    while time.monotonic() < end:
        if path.exists() and path.stat().st_size: return path.read_text()
        if any(p.poll() is not None for p in processes): raise ValueError('bridge exited before rendezvous')
        time.sleep(.005)
    raise TimeoutError('bridge rendezvous')


def pair(left,right,programs,output):
    directory = output / (left+'-to-'+right)
    directory.mkdir()
    processes, logs, sockets, threads = [], [], [], []
    requests, responses, errors = [], [], []
    def launch(language,role,peer=''):
        binary,cwd = programs[language]
        command = ([str(binary),'-test.run=^'+TESTS[language]+'$','-test.v','-test.timeout=20s']
                   if language == 'go' else [str(binary),TESTS[language],'--exact','--test-threads=1','--color=never'])
        env = dict(os.environ,SAGE_BRIDGE_DIR=str(directory),SAGE_BRIDGE_ROLE=role,SAGE_BRIDGE_PEER=peer)
        log = (directory / (role+'.log')).open('xb');logs.append(log)
        p = subprocess.Popen(command,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append(p)
        return p
    result = dict(pair=left+'-to-'+right,status='FAIL')
    try:
        server = launch(right,'server')
        end = time.monotonic()+15
        address = wait_file(directory/'address',processes,end)
        host,port = address.split(':')
        if host != '127.0.0.1' or not 1 <= int(port) <= 65535: raise ValueError('loopback required')
        remote = socket.create_connection((host,int(port)),timeout=10);sockets.append(remote)
        listener = socket.socket();sockets.append(listener)
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(10)
        client = launch(left,'client','127.0.0.1:'+str(listener.getsockname()[1]))
        local,_ = listener.accept();local.settimeout(10);sockets.append(local)
        for source,target,frames in ((local,remote,requests),(remote,local,responses)):
            thread = threading.Thread(target=relay,args=(source,target,frames,errors));thread.start();threads.append(thread)
        for role in ('client','server'):
            value = json.loads(wait_file(directory/(role+'.json'),processes,end))
            if value != dict(role=role,state='READY',protected='NOT_RUN'): raise ValueError('READY observation')
        (directory/'release').write_text('release\n')
        for process in processes: process.wait(timeout=max(.1,end-time.monotonic()))
        for thread in threads: thread.join(timeout=1)
        if errors or any(t.is_alive() for t in threads): raise ValueError('capture failed: '+str(errors))
        for language,role,process in ((right,'server',server),(left,'client',client)):
            if not observed(language,TESTS[language],(directory/(role+'.log')).read_text(),process.returncode):
                raise ValueError(role+' did not pass its exact bridge test')
        result.update(validate(requests,responses),status='PASS')
    except Exception as e:
        result['error'] = str(e)
    finally:
        for process in processes:
            if process.poll() is None:
                try: os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError: pass
            process.wait()
        for sock in sockets:
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            sock.close()
        for thread in threads: thread.join(timeout=2)
        for log in logs: log.close()
        raw = directory/'frames.json'
        raw.write_text(json.dumps(dict(requests=[b.hex() for b in requests],responses=[b.hex() for b in responses]),indent=2)+'\n')
        result['files'] = {p.name:digest(p) for p in directory.iterdir() if p.is_file()}
        result['exit_codes'] = [p.returncode for p in processes]
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('go','rust','output'): p.add_argument('--'+name,type=Path,required=True)
    a = p.parse_args();output = a.output.resolve()
    repos = [a.go.resolve(strict=True),a.rust.resolve(strict=True)]
    if any(output.is_relative_to(root) for root in [ROOT,*repos]): p.error('output must be new and outside repositories')
    output.mkdir(parents=True,exist_ok=False)
    report = dict(kind='mcp-native-setup-interop',status='FAIL',conformance='NOT_ESTABLISHED',catalog=dict(NOT_RUN=71),
                  protected_dispatch='NOT_RUN',journal_audit='NOT_RUN',subjects={},pairs=[])
    try:
        report['inspector_revision'] = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        report['inspector_dirty'] = bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True))
        report['scripts'] = {}
        for name in ('run_mcp_setup_interop.py','run_mcp_core_runtime.py','test_completion010.py','test_record010_adapters.py'):
            source = ROOT/'scripts'/name;(output/name).write_bytes(source.read_bytes());report['scripts'][name] = digest(source)
        with tempfile.TemporaryDirectory(prefix='sage-mcp-interop-') as tmp:
            programs = {}
            for language,repo in zip(('go','rust'),repos):
                programs[language], report['subjects'][language] = build(language,repo,output,Path(tmp))
            for left,right in itertools.product(programs,repeat=2):
                report['pairs'].append(pair(left,right,programs,output))
        if len(report['pairs']) == 4 and all(p['status']=='PASS' for p in report['pairs']): report['status']='PASS'
    except Exception as e: report['error'] = str(e)
    finally: (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['status']=='PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
