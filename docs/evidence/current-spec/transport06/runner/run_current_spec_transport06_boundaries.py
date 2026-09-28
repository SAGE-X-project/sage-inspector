#!/usr/bin/env python3
"""Run bounded in-memory WebSocket events and core signature primitives."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess

import h11
import wsproto
from wsproto import ConnectionType, WSConnection
from wsproto.events import (AcceptConnection, BytesMessage, Request,
                            TextMessage)

from current_spec_catalog import ROOT, load, require, sha
from current_spec_primitive_bridge import invoke_core
from check_current_spec_transport06_vectors import SOURCE, signed
from websocket010 import ProfileError, Reassembly, validate_upgrade


REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}


def connected():
    client = WSConnection(ConnectionType.CLIENT)
    server = WSConnection(ConnectionType.SERVER)
    server.receive_data(client.send(Request(host='agent.example',
                                             target='/messages')))
    events = list(server.events())
    require(len(events) == 1, 'one opening request')
    validate_upgrade(events[0], 'agent.example')
    client.receive_data(server.send(AcceptConnection()))
    events = list(client.events())
    require(len(events) == 1, 'one opening acceptance')
    validate_upgrade(events[0])
    return client, server


def event_observations(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    rows = {row['id']: row for row in suite['cases']}
    positive = rows['TRANSPORT-06-P']
    client, server = connected()
    fragments = [bytes.fromhex(x).decode('utf-8')
                 for x in positive['fragments_hex']]
    raw = client.send(TextMessage(data=fragments[0], message_finished=False))
    raw += client.send(TextMessage(data=fragments[1]))
    server.receive_data(raw)
    assembly = Reassembly()
    delivered = [item for event in server.events()
                 if (item := assembly.feed(event)) is not None]
    require(len(delivered) == 1 and
            load(delivered[0])['recipient'] == positive['expected_recipient'] and
            signed(load(delivered[0]),
                   bytes.fromhex(positive['trusted_public_key_hex'])),
            'one complete signed text envelope after reassembly')
    try:
        validate_upgrade(Request(host='agent.example', target='/messages',
                                 extensions=['permessage-deflate']),
                         'agent.example')
    except ProfileError:
        compressed = 'REJECT'
    else:
        compressed = 'ACCEPT'
    client, server = connected()
    server.receive_data(client.send(BytesMessage(
        data=bytes.fromhex(rows['TRANSPORT-06-N02']['fragments_hex'][0]))))
    try:
        for event in server.events():
            Reassembly().feed(event)
    except ProfileError:
        binary = 'REJECT'
    else:
        binary = 'ACCEPT'
    require(compressed == binary == 'REJECT',
            'in-memory compression negotiation and binary event rejection')
    return {'schema_version': 1,
            'scope': 'in-memory Inspector wsproto event parser; no TLS, socket, or core receiver',
            'wsproto_version': wsproto.__version__,
            'h11_version': h11.__version__,
            'fragmented_text': {'verdict': 'ACCEPT',
                                'messages': 1,
                                'envelope_sha256': hashlib.sha256(delivered[0]).hexdigest()},
            'compressed_upgrade': {'verdict': compressed},
            'binary_event': {'verdict': binary},
            'oversized_fragmented_message': 'UNIT_ONLY_COMPACT_LENGTHS',
            'unsigned_local_message': 'UNIT_ONLY_NO_CORE_RECEIVER'}


def signature_input(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    positive = suite['cases'][0]
    wire = load(b''.join(bytes.fromhex(x) for x in positive['fragments_hex']))
    unsigned = copy.deepcopy(wire)
    signature = base64.urlsafe_b64decode(unsigned.pop('signature') + '==')
    message = b'sage-wire-request|0.10.0\n' + json.dumps(
        unsigned, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()
    return {'algorithm': 'ed25519',
            'public_key_hex': positive['trusted_public_key_hex'],
            'message_hex': message.hex(), 'signature_hex': signature.hex()}


def run(programs, output, root=ROOT):
    require(not output.exists() and
            not output.resolve().is_relative_to(root.resolve()),
            'fresh evidence directory outside repository')
    events = event_observations(root)
    primitive = signature_input(root)
    subjects = {}
    observations = {}
    for language, program in programs.items():
        require(language in REVISIONS and program.is_file() and
                not program.is_symlink(), 'bounded core adapter executable')
        repository, revision = REVISIONS[language]
        subjects[language] = {'repository': repository, 'revision': revision,
                              'executable_sha256': sha(program.read_bytes())}
        observations[language] = invoke_core(
            program, 'TRANSPORT-06-P-signature', 'signature.verify', primitive)
    require(set(subjects) == {'go', 'rust'} and
            all(sha(program.read_bytes()) ==
                subjects[language]['executable_sha256']
                for language, program in programs.items()),
            'stable Go and Rust adapter binaries')
    report = {
        'schema_version': 1,
        'spec_revision': load((root / SOURCE).read_bytes())['spec_revision'],
        'scenario_sha256': sha((root / SOURCE).read_bytes()),
        'runner_sha256': sha(Path(__file__).read_bytes()),
        'bridge_sha256': sha((root / 'scripts/current_spec_primitive_bridge.py').read_bytes()),
        'parser_sha256': sha((root / 'scripts/websocket010.py').read_bytes()),
        'runner_revision': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip(),
        'events': events, 'signature_input': primitive,
        'subjects': subjects, 'signature_observations': observations,
    }
    output.mkdir(parents=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('go', 'rust', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    report = run({'go': args.go.resolve(), 'rust': args.rust.resolve()},
                 args.output.resolve())
    print('Observed', report['events']['fragmented_text']['messages'],
          'in-memory text envelope and both core signature primitives')


if __name__ == '__main__':
    main()
