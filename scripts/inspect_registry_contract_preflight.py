"""Review pinned committed ABI/source before configuring a blockchain Source.

This is a source query, not a resolver, authorization gate, Solidity compiler,
contract runner, RPC client or loaded-code attestation. No inspected code runs.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'verification/0.10.0/registry-contract-preflight/catalog.json'
CATALOG_SHA = 'a374dc60122b7cce4eeadefcd77e0f826bdefab4ad3ae4286806e3384761a322'
MAX_FILE = 2 << 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def catalog(path=CATALOG):
    raw = Path(path).read_bytes()
    require(sha(raw) == CATALOG_SHA, 'reviewed catalog changed')
    return json.loads(raw)


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, timeout=30, stderr=subprocess.PIPE)


def read_repository(root, declaration):
    """Read immutable reviewed commit blobs; never substitute worktree bytes."""
    root = Path(root).resolve(strict=True)
    require(git(root, 'rev-parse', '--show-toplevel').decode().strip() == str(root),
            'repository root required')
    revision = declaration['revision']
    require(type(revision) is str and re.fullmatch(r'[0-9a-f]{40}', revision), 'exact commit required')
    require(git(root, 'cat-file', '-t', revision).strip() == b'commit', 'commit unavailable')
    result = {}
    for name, expected in declaration['files'].items():
        require(type(name) is str and str(PurePosixPath(name)) == name and
                not name.startswith('/') and '..' not in PurePosixPath(name).parts,
                'local committed path required')
        entry = git(root, 'ls-tree', revision, '--', name).decode().split('\t')
        require(len(entry) == 2 and entry[1].rstrip('\n') == name and
                entry[0].split()[:2] in (['100644', 'blob'], ['100755', 'blob']),
                'bounded regular committed file required')
        identity = revision + ':' + name
        size = int(git(root, 'cat-file', '-s', identity))
        require(0 <= size <= MAX_FILE, 'committed file exceeds limit')
        raw = git(root, 'show', identity)
        require(len(raw) == size and sha(raw) == expected, 'committed source hash drift: ' + name)
        result[name] = raw
    return result


def parameter(value, depth=0):
    require(type(value) is dict and depth <= 8, 'bounded ABI parameter required')
    name, kind = value.get('name'), value.get('type')
    require(type(name) is str and len(name) <= 128 and type(kind) is str and len(kind) <= 128,
            'ABI parameter name/type required')
    require(re.fullmatch(r'(?:tuple|address|bool|string|bytes[0-9]*|u?int[0-9]*)(?:\[[0-9]*\])*', kind),
            'ABI parameter type invalid')
    atom = kind.split('[', 1)[0]
    if atom.startswith('bytes') and atom != 'bytes':
        size = atom[5:]
        require(size == str(int(size)) and 1 <= int(size) <= 32, 'ABI byte width invalid')
    if atom.startswith(('int', 'uint')) and atom not in ('int', 'uint'):
        size = atom[4:] if atom.startswith('uint') else atom[3:]
        require(size == str(int(size)) and 8 <= int(size) <= 256 and int(size) % 8 == 0,
                'ABI integer width invalid')
    dimensions = re.findall(r'\[([0-9]*)\]', kind)
    require(len(dimensions) <= 8 and all(not size or (size == str(int(size)) and int(size) > 0)
                                        for size in dimensions), 'ABI array dimension invalid')
    result = dict(name=name, type=kind)
    if kind.startswith('tuple'):
        values = value.get('components')
        require(type(values) is list and 0 < len(values) <= 256, 'ABI tuple components required')
        result['components'] = [parameter(p, depth + 1) for p in values]
        names = [p['name'] for p in result['components'] if p['name']]
        require(len(set(names)) == len(names), 'duplicate ABI tuple name')
    else:
        require('components' not in value, 'non-tuple ABI components')
    return result


def function(abi, name):
    require(type(abi) is list and 0 < len(abi) <= 1024 and all(type(f) is dict for f in abi),
            'bounded ABI array required')
    matches = [f for f in abi if f.get('type') == 'function' and f.get('name') == name]
    require(len(matches) == 1, 'unique reviewed ABI function required: ' + name)
    f = matches[0]
    require(f.get('stateMutability') in ('pure', 'view', 'nonpayable', 'payable'), 'ABI mutability invalid')
    result = dict(type='function', name=name, stateMutability=f['stateMutability'])
    for field in ('inputs', 'outputs'):
        require(type(f.get(field)) is list and len(f[field]) <= 256, 'bounded ABI parameters required')
        result[field] = [parameter(p) for p in f[field]]
    return result


def report(sources, reviewed):
    require(reviewed == catalog(), 'reviewed catalog changed')
    require(set(sources) == set(reviewed['repositories']), 'source repository set drift')
    for repository, declaration in reviewed['repositories'].items():
        require(set(sources[repository]) == set(declaration['files']), 'source file set drift')
        for path, digest in declaration['files'].items():
            require(sha(sources[repository][path]) == digest, 'reviewed source hash drift')
    for row in reviewed['reviewed_spans']:
        lines = sources[row['repository']][row['path']].splitlines(keepends=True)
        require(sha(b''.join(lines[row['line'] - 1:row['end_line']])) == row['sha256'],
                'reviewed source span drift')
    projections = {}
    for contract, names in (
        ('AgentCardRegistry', ('getAgent', 'getAgentByDID', 'getKey', 'agentNonce', 'registerAgentWithParams')),
        ('ISageRegistry', ('getAgent', 'getAgentByDID', 'registerAgent')),
    ):
        abi = json.loads(sources['contracts']['abi/' + contract + '.json'])
        projections[contract] = {name: function(abi, name) for name in names}
    rows = [
        ('record-and-abi', ['REG-01', 'REG-06'], [],
         'AgentCardRegistry and ISageRegistry getAgent inputs share names/types but output tuples differ. Neither exported tuple is the closed normative record; a reviewed exact ABI/record mapping is required.'),
        ('named-key-lifecycle', ['REG-01', 'REG-02', 'REG-03'], ['key-storage', 'key-revocation'],
         'Stored keys have numeric keyType, bytes, signature, verified and registeredAt. A hash-indexed verified flag cannot supply named immutable entries, retained tombstones, proof signer identity or approved role mapping on its own. Optional expiry absence is not itself a violation.'),
        ('record-version', ['REG-03', 'REG-05'], ['key-addition', 'key-revocation', 'metadata-version-counter', 'kem-version-counter', 'endpoint-version-counter'],
         'agentNonce increments on metadata/KEM/endpoint updates but not all lifecycle/key mutations; mutation APIs do not take the normative expected previous record version. It cannot be assumed to be the whole-record version.'),
        ('terminal-state', ['REG-03'], ['activation-state', 'deactivation-state'],
         'A single active boolean is used for initial inactivity and deactivation; a reviewed mapping must establish created/active/terminal deactivated state and authenticated transitions, not infer them from the boolean alone.'),
        ('proof-validation', ['REG-04', 'REG-06'], ['ed25519-validation', 'kem-legacy-endorsement'],
         'The reviewed Ed25519 branch checks signature length only. X25519 uses a separate wallet-domain endorsement. Neither verified=true nor these legacy domains establish the normative named-key challenge/proof; complete independent proof validation is required.'),
        ('claim-and-identity', ['REG-06'], ['legacy-claim', 'registry-did-hook'],
         'The candidate uses a keccak/ABI commitment with timestamp windows and a legacy DID hook. The normative profile specifies SHA-256/domain/JCS claim bytes, block windows and canonical locator/agent identity. A reader alone cannot establish write-side compliance.'),
        ('actual-provider-ownership', ['EXEC-02', 'EXEC-06', 'REG-05', 'REG-06'], [],
         'The ADK factory/instance ports and core Source contract require protected actual loaded-code/record/proof/finality validation. Source hashes, ABI exports and fixture assertions do not supply a selected loader, custody boundary, validating RPC observer or deployed code identity.'),
    ]
    return dict(
        schema_version=1, kind='REGISTRY_CONTRACT_SOURCE_PREFLIGHT', protocol_version='0.10.0',
        catalog_sha256=CATALOG_SHA, source_query_status='REVIEWED_SOURCE_MATCHED',
        repositories=reviewed['repositories'], reviewed_spans=reviewed['reviewed_spans'],
        abi_projections=projections,
        findings=[dict(id=ident, normative_rules=rules, source_spans=spans,
                       status='MAPPING_REVIEW_REQUIRED', review=text) for ident, rules, spans, text in rows],
        binding_readiness='REVIEW_REQUIRED', selected_deployment=None, selected_host=None,
        live_chain_verification='NOT_RUN', contract_compilation='NOT_RUN', contract_execution='NOT_RUN',
        loaded_instance_attestation='NOT_RUN', effect_observations=None,
        deployed_host_controls=dict(count=13, status='NOT_RUN'),
        independent_hop_execution='NOT_RUN', full_conformance='NOT_ESTABLISHED',
        limitations=[
            'Manual bounded source/ABI review, not a complete Solidity semantic or vulnerability audit.',
            'Committed blobs are read at exact revisions; dirty worktree contents are never inspected or overwritten.',
            'Exported ABI provenance is pinned; compiler-to-source or deployed-bytecode equivalence is not established.',
            'Different ABI field names do not require identical wire field names; reviewed semantic mapping remains possible.',
            'No contract, deployment, inspected loader/tool, RPC or attack-capable bypass program is executed.',
            'Query success is not connection authorization, implementation conformance or a deployed-host PASS.',
            'Preserve approved program order: record gaps now; do not silently upgrade contracts, change normative rules or substitute Web authority.',
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('contracts', 'spec', 'go', 'adk'):
        parser.add_argument('--' + name + '-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', type=Path)
    args = parser.parse_args()
    reviewed = catalog()
    sources = {name: read_repository(getattr(args, name + '_root'), declaration)
               for name, declaration in reviewed['repositories'].items()}
    result = report(sources, reviewed)
    if args.check:
        require(result == json.loads(args.check.read_text()), 'saved source report drift')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('Reviewed 16 committed files and 7 mapping obligations; blockchain binding remains REVIEW_REQUIRED')


if __name__ == '__main__':
    main()
