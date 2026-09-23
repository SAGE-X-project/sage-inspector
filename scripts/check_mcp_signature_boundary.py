"""Audit the pinned MCP intent and result signature algorithm boundaries."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from check_mcp_owner_admission import load, require, sha, read

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'verification/0.10.0/mcp-signature-boundary-contract.json'
LANGUAGES = {'go', 'rust'}
BOUNDARIES = {'intent-algorithm', 'result-algorithm'}
FILES = {
    'go': {'pkg/agent/guard010/verify.go', 'pkg/agent/guard010/ledger_test.go'},
    'rust': {'src/guard010/mod.rs', 'src/guard010/ledger.rs'},
}
TESTS = {
    'go': {
        'intent-algorithm': 'TestBridgeIntentSignatureAlgorithmBoundary',
        'result-algorithm': 'TestBridgeResultSignatureAlgorithmBoundary',
    },
    'rust': {
        'intent-algorithm': 'guard010::ledger::tests::intent_signature_algorithm_boundary_accepts_only_ed25519',
        'result-algorithm': 'guard010::ledger::tests::result_signature_algorithm_boundary_accepts_only_ed25519',
    },
}


def exact(value, fields, message):
    require(type(value) is dict and set(value) == set(fields), message)


def validate(value):
    exact(value, ('schema_version', 'protocol_version', 'kind', 'conformance', 'boundaries', 'cores'), 'contract fields')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'schema version')
    require(value['protocol_version'] == '0.10.0' and value['kind'] == 'mcp-signature-boundary-contract', 'contract identity')
    require(value['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')
    require(type(value['boundaries']) is list and len(value['boundaries']) == 2, 'boundary count')
    found = set()
    for boundary in value['boundaries']:
        exact(boundary, ('id', 'accepted', 'rejected', 'contract'), 'boundary fields')
        ident = boundary['id']
        require(ident in BOUNDARIES and ident not in found and boundary['accepted'] == 'ed25519', 'boundary identity')
        require(boundary['rejected'] == ['ecdsa-p256-sha256', 'secp256k1'], 'algorithm set')
        require(type(boundary['contract']) is str and 80 <= len(boundary['contract']) <= 400, 'boundary text')
        found.add(ident)
    require(found == BOUNDARIES, 'boundary inventory')
    require(set(value['cores']) == LANGUAGES, 'core inventory')
    for language, core in value['cores'].items():
        exact(core, ('revision', 'files', 'tests'), 'core fields')
        require(re.fullmatch('[0-9a-f]{40}', core['revision']) is not None, 'core revision')
        require(type(core['files']) is dict and set(core['files']) == FILES[language], 'source inventory')
        require(all(re.fullmatch('[0-9a-f]{64}', digest or '') for digest in core['files'].values()), 'source digest')
        require(core['tests'] == TESTS[language], 'test identity')
    return value


def contract():
    return validate(load(CONTRACT.read_bytes()))


def audit(roots=None):
    raw = CONTRACT.read_bytes()
    value = validate(load(raw))
    identities = {}
    for language, root in (roots or {}).items():
        require(language in LANGUAGES, 'unknown core')
        root = root.resolve(strict=True)
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip()
        require(revision == value['cores'][language]['revision'], 'core revision: ' + language)
        for path, expected in value['cores'][language]['files'].items():
            require(sha(read(root, path)) == expected, 'core source: ' + path)
        identities[language] = {'status': 'SOURCE_IDENTITY_VERIFIED', 'revision': revision}
    return {
        'schema_version': 1,
        'kind': 'mcp-signature-boundary-audit',
        'status': 'PASS',
        'conformance': 'NOT_ESTABLISHED',
        'runtime': 'NOT_RUN',
        'contract_sha256': sha(raw),
        'boundaries': {item['id']: {'accepted': [item['accepted']], 'rejected': item['rejected']} for item in value['boundaries']},
        'selected_tests': {language: value['cores'][language]['tests'] for language in sorted(LANGUAGES)},
        'source_identity': {language: identities.get(language, {'status': 'NOT_CHECKED'}) for language in sorted(LANGUAGES)},
        'scope': 'Pinned intent and result proof algorithm boundaries only; carriage, provisioning and protocol conformance require separate evidence.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path)
    parser.add_argument('--rust-root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        require(not output.exists() and output != ROOT and not output.is_relative_to(ROOT), 'new output outside Inspector required')
        roots = {name: path for name, path in (('go', args.go_root), ('rust', args.rust_root)) if path}
        report = audit(roots)
        output.mkdir(parents=True)
        (output / 'contract.json').write_bytes(CONTRACT.read_bytes())
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(2, 'signature boundary audit error: ' + str(error) + '\n')
    print('MCP intent and result signature boundary audit PASS; runtime NOT_RUN; conformance NOT_ESTABLISHED.')


if __name__ == '__main__':
    main()
