"""Check that a missing deployment remains an unrun live-chain inspection."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs/evidence/registry-source-deployment-audit'
SOURCE_FILES = {'README.md', 'deployments/config/production.yaml',
                'deployments/config/staging.yaml'}
MISSING = {'selected_deployment', 'trusted_rpc_or_resolver_identity',
           'deployed_code_hash', 'reviewed_read_abi_mapping',
           'reviewed_write_abi_mapping', 'upgrade_policy', 'operator_scopes',
           'transaction_authorization', 'finality_policy', 'readiness_policy',
           'trusted_observer_revision_and_binary', 'record_and_key_proof_source'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check(base=EVIDENCE, go_root=None):
    manifest = json.loads((base / 'manifest.json').read_text())
    baseline = json.loads((ROOT / 'verification/0.10.0/normative-baseline-lock.json').read_text())
    require(manifest['schema_version'] == 1
            and manifest['kind'] == 'registry-source-deployment-audit'
            and manifest['protocol_version'] == '0.10.0'
            and manifest['spec_revision'] == baseline['spec']['revision'],
            'audit baseline')
    require(manifest['status'] == 'NOT_RUN'
            and manifest['live_chain_verification'] == 'NOT_RUN'
            and manifest['conformance'] == 'NOT_ESTABLISHED',
            'audit verdict was promoted')
    require(set(manifest['surveyed_go_files']) == SOURCE_FILES
            and all(re.fullmatch(r'[0-9a-f]{64}', value)
                    for value in manifest['surveyed_go_files'].values()),
            'source inventory')
    if go_root is not None:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                           cwd=go_root, text=True).strip()
        require(revision == manifest['go_revision'], 'Go source revision differs')
        for name, expected in manifest['surveyed_go_files'].items():
            require(sha((go_root / name).read_bytes()) == expected,
                    'source hash differs: ' + name)
    fixture = manifest['inspector_fixture']
    require(fixture['path'] == 'vectors/0.10.0/registry-source-binding.json'
            and sha((ROOT / fixture['path']).read_bytes()) == fixture['sha256']
            and fixture['environment'] == 'synthetic'
            and json.loads((ROOT / fixture['path']).read_text())['environment'] == 'synthetic',
            'synthetic fixture promoted')
    candidate = manifest['readme_candidate']
    require(candidate['status'] == 'UNVERIFIED_CANDIDATE'
            and candidate['chain_id'] == '11155111'
            and candidate['network'] == 'Sepolia'
            and candidate['contract'] == 'AgentCardRegistry'
            and candidate['registry_address'] ==
            '0xc7ecf7ad6ee71cb0d94f0eb00f46f1ddf432a808',
            'README candidate promoted')
    if go_root is not None:
        require(candidate['registry_address'] in (go_root / 'README.md').read_text().lower(),
                'candidate address absent from README')
    require(set(manifest['missing_binding']) == MISSING, 'deployment requirements changed')
    runtime = manifest['runtime']
    require(runtime['exit_code'] == 3
            and runtime['report'] == 'unconfigured-report.json'
            and runtime['stdout'] == 'unconfigured.stdout'
            and runtime['stderr'] == 'unconfigured.stderr',
            'runtime status')
    stdout = (base / runtime['stdout']).read_bytes()
    stderr = (base / runtime['stderr']).read_bytes()
    require(sha(stdout) == runtime['stdout_sha256']
            and sha(stderr) == runtime['stderr_sha256']
            and stderr == b'' and stdout.count(b'\n') == 1
            and json.loads(stdout) == {'status': 'NOT_RUN',
                                       'conformance': 'NOT_ESTABLISHED'},
            'runtime process output')
    raw = (base / runtime['report']).read_bytes()
    require(sha(raw) == runtime['report_sha256'], 'runtime report hash')
    report = json.loads(raw)
    require(report['kind'] == 'registry-source-evidence'
            and report['status'] == 'NOT_RUN'
            and report['live_chain_verification'] == 'NOT_RUN'
            and report['conformance'] == 'NOT_ESTABLISHED'
            and report['actual_core_execution'] is False
            and report['reason'] == 'No deployment binding supplied.'
            and report['measurements'] == [] and report['files'] == {},
            'unconfigured report was promoted')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path)
    args = parser.parse_args()
    checked = check(go_root=args.go_root)
    print(f"Registry Source: {checked['status']}; live chain {checked['live_chain_verification']}")
