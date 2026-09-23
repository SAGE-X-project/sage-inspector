"""Validate the archived unconfigured Agent host inspection verdict."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs/evidence/agent-host-deployment-audit'
SOURCES = {
    'go': ('pkg/agent/guard010/mcp_host.go', 'pkg/agent/guard010/README.md'),
    'rust': ('src/guard010/README.md',),
    'inspector': ('scripts/inspect_host.py', 'vectors/0.10.0/host-manifest.json'),
}
REQUIRED = {
    'selected_host_executable', 'selected_host_configuration',
    'host_adapter_executable', 'trusted_external_witness_executable',
    'witness_isolation_boundary', 'protected_effect_inventory',
    'trusted_signing_key_boundary', 'immutable_component_and_dispatch_binding',
    'recovery_and_operator_policy',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check(base=EVIDENCE, go_root=None, rust_root=None):
    manifest = json.loads((base / 'manifest.json').read_text())
    baseline = json.loads((ROOT / 'verification/0.10.0/normative-baseline-lock.json').read_text())
    require(manifest['schema_version'] == 1
            and manifest['kind'] == 'agent-host-deployment-audit'
            and manifest['protocol_version'] == '0.10.0'
            and manifest['spec_revision'] == baseline['spec']['revision']
            and manifest['inspector_revision'] == manifest['sources']['inspector']['revision'],
            'audit baseline')
    require(manifest['status'] == 'NOT_RUN'
            and manifest['conformance'] == 'NOT_ESTABLISHED'
            and manifest['host_binding'] is None
            and set(manifest['missing_binding']) == REQUIRED,
            'unconfigured host verdict was promoted')
    roots = {'go': go_root, 'rust': rust_root, 'inspector': ROOT}
    for name, expected_paths in SOURCES.items():
        entry = manifest['sources'][name]
        require(set(entry['files']) == set(expected_paths)
                and re.fullmatch(r'[0-9a-f]{40}', entry['revision'])
                and all(re.fullmatch(r'[0-9a-f]{64}', value)
                        for value in entry['files'].values()),
                'source inventory: ' + name)
        if roots[name] is not None:
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                               cwd=roots[name], text=True).strip()
            if name == 'inspector':
                # The audit is recorded against its parent before this commit.
                require(entry['revision'] == manifest['inspector_revision'],
                        'Inspector source revision differs')
            else:
                require(revision == entry['revision'], name + ' source revision differs')
            for path, expected in entry['files'].items():
                require(sha((roots[name] / path).read_bytes()) == expected,
                        'source hash differs: ' + name + '/' + path)
    runtime = manifest['runtime']
    require(runtime['exit_code'] == 3
            and runtime['report'] == 'unconfigured/summary.json'
            and runtime['stdout'] == 'unconfigured.stdout'
            and runtime['stderr'] == 'unconfigured.stderr', 'runtime contract')
    stdout = (base / runtime['stdout']).read_bytes()
    stderr = (base / runtime['stderr']).read_bytes()
    require(sha(stdout) == runtime['stdout_sha256']
            and sha(stderr) == runtime['stderr_sha256']
            and stderr == b'' and stdout.count(b'\n') == 1,
            'runtime process output')
    output = json.loads(stdout)
    require(set(output) == {'status', 'report'}
            and output['status'] == 'INCOMPLETE'
            and output['report'].endswith('/unconfigured/summary.json'),
            'unconfigured process result was promoted')
    raw = (base / runtime['report']).read_bytes()
    require(sha(raw) == runtime['report_sha256'], 'runtime report hash')
    report = json.loads(raw)
    fixture_raw = (ROOT / 'vectors/0.10.0/host-manifest.json').read_bytes()
    fixtures = json.loads(fixture_raw)['scenarios']
    require(report['schema_version'] == 1
            and report['protocol_version'] == '0.10.0'
            and report['status'] == 'INCOMPLETE'
            and report['conformance'] == 'NOT_ESTABLISHED'
            and report['manifest_sha256'] == sha(fixture_raw)
            and report['binding'] is None
            and report['adapter_sha256'] is None
            and report['runner_sha256'] is None
            and report['evidence_files'] == {}
            and len(report['scenarios']) == len(fixtures) == 8,
            'host report was promoted')
    require(sum(f['steps'] for f in fixtures) == 40, 'host scenario inventory changed')
    for expected, actual in zip(fixtures, report['scenarios']):
        require(actual['id'] == expected['id']
                and actual['fixture_sha256'] == expected['sha256']
                and actual['rule_ids'] == expected['rule_ids']
                and actual['steps'] == expected['steps']
                and actual['status'] == 'NOT_RUN'
                and actual['observed_effects'] is None
                and actual['reason'] ==
                'No pinned host adapter and external witness binding supplied.'
                and 'report' not in actual,
                'host scenario was promoted: ' + expected['id'])
    control = manifest['internal_core_control']
    require(control['kind'] == 'GO_INTERNAL_HOST_TEST_ONLY'
            and control['exit_code'] == 0
            and control['command'] ==
            "go test ./pkg/agent/guard010 -run '^TestMCPHostRuntimeExchange$' -count=1",
            'internal core control')
    control_stdout = (base / control['stdout']).read_bytes()
    control_stderr = (base / control['stderr']).read_bytes()
    require(sha(control_stdout) == control['stdout_sha256']
            and sha(control_stderr) == control['stderr_sha256']
            and control_stdout.startswith(
                b'ok  \tgithub.com/sage-x-project/sage/pkg/agent/guard010\t')
            and control_stderr == b'', 'internal core control output')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path)
    parser.add_argument('--rust-root', type=Path)
    args = parser.parse_args()
    checked = check(go_root=args.go_root, rust_root=args.rust_root)
    print(f"Agent host: {checked['status']}; conformance {checked['conformance']}")
