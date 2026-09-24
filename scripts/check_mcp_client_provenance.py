"""Check pinned core MCP client tests without promoting them to host conformance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs/evidence/mcp-client-provenance'
SOURCES = {
    'go': {
        'revision': '62242937995d152e3c2a6d4bbb8a08229680684a',
        'files': {
            'pkg/agent/guard010/mcp_root_capture.go': '6057f7e0dc8612a4aa4a13b556944378b22218ab57ea2100afd3d74fedb7b6db',
            'pkg/agent/guard010/mcp_owned_client.go': '2177925c39297bad322ddfbd0f6543df1cbc116f69bf7ff2e41fe7007e9ec35c',
            'pkg/agent/guard010/mcp_parent_admission_test.go': 'b799bf817ad4a92a0eb733b07ba1f5398a567a79352b463be8494bea893c7666',
            'pkg/agent/guard010/mcp_owned_client_test.go': '72ddb3a5ead882f5426a45ca0d0004fde030de56d11ef4f155332d4c1e01a920',
        },
    },
    'rust': {
        'revision': 'e5d6b43b064e02ae467b4dd835272c3fc4ea29d1',
        'files': {
            'src/guard010/mcp_owned.rs': '7323460c0cb5d73ff5dbea20e523ab4708a2e23db6d0655081c29a44ffe71e85',
            'src/guard010/mcp_transport/connection.rs': 'e24966b9f13e3253881e6a150235288d3a6e655a74c2f07b8be3766220cb7cc8',
            'src/hpke/completion010/mcp_admission_tests.rs': 'e2fe9f46c08795b73ca7b8e665cf54b422a3c5d8e30967b71165c59e28277e6a',
            'src/hpke/completion010/mcp_reply_tests.rs': '42cad7c21626843dd6148672e4857dd57d36a3c8abde1bfc0a296eb32128af35',
        },
    },
}
CASES = {
    'go-root': ('go', 'TestMCPOwnedRootRequiresCapturedOriginalBeforeJournal'),
    'go-hop': ('go', 'TestMCPOwnedHopUsesParentGateBeforeRuntimeSend'),
    'go-admission': ('go', 'TestMCPParentAdmissionExistsOnlyDuringAdmittedWorker'),
    'rust-root': ('rust', 'owned_root_binds_captured_input_before_journal_and_runtime'),
    'rust-hop': ('rust', 'owned_hop_rechecks_parent_before_mcp_transport'),
    'rust-admission': ('rust', 'parent_admission_is_bound_to_the_active_admitted_worker'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(source, name):
    if source == 'go':
        return ['go', 'test', '-count=1', '-v', './pkg/agent/guard010', '-run', '^' + name + '$']
    return ['cargo', 'test', '--offline', '--lib', name, '--', '--nocapture']


def check_source(name, root):
    expected = SOURCES[name]
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(revision == expected['revision'], name + ' revision differs')
    changed = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'],
                                      cwd=root, text=True).strip()
    require(not changed, name + ' tracked files differ from pinned revision')
    for path, digest in expected['files'].items():
        require(sha((root / path).read_bytes()) == digest, name + ' source differs: ' + path)


def check(base=EVIDENCE, go_root=None, rust_root=None):
    report = json.loads((base / 'report.json').read_text())
    require(set(report) == {'schema_version', 'kind', 'protocol_version', 'status',
                            'conformance', 'deployed_host', 'sources', 'cases'}, 'report shape')
    require(report['schema_version'] == 1
            and report['kind'] == 'mcp-client-core-provenance'
            and report['protocol_version'] == '0.10.0'
            and report['status'] == 'CORE_BOUNDARY_OBSERVED'
            and report['conformance'] == 'NOT_ESTABLISHED'
            and report['deployed_host'] == 'NOT_RUN', 'core evidence promoted')
    require(report['sources'] == SOURCES, 'source inventory changed')
    require(set(report['cases']) == set(CASES), 'case inventory changed')
    for source, root in (('go', go_root), ('rust', rust_root)):
        if root is not None:
            check_source(source, root)
    for case_id, (source, name) in CASES.items():
        entry = report['cases'][case_id]
        require(set(entry) == {'source', 'test', 'command', 'exit_code',
                               'stdout', 'stdout_sha256', 'stderr', 'stderr_sha256'},
                'case shape: ' + case_id)
        require(entry['source'] == source and entry['test'] == name
                and entry['command'] == command(source, name)
                and entry['exit_code'] == 0
                and entry['stdout'] == case_id + '.stdout'
                and entry['stderr'] == case_id + '.stderr', 'case contract: ' + case_id)
        out = (base / entry['stdout']).read_bytes()
        err = (base / entry['stderr']).read_bytes()
        require(sha(out) == entry['stdout_sha256']
                and sha(err) == entry['stderr_sha256'], 'log hash: ' + case_id)
        decoded = out.decode('utf-8')
        if source == 'go':
            require(re.search(r'^--- PASS: ' + re.escape(name) + r' \(', decoded, re.M)
                    and len(re.findall(r'^--- PASS: ', decoded, re.M)) == 1
                    and re.search(r'^ok\s+github.com/sage-x-project/sage/pkg/agent/guard010\s+', decoded, re.M),
                    'Go test outcome: ' + case_id)
        else:
            require(re.search(r'^test .*::' + re.escape(name) + r' \.\.\. ok$', decoded, re.M)
                    and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured;', decoded, re.M),
                    'Rust test outcome: ' + case_id)
        require('FAILED' not in decoded and 'SKIP' not in decoded
                and 'panicked at' not in decoded, 'failed or skipped: ' + case_id)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=EVIDENCE)
    parser.add_argument('--go-root', type=Path)
    parser.add_argument('--rust-root', type=Path)
    args = parser.parse_args()
    result = check(args.evidence, go_root=args.go_root, rust_root=args.rust_root)
    print(f"MCP core boundary: {result['status']}; host {result['deployed_host']}; conformance {result['conformance']}")
