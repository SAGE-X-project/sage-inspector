"""Run allowlisted core MCP boundary tests at pinned source revisions."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from check_mcp_client_provenance import CASES, SOURCES, check, check_source, command, sha


def run(go_root, rust_root, output):
    roots = {'go': go_root, 'rust': rust_root}
    for source, root in roots.items():
        check_source(source, root)
    output.mkdir(parents=True, exist_ok=False)
    report = {
        'schema_version': 1,
        'kind': 'mcp-client-core-provenance',
        'protocol_version': '0.10.0',
        'status': 'CORE_BOUNDARY_OBSERVED',
        'conformance': 'NOT_ESTABLISHED',
        'deployed_host': 'NOT_RUN',
        'sources': SOURCES,
        'cases': {},
    }
    with tempfile.TemporaryDirectory(prefix='sage-mcp-provenance-') as temp:
        cache = Path(temp)
        (cache / 'go').mkdir()
        (cache / 'rust').mkdir()
        for case_id, (source, name) in CASES.items():
            argv = command(source, name)
            env = os.environ.copy()
            env['GOPROXY'] = 'off'
            env['CARGO_NET_OFFLINE'] = 'true'
            env['GOCACHE'] = str(cache / 'go')
            env['CARGO_TARGET_DIR'] = str(cache / 'rust')
            completed = subprocess.run(argv, cwd=roots[source], env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       timeout=300, check=False)
            stdout_name, stderr_name = case_id + '.stdout', case_id + '.stderr'
            (output / stdout_name).write_bytes(completed.stdout)
            (output / stderr_name).write_bytes(completed.stderr)
            report['cases'][case_id] = {
                'source': source, 'test': name, 'command': argv,
                'exit_code': completed.returncode,
                'stdout': stdout_name, 'stdout_sha256': sha(completed.stdout),
                'stderr': stderr_name, 'stderr_sha256': sha(completed.stderr),
            }
            print(f'{case_id}: exit {completed.returncode}', flush=True)
    if any(case['exit_code'] != 0 for case in report['cases'].values()):
        report['status'] = 'INCOMPLETE'
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    check(output, go_root, rust_root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', required=True, type=Path)
    parser.add_argument('--rust-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    run(args.go_root, args.rust_root, args.output)
