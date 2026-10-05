"""Audit nine conceptual host ports using pinned source and external compilers.

Compilation proves public reachability only. The reviewed issuance gap, host
callbacks and private assembly findings never become full conformance PASS.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from host_port_contract import PORTS, catalog as host_catalog, hex_string, require
from inspect_root_capture_parity import (GO_REVISION, NORMATIVE_REVISION, ROOT,
                                         RUST_REVISION, check_source, sha)

CATALOG = ROOT / 'verification/0.10.0/host-port/public-api.json'
REPORT = ROOT / 'docs/evidence/host-public-api.json'
COVERAGE = {
    'CaptureStore': 'PUBLIC_PRIMITIVE',
    'PolicyAuthorizer': 'PUBLIC_CALLBACK',
    'IdentityAndReadiness': 'PUBLIC_CALLBACK_WITH_PRIVATE_ASSEMBLY',
    'MeasuredComponent': 'PUBLIC_CALLBACK',
    'IntentSigner': 'SOURCE_REVIEW_GAP',
    'TransportOwner': 'PUBLIC_PRIMITIVE_WITH_PRIVATE_ASSEMBLY',
    'AdmissionLedger': 'PUBLIC_PRIMITIVE_WITH_PRIVATE_ASSEMBLY',
    'EffectOwner': 'PUBLIC_CALLBACK',
    'ResultConsumer': 'PUBLIC_PRIMITIVE',
}
GAPS = {'IntentSigner', 'IdentityAndReadiness', 'TransportOwner', 'AdmissionLedger'}


def catalog(path=CATALOG):
    suite = json.loads(path.read_text())
    require(set(suite) == {'schema_version', 'protocol_version',
            'normative_source_revision', 'go_revision', 'rust_revision',
            'scope', 'ports'} and type(suite['schema_version']) is int and
            suite['schema_version'] == 1 and suite['protocol_version'] == '0.10.0' and
            suite['normative_source_revision'] == NORMATIVE_REVISION and
            suite['go_revision'] == GO_REVISION and suite['rust_revision'] == RUST_REVISION,
            'public API catalog provenance')
    contract = host_catalog()
    require(contract['normative_source_revision'] == NORMATIVE_REVISION and
            isinstance(suite['scope'], str) and suite['scope'] and
            type(suite['ports']) is list and len(suite['ports']) == len(PORTS) and
            {row['port'] for row in suite['ports']} == PORTS,
            'exact nine host ports')
    for row in suite['ports']:
        port = row['port']
        require(set(row) == {'port', 'coverage', 'host_obligation', 'gap', 'go', 'rust'} and
                row['coverage'] == COVERAGE[port] and
                type(row['host_obligation']) is str and row['host_obligation'] and
                ((type(row['gap']) is str and bool(row['gap'])) if port in GAPS
                 else row['gap'] is None), 'reviewed host responsibility and gap')
        for language in ('go', 'rust'):
            api = row[language]
            require(set(api) == {'types', 'traits', 'references', 'sources'},
                    'closed public API entry')
            pattern = (r'[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)?'
                       if language == 'go' else
                       r'[A-Za-z][A-Za-z0-9_]*(?:::[A-Za-z][A-Za-z0-9_]*)?')
            for field in ('types', 'traits', 'references'):
                items = api[field]
                require(type(items) is list and len(items) == len(set(items)) and
                        all(type(item) is str and re.fullmatch(pattern, item) for item in items),
                        'bounded compiler references')
            require(language != 'go' or not api['traits'], 'Go interfaces use types')
            require(bool(api['types'] or api['traits'] or api['references']) ==
                    (port != 'IntentSigner'), 'issuance gap is source review only')
            sources = api['sources']
            source_pattern = (r'pkg/agent/guard010/[a-z_]+\.go' if language == 'go'
                              else r'src/guard010/[a-z_/]+\.rs')
            require(type(sources) is dict and sources and
                    all(re.fullmatch(source_pattern, name) and '..' not in name and
                        hex_string(digest, 64) for name, digest in sources.items()),
                    'pinned source file set')
    return suite


def check_sources(suite, roots):
    for language in ('go', 'rust'):
        root = check_source(roots[language], suite[language + '_revision'])
        require(not subprocess.check_output(
            ['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root, text=True).strip(),
            'core source contains untracked files')
        for row in suite['ports']:
            for name, digest in row[language]['sources'].items():
                require(sha((root / name).read_bytes()) == digest,
                        'reviewed core source drift: ' + name)
        roots[language] = root
    return roots


def probe_source(suite, language):
    if language == 'go':
        lines = ['package main', '', 'import (', '"fmt"',
                 '"github.com/sage-x-project/sage/pkg/agent/guard010"', ')', '', 'func main() {']
        for row in suite['ports']:
            api = row[language]
            lines += ['var _ *guard010.' + name for name in api['types']]
            for name in api['references']:
                receiver, dot, method = name.partition('.')
                expression = ('(*guard010.' + receiver + ').' + method
                              if dot and receiver not in
                              {'Authority', 'IntentPolicy', 'Component', 'ClientSender'}
                              else 'guard010.' + name)
                lines.append('_ = ' + expression)
            lines += ['fmt.Println(' + json.dumps(row['port']) + ')']
        return '\n'.join(lines + ['}', ''])
    lines = ['use sage_crypto_core::guard010;', '', 'fn main() {']
    for row in suite['ports']:
        api = row[language]
        lines += ['let _ = std::mem::size_of::<guard010::' + name + '>();'
                  for name in api['types']]
        lines += ['let _ = std::mem::size_of::<Box<dyn guard010::' + name + '>>();'
                  for name in api['traits']]
        lines += ['let _ = guard010::' + name + ';' for name in api['references']]
        lines += ['println!(' + json.dumps(row['port']) + ');']
    return '\n'.join(lines + ['}', ''])


def private_source(language):
    if language == 'go':
        return ('package main\nimport "github.com/sage-x-project/sage/pkg/agent/guard010"\n'
                'func main() { _ = guard010.newMCPHost }\n')
    return 'use sage_crypto_core::guard010::mcp_transport::Host;\nfn main() {}\n'


def check_private_rejection(language, result):
    stderr = result.stderr
    if language == 'go':
        expected = 'guard010.newMCPHost' in stderr and any(
            value in stderr for value in ('undefined:', 'unexported', 'not exported'))
    else:
        errors = re.findall(r'error\[(E[0-9]+)\]', stderr)
        expected = errors == ['E0603'] and 'mcp_transport' in stderr and 'private' in stderr
    require(result.returncode != 0 and expected, 'private assembly compiler rejection')


def compile_probes(temp, suite, roots):
    environment = os.environ.copy()
    environment.update(GOPROXY='off', GOFLAGS='-mod=mod', CARGO_NET_OFFLINE='true',
                       GOCACHE=str(temp / 'go-cache'), CARGO_TARGET_DIR=str(temp / 'rust-target'))
    for language in ('go', 'rust'):
        directory = temp / language
        directory.mkdir()
        if language == 'go':
            source = directory / 'main.go'
            (directory / 'go.mod').write_text(
                'module sage-inspector-host-api\n\ngo 1.26.0\n\n'
                'require github.com/sage-x-project/sage v0.0.0\n'
                f'replace github.com/sage-x-project/sage => {roots[language]}\n')
            binary = temp / 'go-probe'
            build = ['go', 'build', '-o', str(binary), '.']
        else:
            (directory / 'src').mkdir()
            source = directory / 'src/main.rs'
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="host_api_probe"\nversion="0.0.0"\n'
                'edition="2021"\nrust-version="1.88"\n\n[dependencies]\n'
                f'sage_crypto_core={{path={json.dumps(str(roots[language]))}}}\n')
            binary = temp / 'rust-target/debug/host_api_probe'
            build = ['cargo', 'build', '--offline', '--quiet']
        source.write_text(probe_source(suite, language))
        subprocess.run(build, cwd=directory, env=environment, check=True, timeout=300)
        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                check=True, timeout=10)
        require(not result.stderr and result.stdout.splitlines() ==
                [row['port'] for row in suite['ports']], 'public probe execution marker')
        source.write_text(private_source(language))
        result = subprocess.run(build, cwd=directory, env=environment,
                                capture_output=True, text=True, timeout=300)
        check_private_rejection(language, result)


def expected_report(suite, path=CATALOG):
    return {
        'schema_version': 1, 'kind': 'host-public-api-audit',
        'protocol_version': '0.10.0', 'normative_source_revision': NORMATIVE_REVISION,
        'go_revision': GO_REVISION, 'rust_revision': RUST_REVISION,
        'catalog_sha256': sha(path.read_bytes()),
        'host_contract_sha256': sha((ROOT / 'verification/0.10.0/host-port/cases.json').read_bytes()),
        'probe_sha256': {language: {
            'public': sha(probe_source(suite, language).encode()),
            'private': sha(private_source(language).encode())}
            for language in ('go', 'rust')},
        'status': 'PUBLIC_API_ACCESSIBILITY', 'full_conformance': 'NOT_ESTABLISHED',
        'deployed_host': 'NOT_RUN', 'protected_intent_issuance': 'NOT_RUN',
        'private_assembly': {'go': 'NOT_IMPORTABLE', 'rust': 'NOT_IMPORTABLE'},
        'ports': [dict(row, evidence='SOURCE_REVIEW_ONLY' if row['port'] == 'IntentSigner'
                       else 'EXTERNAL_COMPILATION_ONLY') for row in suite['ports']],
    }


def check_report(report):
    suite = catalog()
    require(type(report) is dict and json.dumps(report, sort_keys=True) ==
            json.dumps(expected_report(suite), sort_keys=True),
            'public API report scope or provenance')
    return len(suite['ports'])


def inspect(go_root, rust_root):
    suite = catalog()
    roots = check_sources(suite, {'go': go_root, 'rust': rust_root})
    with tempfile.TemporaryDirectory(prefix='sage-host-api-') as directory:
        compile_probes(Path(directory), suite, roots)
    return expected_report(suite)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path)
    parser.add_argument('--rust-root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if bool(args.go_root) != bool(args.rust_root) or args.output and not args.go_root:
        parser.error('supply both core roots; output requires execution')
    report = inspect(args.go_root, args.rust_root) if args.go_root else json.loads(REPORT.read_text())
    count = check_report(report)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'ports': count, 'status': report['status'],
                      'deployed_host': report['deployed_host']}))


if __name__ == '__main__':
    main()
