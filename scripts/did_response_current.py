"""Recheck frozen DID contracts against a separate repaired public module."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import did_profile_observation as old
from a2a_card_observation import canonical, compiler_inputs, execute
from current_spec_catalog import ROOT, load, require, sha

SUBJECT_PATH = 'verification/0.10.0/a2a-did/did-response-current-subject.json'
SUBJECT_SHA256 = '28946db1c3295b38fb8fa90d9dbb8f746ee4a565516810bfec26bd9679a1d8f4'
ADAPTER = 'adapters/did-response-current'


def subject(root=ROOT):
    raw = (root / SUBJECT_PATH).read_bytes()
    require(sha(raw) == SUBJECT_SHA256, 'repaired subject drift')
    value = load(raw)
    require(set(value) == {'repository', 'revision', 'modules'} and value['repository'] == 'SAGE-X-project/did-go'
            and re.fullmatch('[0-9a-f]{40}', value['revision']) is not None
            and set(value['modules']) == set(old.MODULES), 'closed repaired subject')
    for path, dep in value['modules'].items():
        require(set(dep) == {'Version', 'Sum', 'GoModSum'} and dep['Version'].startswith('v0.0.0-')
                and all(re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', dep[k]) for k in ('Sum', 'GoModSum')),
                'closed repaired module')
    return value


def assess(observations, root=ROOT):
    # Reuse the original independent expected bodies without copying or
    # weakening either known finding. Only the subject identity is different.
    report = old.assess(observations, root)
    report.update(kind='did-response-repair-observation', subject=subject(root),
                  subject_manifest_sha256=SUBJECT_SHA256, historical_results_merged=False)
    return report


def module_info(go, directory, env, expected):
    result = []
    for path, wanted in expected.items():
        value = load(execute([go, 'list', '-mod=readonly', '-m', '-json', path], directory, env).stdout)
        require(value.get('Path') == path and not value.get('Replace') and not value.get('Main')
                and all(value.get(k) == v for k, v in wanted.items()), 'repaired module identity')
        result.append({'Path': path, **wanted})
    require(execute([go, 'mod', 'verify'], directory, env).stdout == b'all modules verified\n', 'repaired cache verification')
    return result


def observer_sources(root):
    paths = ('scripts/did_response_current.py', 'scripts/did_profile_observation.py',
             'scripts/a2a_card_observation.py', 'scripts/a2a_did_catalog.py',
             'scripts/current_spec_catalog.py', SUBJECT_PATH,
             'vectors/0.10.0/did-profile-observations.json')
    return {p: sha((root / p).read_bytes()) for p in paths}


def run_native(go, root=ROOT):
    selected = subject(root); before = observer_sources(root)
    directory = root / ADAPTER
    env = os.environ.copy()
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='-mod=readonly', GOPROXY='off', CGO_ENABLED='0')
    compiler = execute([go, 'version'], directory, env).stdout.decode().strip()
    require(re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)', compiler) is not None, 'required compiler')
    modules = module_info(go, directory, env, selected['modules'])
    source = compiler_inputs(go, directory, env)
    require(set(source) == {'main.go', 'go.mod', 'go.sum'}, 'complete repaired adapter source')
    observations = []; raw_trace = []
    with tempfile.TemporaryDirectory(prefix='sage-response-current-') as tmp:
        binary = Path(tmp) / 'observer'
        execute([go, 'build', '-trimpath', '-o', str(binary), '.'], directory, env)
        digest = sha(binary.read_bytes())
        build_info = execute([go, 'version', '-m', '-json', str(binary)], directory, env).stdout
        info = load(build_info)
        deps = {v['Path']: v for v in info['Deps']}
        require(info['GoVersion'] == 'go1.26.8' and set(deps) == set(selected['modules']), 'compiled graph identity')
        for path, dep in selected['modules'].items():
            require(path in deps and not deps[path].get('Replace')
                    and deps[path]['Version'] == dep['Version'] and deps[path]['Sum'] == dep['Sum'], 'compiled dependency identity')
        for c in old.fixtures(root):
            if c['id'] in old.UNSUPPORTED: continue
            raw = canonical(c['input'])
            done = subprocess.run([str(binary)], input=raw, capture_output=True, timeout=20, env=env, check=True)
            require(len(done.stdout) <= 2 * 1024 * 1024 and not done.stderr, 'bounded clean native output')
            observations.append({'id': c['id'], 'input_sha256': sha(raw), 'actual': load(done.stdout)})
            raw_trace.append({'id': c['id'], 'stdout_hex': done.stdout.hex(), 'stdout_sha256': sha(done.stdout)})
        require(digest == sha(binary.read_bytes()), 'repaired executable changed')
    require(source == compiler_inputs(go, directory, env) and modules == module_info(go, directory, env, selected['modules']), 'repaired build inputs changed')
    require(before == observer_sources(root), 'repaired observer source changed')
    report = assess(observations, root)
    report.update(evidence_kind='inspector-launched-native-DID-processes',
                  observer={'repository': 'SAGE-X-project/sage-inspector',
                            'revision': execute(['git', 'rev-parse', 'HEAD'], root, env).stdout.decode().strip(),
                            'source_sha256': before},
                  execution={'compiler': compiler, 'adapter_sha256': digest, 'adapter_source_sha256': source,
                             'modules': modules, 'build_info': info, 'process_count': len(observations),
                             'runtime': 'library-api-and-owned-loopback-TLS', 'raw_trace': raw_trace})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true'); parser.add_argument('--go', default='go')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run_native(args.go) if args.native else assess([])
        with args.output.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        require(not report['status_counts'].get('FAIL', 0), 'repaired DID contract finding; FAIL preserved')
        if args.native:
            require(report['status_counts'] == {'NOT_RUN': 555, 'PARTIAL': 25, 'UNSUPPORTED': 3}, 'incomplete repaired native inspection')
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as e:
        parser.exit(1, 'Repaired DID observation FAIL: ' + str(e) + '\n')
    print('Repaired DID observation: ' + str(report['status_counts']) + '; full conformance NOT_ESTABLISHED')

if __name__ == '__main__': main()
