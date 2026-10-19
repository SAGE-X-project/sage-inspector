"""Inspect a real public paired DID operation under an explicit fixture Source."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from a2a_did_catalog import ROOT, SPEC_REVISION, inventory
from a2a_card_observation import canonical, compiler_inputs, execute
from current_spec_catalog import load, require, sha

CONTRACT = 'didp-03-two-observations'
FIXTURE_PATH = 'vectors/0.10.0/did-paired-observations.json'
FIXTURE_SHA256 = 'cc22289fc9ce2e6f76c9658da81ffd50dcd3bac6b375da0ff1fd517a180a7b16'
SUBJECT_PATH = 'verification/0.10.0/a2a-did/did-paired-subject.json'
SUBJECT_SHA256 = 'c26a759ec5d4bbd011d5f05ce78fb5acb86331f05d5690aba42188ae769ccddd'
ADAPTER = 'adapters/did-paired-views'
SCENARIOS = {'changing', 'created', 'deactivated', 'unusable', 'second-error', 'source-stale', 'invalid-id', 'scratch'}


def subject(root=ROOT):
    raw = (root / SUBJECT_PATH).read_bytes()
    require(sha(raw) == SUBJECT_SHA256, 'paired subject drift')
    value = load(raw)
    paths = {'github.com/sage-x-project/did-go', 'github.com/sage-x-project/did-go/advanced/sage'}
    require(set(value) == {'repository', 'revision', 'modules'}
            and value['repository'] == 'SAGE-X-project/did-go'
            and re.fullmatch('[0-9a-f]{40}', value['revision']) is not None
            and set(value['modules']) == paths, 'closed paired subject')
    for dep in value['modules'].values():
        require(set(dep) == {'Version', 'Sum', 'GoModSum'} and dep['Version'].startswith('v0.0.0-')
                and all(re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', dep[k]) for k in ('Sum', 'GoModSum')),
                'closed paired module')
    require(value['modules']['github.com/sage-x-project/did-go/advanced/sage']['Version'].endswith(value['revision'][:12]), 'paired revision linkage')
    return value


def fixtures(root=ROOT):
    raw = (root / FIXTURE_PATH).read_bytes()
    require(sha(raw) == FIXTURE_SHA256, 'paired fixture drift')
    value = load(raw)
    require(set(value) == {'schema', 'spec_revision', 'contract_id', 'scope', 'cases'}
            and value['schema'] == 'sage-paired-did-fixtures-v1'
            and value['spec_revision'] == SPEC_REVISION and value['contract_id'] == CONTRACT
            and value['scope'] == 'configured-fixture-source-paired-api', 'paired fixture identity')
    rows = value['cases']
    require(type(rows) is list and len(rows) == 8 and {c['id'] for c in rows} == SCENARIOS, 'complete paired scenarios')
    for c in rows:
        require(set(c) == {'id', 'input', 'expected'} and c['input'] == {'scenario': c['id']}, 'closed paired scenario')
    return [{**c, 'input_sha256': sha(canonical(c['input']))} for c in rows]


def checked_actual(value):
    require(type(value) is dict and set(value) == {'source_calls', 'producer_calls', 'results'}
            and all(type(value[k]) is int and 0 <= value[k] <= 4 for k in ('source_calls', 'producer_calls'))
            and type(value['results']) is list and 1 <= len(value['results']) <= 2, 'closed actual paired output')
    rows = []
    for row in value['results']:
        require(type(row) is dict and set(row) == {'core10', 'did11', 'code'} and type(row['code']) is str and len(row['code']) <= 100, 'closed actual pair')
        result = {'code': row['code']}
        for name in ('core10', 'did11'):
            view = row[name]
            if view is None:
                result[name] = None
                continue
            require(type(view) is dict and set(view) == {'body_hex', 'metadata_hex', 'content_type'}
                    and type(view['content_type']) is str and len(view['content_type']) <= 100, 'closed paired view')
            decoded = {'content_type': view['content_type']}
            for encoded, output in (('body_hex', 'body'), ('metadata_hex', 'metadata')):
                text = view[encoded]
                require(type(text) is str and len(text) <= 524288
                        and re.fullmatch('(?:[0-9a-f]{2})*', text) is not None, 'bounded paired bytes')
                decoded[output] = load(bytes.fromhex(text))
                require(type(decoded[output]) is dict, 'paired JSON object')
            result[name] = decoded
        rows.append(result)
    return {'source_calls': value['source_calls'], 'producer_calls': value['producer_calls'], 'results': rows}


def matches(actual, expected):
    try:
        return canonical(checked_actual(actual)) == canonical(expected)
    except (ValueError, KeyError, TypeError):
        return False


def assess(observations, root=ROOT):
    expected = {c['id']: c for c in fixtures(root)}
    require(type(observations) is list and len(observations) <= 8, 'bounded paired observations')
    seen = {}
    for row in observations:
        require(type(row) is dict and set(row) == {'id', 'input_sha256', 'actual'}
                and type(row['id']) is str and row['id'] in expected and row['id'] not in seen, 'paired observation identity')
        c = expected[row['id']]
        require(row['input_sha256'] == c['input_sha256'], 'paired input identity')
        seen[row['id']] = matches(row['actual'], c['expected'])
    status = 'FAIL' if not all(seen.values()) else ('PARTIAL' if len(seen) == 8 else 'NOT_RUN')
    report = inventory(root)
    require(sum(c['id'] == CONTRACT and c['rule_id'] == 'DIDP-03' for c in report['cases']) == 1, 'paired inventory linkage')
    for c in report['cases']:
        c['status'] = status if c['id'] == CONTRACT else 'NOT_RUN'
        if c['id'] == CONTRACT:
            c['coverage_notes'] = 'Actual public ObserveViews with changing fixture Source, full expected pairs, refusal and ownership controls; no operating authority.'
    report.update(kind='paired-DID-observation', evidence_kind='reported-library-output',
                  subject=subject(root), subject_manifest_sha256=SUBJECT_SHA256,
                  fixture_sha256=FIXTURE_SHA256, historical_results_merged=False,
                  scope={'projection': 'CONFIGURED_FIXTURE_SOURCE_PAIRED_API', 'protected_message_authority': 'NOT_RUN',
                         'deployed_registry': 'NOT_BOUND', 'http_binding': 'NOT_RUN', 'full_conformance': 'NOT_ESTABLISHED'},
                  observations=observations, scenario_results=seen,
                  status_counts=dict(Counter(c['status'] for c in report['cases'])))
    return report


def module_info(go, directory, env, expected):
    result = []
    for path, dep in expected.items():
        value = load(execute([go, 'list', '-mod=readonly', '-m', '-json', path], directory, env).stdout)
        require(value.get('Path') == path and not value.get('Replace') and not value.get('Main')
                and all(value.get(k) == v for k, v in dep.items()), 'paired module identity')
        result.append({'Path': path, **dep})
    require(execute([go, 'mod', 'verify'], directory, env).stdout == b'all modules verified\n', 'paired module cache')
    return result


def observer_sources(root):
    paths = ('scripts/did_paired_observation.py', 'scripts/a2a_card_observation.py', 'scripts/a2a_did_catalog.py',
             'scripts/current_spec_catalog.py', FIXTURE_PATH, SUBJECT_PATH)
    return {p: sha((root / p).read_bytes()) for p in paths}


def run_native(go, root=ROOT):
    selected = subject(root)
    before = observer_sources(root)
    directory = root / ADAPTER
    env = os.environ.copy()
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='-mod=readonly', GOPROXY='off', CGO_ENABLED='0')
    compiler = execute([go, 'version'], directory, env).stdout.decode().strip()
    require(re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)', compiler) is not None, 'required paired compiler')
    modules = module_info(go, directory, env, selected['modules'])
    source = compiler_inputs(go, directory, env)
    require(set(source) == {'main.go', 'go.mod', 'go.sum'}, 'complete paired adapter source')
    observations, raw_trace = [], []
    with tempfile.TemporaryDirectory(prefix='sage-paired-inspector-') as tmp:
        binary = Path(tmp) / 'observer'
        execute([go, 'build', '-trimpath', '-o', str(binary), '.'], directory, env)
        digest = sha(binary.read_bytes())
        info = load(execute([go, 'version', '-m', '-json', str(binary)], directory, env).stdout)
        deps = {d['Path']: d for d in info['Deps']}
        require(info['GoVersion'] == 'go1.26.8' and set(deps) == set(selected['modules']), 'compiled paired graph')
        for path, dep in selected['modules'].items():
            require(not deps[path].get('Replace') and deps[path]['Version'] == dep['Version']
                    and deps[path]['Sum'] == dep['Sum'], 'compiled paired dependency')
        for c in fixtures(root):
            raw = canonical(c['input'])
            done = subprocess.run([str(binary)], input=raw, capture_output=True, timeout=20, env=env, check=True)
            require(len(done.stdout) <= 2 * 1024 * 1024 and not done.stderr, 'bounded clean paired process')
            observations.append({'id': c['id'], 'input_sha256': sha(raw), 'actual': load(done.stdout)})
            raw_trace.append({'id': c['id'], 'stdout_hex': done.stdout.hex(), 'stdout_sha256': sha(done.stdout)})
        require(digest == sha(binary.read_bytes()), 'paired executable changed')
    require(source == compiler_inputs(go, directory, env)
            and modules == module_info(go, directory, env, selected['modules']), 'paired build input drift')
    require(before == observer_sources(root), 'paired observer source drift')
    report = assess(observations, root)
    report.update(evidence_kind='inspector-launched-native-paired-DID-processes',
                  observer={'repository': 'SAGE-X-project/sage-inspector',
                            'revision': execute(['git', 'rev-parse', 'HEAD'], root, env).stdout.decode().strip(), 'source_sha256': before},
                  execution={'compiler': compiler, 'adapter_sha256': digest, 'adapter_source_sha256': source,
                             'modules': modules, 'build_info': info, 'process_count': len(observations),
                             'runtime': 'public-library-paired-API', 'raw_trace': raw_trace})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--go', default='go')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run_native(args.go) if args.native else assess([])
        with args.output.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        require(not report['status_counts'].get('FAIL', 0), 'paired contract finding; FAIL preserved')
        if args.native:
            require(report['status_counts'] == {'NOT_RUN': 582, 'PARTIAL': 1}, 'incomplete paired inspection')
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as e:
        parser.exit(1, 'Paired DID inspection FAIL: ' + str(e) + '\n')
    print('Paired DID inspection: ' + str(report['status_counts']) + '; full conformance NOT_ESTABLISHED')

if __name__ == '__main__': main()
