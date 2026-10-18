"""Recompute bounded ingress evidence; synthetic units never replace execution."""
import argparse
import ast
import json
from pathlib import Path
import re
import trace
import unittest


def verify(directory):
    import ingress_refusal_observation as o
    report = o.load((directory / 'ingress-refusal-native.json').read_bytes())
    fresh = o.assess(report['memory_observations'], report['native_observations'])
    o.require(set(report) == set(fresh) | {'observer', 'execution'}, 'closed execution report')
    projected = {k: report[k] for k in fresh}; projected['evidence_kind'] = fresh['evidence_kind']
    o.require(o.canonical(projected) == o.canonical(fresh) and fresh['status_counts'] == {'PARTIAL': 3, 'NOT_RUN': 580} and report['evidence_kind'] == 'inspector-launched-memory-unit-and-separate-benign-native', 'bounded complete evidence; no historical union')
    selected = o.subject(); observer = report['observer']; execution = report['execution']
    revision = (directory / 'ingress-refusal-revision.txt').read_text().strip()
    o.require(re.fullmatch('[0-9a-f]{40}', revision) is not None and o.canonical(observer) == o.canonical({'repository': 'SAGE-X-project/sage-inspector', 'revision': revision, 'source_sha256': o.observer_sources()}), 'actual clean observer checkout/source identity')
    o.require(set(execution) == {'memory', 'native'}, 'separate execution proofs')
    memory = execution['memory']; native = execution['native']
    o.require(set(memory) == {'download', 'package_source_sha256', 'package_inputs', 'dependencies', 'test_binary_sha256', 'build_info', 'build_command', 'test_command', 'execution_directory', 'raw_test_sha256', 'test_returncode', 'test_stderr_hex', 'scope'}, 'closed public unit execution proof')
    raw = (directory / 'ingress-refusal-memory-tests.jsonl').read_bytes()
    o.require(o.canonical(o.witnesses(raw)) == o.canonical(report['memory_observations']) and memory['raw_test_sha256'] == o.sha(raw) and type(memory['test_returncode']) is int and memory['test_returncode'] == 0 and memory['test_stderr_hex'] == '', 'raw actual unit stream linkage')
    expected_adk = {'Path': 'github.com/sage-x-project/sage-adk', **selected['modules']['github.com/sage-x-project/sage-adk']}
    o.require(o.canonical(memory['download']) == o.canonical(expected_adk) and memory['package_source_sha256'] == selected['package_sources'], 'canonical public module and package source proof')
    inputs = memory['package_inputs']
    expected_inputs = {'GoFiles': sorted(p.rsplit('/', 1)[1] for p in selected['package_sources'] if p.endswith('.go') and not p.endswith('_test.go')), 'TestGoFiles': sorted(p.rsplit('/', 1)[1] for p in selected['package_sources'] if p.endswith('_test.go')), 'XTestGoFiles': [], 'EmbedFiles': ['schema.json']}
    o.require(o.canonical(inputs) == o.canonical(expected_inputs), 'recorded package inputs, not full compiler closure')
    expected_deps = [{'Path': p, **v} for p, v in selected['modules'].items() if p != 'github.com/sage-x-project/sage-adk']
    o.require(o.canonical(memory['dependencies']) == o.canonical(expected_deps), 'separate public dependency metadata')
    info = memory['build_info']
    o.require(o.canonical(o.load((directory / 'ingress-refusal-test-build-info.json').read_bytes())) == o.canonical(info), 'raw test BuildInfo linkage')
    settings = o.build_settings(info)
    o.require(info.get('GoVersion') == 'go1.26.8' and info.get('Path') == o.PACKAGE + '.test' and settings.get('-race') == 'true' and memory['scope'] == 'verified public module as test main; no compiled dependency metadata claim', 'test BuildInfo limitation')
    o.require(type(memory['execution_directory']) is str and Path(memory['execution_directory']).name == 'module' and Path(memory['execution_directory']).is_absolute(), 'actual temporary full module root')
    binary = str(Path(memory['execution_directory']).parent / 'ingress.test')
    o.require(memory['build_command'] == ['go', 'test', '-mod=readonly', '-race', '-c', '-o', binary, './core/a2abinding'] and memory['test_command'] == ['go', 'tool', 'test2json', '-t', '-p', o.PACKAGE, binary, '-test.v=test2json', '-test.run=^' + o.PARENT + '$', '-test.count=1', '-test.timeout=30s'], 'exact selected compiled unit command')
    o.require(set(native) == {'adapter_sha256', 'adapter_source_sha256', 'modules', 'build_info', 'raw_trace', 'process_count'} and type(native['process_count']) is int and native['process_count'] == 2, 'separate normal native proof')
    o.compiled_native(native['build_info'], selected['modules'], revision)
    o.require(native['modules'] == [{'Path': p, **v} for p, v in selected['modules'].items()] and native['adapter_source_sha256'] == {p: o.sha((o.ROOT / o.ADAPTER / p).read_bytes()) for p in ('main.go', 'fixture.go', 'card.go', 'go.mod', 'go.sum')}, 'separate native public modules/source')
    for digest in [memory['test_binary_sha256'], native['adapter_sha256']]: o.require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest) is not None, 'recorded executable digest')
    attempts = [o.load(line) for line in (directory / 'ingress-refusal-native.attempts.jsonl').read_bytes().splitlines()]
    o.require(o.canonical(attempts) == o.canonical(native['raw_trace']) and len(attempts) == 2 and [t['id'] for t in attempts] == ['bare', 'http'], 'complete separate raw native attempts')
    for row in attempts:
        o.require(set(row) == {'id', 'input_hex', 'input_sha256', 'stdout_hex', 'stdout_sha256', 'stderr_hex', 'returncode'}, 'closed raw native trace')
        raw_input = o.canonical({'completion': row['id']}); stdout = o.rawhex(row['stdout_hex'], 262144)
        o.require(row['input_hex'] == raw_input.hex() and row['input_sha256'] == o.sha(raw_input) and row['stdout_sha256'] == o.sha(stdout) and row['stderr_hex'] == '' and type(row['returncode']) is int and row['returncode'] == 0 and o.canonical(o.load(stdout)) == o.canonical(report['native_observations'][row['id']]), 'actual benign native process/output linkage')
    print('Ingress evidence: 5 memory controls / 2 separate normal native TLS; 3 PARTIAL / 580 NOT_RUN')


def run(directory):
    tracer = trace.Trace(count=True, trace=False)
    def exercise():
        import ingress_refusal_observation as o
        report = o.run_native('go', directory)
        with (directory / 'ingress-refusal-native.json').open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        suite = unittest.defaultTestLoader.loadTestsFromName('test_ingress_refusal_observation')
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if not result.wasSuccessful() or result.skipped: raise SystemExit(1)
        verify(directory)
    tracer.runfunc(exercise)
    path = Path(__file__).with_name('ingress_refusal_observation.py').resolve()
    statements = {n.lineno for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, ast.stmt)}
    hits = {line for (file, line), count in tracer.results().counts.items() if Path(file).resolve() == path and count}
    coverage = {'covered': len(statements & hits), 'statements': len(statements), 'unexecuted': sorted(statements - hits), 'scope': 'observer statement lines; actual remote runtime plus authored synthetic parser units'}
    with (directory / 'ingress-refusal-python-coverage.json').open('x') as output: output.write(json.dumps(coverage, indent=2) + '\n')
    print('Ingress Python coverage:', coverage)
    if not statements or coverage['covered'] / coverage['statements'] < .90: raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if args.run: run(args.directory)
    else: verify(args.directory)
