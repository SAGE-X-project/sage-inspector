"""Bind actual native bytes and separately attributed memory-unit witnesses."""
import argparse
import ast
import json
from pathlib import Path
import re
import trace
import unittest


def verify_native(directory):
    import did_authority_observation as o
    report = o.load((directory/'did-authority-native.json').read_bytes())
    fresh = o.assess(report['native_observations'], [])
    o.require(set(report) == set(fresh)|{'observer','execution'}, 'closed native report')
    bound = {k:report[k] for k in fresh}
    bound['evidence_kind'] = fresh['evidence_kind']
    o.require(o.canonical(bound) == o.canonical(fresh) and fresh['status_counts'] == {'NOT_RUN':583} and set(fresh['native_results']) == o.NATIVE_IDS and all(fresh['native_results'].values()) and report['evidence_kind'] == 'inspector-launched-benign-authority-native-processes', 'native alone is not authority-unit proof')
    observer = report['observer']; revision = (directory/'did-authority-revision.txt').read_text().strip()
    o.require(set(observer) == {'repository','revision','source_sha256'} and observer['repository'] == 'SAGE-X-project/sage-inspector' and re.fullmatch('[0-9a-f]{40}', revision) is not None and observer['revision'] == revision and observer['source_sha256'] == o.observer_sources(), 'native observer source identity')
    execution = report['execution']; selected = o.subject()
    o.compiled_modules(execution['build_info'], selected['modules'], revision)
    o.require(type(execution['adapter_sha256']) is str and re.fullmatch('[0-9a-f]{64}',execution['adapter_sha256']) is not None and execution['modules'] == [{'Path':p,**v} for p,v in selected['modules'].items()] and execution['compiler'] == 'go version go1.26.8 linux/amd64' and type(execution['process_count']) is int and execution['process_count'] == 2 and execution['runtime'] == 'actual-public-owned-loopback-TLS-adapter', 'separate native binary and selected module proof')
    o.require(execution['adapter_source_sha256'] == {p:o.sha((o.ROOT/o.ADAPTER/p).read_bytes()) for p in o.SOURCE_FILES}, 'native compile inputs')
    traces = execution['raw_trace']
    attempts = [o.load(line) for line in (directory/'did-authority-native.attempts.jsonl').read_bytes().splitlines()]
    o.require(o.canonical(attempts) == o.canonical(traces) and len(traces) == len(report['native_observations']) == 2 and [r['id'] for r in traces] == ['bare','http'], 'exact unaltered two native attempts')
    for observed, raw in zip(report['native_observations'], traces):
        input_bytes = o.canonical({'completion':raw['id']}); stdout = bytes.fromhex(raw['stdout_hex'])
        o.require(set(raw) == {'id','input_hex','input_sha256','stdout_hex','stdout_sha256','stderr_hex','returncode'} and raw['input_hex'] == input_bytes.hex() and raw['input_sha256'] == o.sha(input_bytes) == observed['input_sha256'] and raw['id'] == observed['id'] and raw['stdout_sha256'] == o.sha(stdout) and raw['stderr_hex'] == '' and type(raw['returncode']) is int and raw['returncode'] == 0 and o.canonical(o.load(stdout)) == o.canonical(observed['actual']), 'raw native result linkage')
    return report


def verify(directory):
    import did_authority_observation as o
    native = verify_native(directory)
    raw = (directory/'did-authority-tests.jsonl').read_bytes()
    units = o.parse_units(raw)
    fresh = o.assess(native['native_observations'], units)
    o.require(fresh['status_counts'] == {'PARTIAL':2,'NOT_RUN':581} and all(fresh['unit_results'].values()), 'complete bounded authority evidence')
    fresh.update(evidence_kind='actual-native-plus-attributed-memory-units', native_report_sha256=o.sha((directory/'did-authority-native.json').read_bytes()), unit_event_sha256=o.sha(raw), unit_test_source_sha256=o.sha((o.ROOT/o.ADAPTER/'main_test.go').read_bytes()))
    path = directory/'did-authority-observation.json'
    if path.exists():
        o.require(o.canonical(o.load(path.read_bytes())) == o.canonical(fresh), 'unaltered independently recomputed authority report')
    else:
        with path.open('x') as output:
            output.write(json.dumps(fresh,indent=2)+'\n')
    print('DID card authority: actual benign native 2; memory-only controls 13; 2 PARTIAL / 581 NOT_RUN; full conformance NOT_ESTABLISHED')
    return fresh


def run(directory):
    tracer = trace.Trace(count=True,trace=False)
    def exercise():
        import did_authority_observation as o
        with (directory/'did-authority-native.attempts.jsonl').open('x') as attempts:
            report = o.run_native('go',attempts=attempts)
        with (directory/'did-authority-native.json').open('x') as output:
            output.write(json.dumps(report,indent=2)+'\n')
        verify_native(directory)
        suite = unittest.defaultTestLoader.loadTestsFromName('test_did_authority_observation')
        if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():raise SystemExit(1)
    tracer.runfunc(exercise)
    path = Path(__file__).with_name('did_authority_observation.py').resolve()
    statements = {n.lineno for n in ast.walk(ast.parse(path.read_text())) if isinstance(n,ast.stmt)}
    hits = {line for (file,line),count in tracer.results().counts.items() if Path(file).resolve() == path and count}
    coverage = {'covered':len(statements&hits),'statements':len(statements),'unexecuted':sorted(statements-hits),'scope':'Python observer statement lines; benign native plus separate synthetic checker controls'}
    with (directory/'did-authority-python-coverage.json').open('x') as output:
        output.write(json.dumps(coverage,indent=2)+'\n')
    print('DID authority Python coverage:',coverage)
    if not statements or coverage['covered']/coverage['statements'] < .90:raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--directory',type=Path,required=True)
    args = parser.parse_args()
    if args.run:run(args.directory)
    else:verify(args.directory)
