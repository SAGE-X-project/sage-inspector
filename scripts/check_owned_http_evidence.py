"""Run and recheck a bounded public HTTP observer; preserve its partial scope."""
import argparse
import ast
import json
import re
from pathlib import Path
import trace
import unittest


def verify(directory):
    import owned_http_observation as o
    report=o.load((directory/'owned-http-native.json').read_bytes())
    fresh=o.assess(report['observations'])
    o.require(set(report)==set(fresh)|{'observer','execution'},'closed native report fields')
    bound={k:report[k] for k in fresh}
    bound['evidence_kind']=fresh['evidence_kind']
    o.require(o.canonical(bound)==o.canonical(fresh) and fresh['status_counts']=={'PARTIAL':4,'NOT_RUN':579} and all(fresh['scenario_results'].values()) and report['evidence_kind']=='inspector-launched-native-owned-http-processes','separate bounded native result')
    observer=report['observer'];revision=(directory/'owned-http-revision.txt').read_text().strip()
    o.require(set(observer)=={'repository','revision','source_sha256'} and observer['repository']=='SAGE-X-project/sage-inspector' and type(observer['revision']) is str and re.fullmatch('[0-9a-f]{40}',revision) is not None and observer['revision']==revision,'actual checkout identity')
    execution=report['execution'];subject=o.subject();o.compiled_modules(execution['build_info'],subject['modules'])
    o.require(type(execution['adapter_sha256']) is str and re.fullmatch('[0-9a-f]{64}',execution['adapter_sha256']) is not None,'recorded native executable digest')
    o.require(execution['modules']==[{'Path':p,**v} for p,v in subject['modules'].items()] and execution['compiler']=='go version go1.26.8 linux/amd64' and type(execution['process_count']) is int and execution['process_count']==22 and execution['runtime']=='actual-public-owned-loopback-TLS-adapter','separate four-module proof')
    _,cases=o.fixtures();traces=execution['raw_trace']
    o.require(len(traces)==22 and [r['id'] for r in traces]==list(cases) and len(report['observations'])==22,'exact actual native branches')
    attempts=[json.loads(line) for line in (directory/'owned-http-native.attempts.jsonl').read_text().splitlines()]
    o.require(o.canonical(attempts)==o.canonical(traces),'unaltered raw attempt log')
    for observed,raw in zip(report['observations'],traces):
        input_bytes=o.canonical(cases[raw['id']]['input']);stdout=bytes.fromhex(raw['stdout_hex'])
        o.require(raw['input_hex']==input_bytes.hex() and raw['input_sha256']==o.sha(input_bytes)==observed['input_sha256'] and raw['stdout_sha256']==o.sha(stdout) and raw['stderr_hex']=='' and type(raw['returncode']) is int and raw['returncode']==0 and raw['id']==observed['id'] and o.canonical(o.load(stdout))==o.canonical(observed['actual']),'raw process/result linkage')
    o.require(execution['adapter_source_sha256']=={p:o.sha((o.ROOT/o.ADAPTER/p).read_bytes()) for p in ('fixture.go','main.go','go.mod','go.sum')} and report['observer']['source_sha256']==o.observer_sources(o.ROOT),'actual source bytes')
    print('Owned HTTP native evidence: 22 processes; 4 PARTIAL / 579 NOT_RUN; no full conformance')


def run(directory):
    # Imports and native execution are traced before authored units. The units'
    # synthetic process mocks remain a separate checker-control result.
    tracer=trace.Trace(count=True,trace=False)
    def exercise():
        import owned_http_observation as o
        with (directory/'owned-http-native.attempts.jsonl').open('x') as attempts:
            report=o.run_native('go',attempts=attempts)
        with (directory/'owned-http-native.json').open('x') as output:
            output.write(json.dumps(report,indent=2)+'\n')
        o.require(report['status_counts']=={'PARTIAL':4,'NOT_RUN':579} and len(report['scenario_results'])==22 and all(report['scenario_results'].values()),'native observation failed; raw result preserved')
        suite=unittest.defaultTestLoader.loadTestsFromName('test_owned_http_observation')
        if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():raise SystemExit(1)
    tracer.runfunc(exercise)
    path=Path(__file__).with_name('owned_http_observation.py').resolve()
    statements={n.lineno for n in ast.walk(ast.parse(path.read_text())) if isinstance(n,ast.stmt)}
    hits={line for (file,line),count in tracer.results().counts.items() if Path(file).resolve()==path and count}
    coverage={'covered':len(statements&hits),'statements':len(statements),'unexecuted':sorted(statements-hits),'scope':'observer Python statement lines; native plus authored checker controls'}
    with (directory/'owned-http-python-coverage.json').open('x') as output:
        output.write(json.dumps(coverage,indent=2)+'\n')
    print('Owned HTTP Python coverage:',coverage)
    if not statements or coverage['covered']/coverage['statements']<.90:raise SystemExit(1)
    verify(directory)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--directory',type=Path,required=True)
    args=parser.parse_args()
    if args.run:run(args.directory)
    else:verify(args.directory)
