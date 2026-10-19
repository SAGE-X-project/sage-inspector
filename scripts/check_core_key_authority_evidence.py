"""Recompute paired native output; synthetic parser tests are separate evidence."""
import argparse
import json
import os
from pathlib import Path
import re
import unittest
import core_key_authority_observation as o
import core_key_authority_execution as x

NAMES = ['go-compiler','go-download','go-cache','go-modules','go-package','go-build','go-build-info','go-tests','rust-compiler','rust-revision','rust-tree','rust-files','rust-build','rust-tests']


def verify(directory):
    report = o.load((directory/'core-key-authority-native.json').read_bytes())
    go_raw = (directory/'go-tests.stdout').read_bytes(); rust_raw = (directory/'rust-tests.stdout').read_bytes()
    fresh = o.assess(o.go_witnesses(go_raw), o.rust_witnesses(rust_raw))
    o.closed(report, set(fresh) | {'observer','execution'}, 'actual report')
    projection = {k:report[k] for k in fresh}; projection['evidence_kind'] = fresh['evidence_kind']
    o.require(o.canonical(projection) == o.canonical(fresh) and report['evidence_kind'] == 'inspector-launched-paired-core-native-units' and fresh['status_counts'] == {'PARTIAL':2,'NOT_RUN':581}, 'full recomputed report and historical separation')
    revision = (directory/'core-key-authority-revision.txt').read_text().strip()
    o.require(re.fullmatch('[0-9a-f]{40}', revision) is not None and o.canonical(report['observer']) == o.canonical({'repository':'SAGE-X-project/sage-inspector','revision':revision,'source_sha256':o.observer_sources()}), 'exact observer identity/source')
    selected = o.subject(); execution = report['execution']; o.closed(execution, {'go','rust','commands','environment','capture_directory'}, 'execution')
    env = {'GOTOOLCHAIN':'local','GOWORK':'off','GOFLAGS':'-mod=readonly','GOPROXY':'off','CGO_ENABLED':'1','RUSTUP_TOOLCHAIN':'1.88.0','CARGO_TERM_COLOR':'never','CARGO_INCREMENTAL':'0'}
    o.require(execution['environment'] == env, 'fixed offline execution environment')
    o.require(type(execution['capture_directory']) is str and Path(execution['capture_directory']).is_absolute(), 'original evidence capture directory')
    go = execution['go']; rust = execution['rust']
    o.closed(go, {'download','selected_sources','whole_source_sha256','whole_source_files','package_inputs','modules','build_info','test_binary_sha256','execution_directory','raw_test_sha256'}, 'Go acquisition proof')
    o.closed(rust, {'revision','tree','selected_sources','whole_source_sha256','whole_source_files','cargo_lock_sha256','test_binary_sha256','execution_directory','target_directory','test_executable','raw_test_sha256','compiler'}, 'Rust acquisition proof')
    groot = Path(go['execution_directory']); rroot = Path(rust['execution_directory']); target = Path(rust['target_directory']); gbin = groot.parent/'authority.test'; rbin = Path(rust['test_executable'])
    o.require(groot.is_absolute() and groot.name == 'module' and groot.parent.name.startswith('sage-core-key-authority-go-') and rroot.is_absolute() and target.is_absolute() and target.name == 'target' and target.parent.name.startswith('sage-core-key-authority-rust-'), 'owned whole source/target locations')
    expected = {
        'go-compiler':(['go','version'],None),
        'go-download':(['go','mod','download','-json',selected['go']['module']['Path']+'@'+selected['go']['module']['Version']],execution['capture_directory']),
        'go-cache':(['go','mod','verify'],str(groot)),
        'go-modules':(['go','list','-mod=readonly','-m','-json','all'],str(groot)),
        'go-package':(['go','list','-mod=readonly','-json','.'],str(groot/'pkg/agent/hpke')),
        'go-build':(['go','test','-mod=readonly','-race','-c','-o',str(gbin),'./pkg/agent/hpke'],str(groot)),
        'go-build-info':(['go','version','-m','-json',str(gbin)],str(groot)),
        'go-tests':(['go','tool','test2json','-t','-p',o.PACKAGE,str(gbin),'-test.v=test2json','-test.run=^'+o.PARENT+'$','-test.count=1','-test.timeout=30s'],str(groot)),
        'rust-compiler':(['rustc','--version'],str(rroot)),
        'rust-revision':(['git','rev-parse','HEAD'],str(rroot)),
        'rust-tree':(['git','rev-parse','HEAD^{tree}'],str(rroot)),
        'rust-files':(['git','ls-files','-z'],str(rroot)),
        'rust-build':(['cargo','test','--locked','--offline','--lib','--no-run','--message-format=json','--target-dir',str(target)],str(rroot)),
        'rust-tests':([str(rbin),'handshake_key_authority_','--nocapture','--test-threads=1'],str(rroot))}
    commands = execution['commands']
    o.require(type(commands) is list and [c.get('name') for c in commands] == NAMES, 'complete exact command order')
    for row in commands:
        o.closed(row, {'name','args','cwd','returncode','stdout_sha256','stderr_sha256'}, 'command proof')
        args, cwd = expected[row['name']]
        o.integer(row['returncode'], 0, 'native command returncode')
        o.require(row['args'] == args and type(row['cwd']) is str and Path(row['cwd']).is_absolute() and (cwd is None or row['cwd'] == cwd), 'exact native command/cwd')
        for pipe in ['stdout','stderr']:
            raw = (directory/(row['name']+'.'+pipe)).read_bytes()
            o.require(len(raw) <= 16777216 and row[pipe+'_sha256'] == o.sha(raw), 'actual retained command output linkage')
    o.require((directory/'go-tests.stderr').read_bytes() == (directory/'rust-tests.stderr').read_bytes() == b'', 'empty native test stderr')
    o.require((directory/'go-compiler.stdout').read_bytes().strip() == b'go version go1.26.8 linux/amd64' and (directory/'rust-compiler.stdout').read_bytes().strip() == b'rustc 1.88.0 (6b00bc388 2025-06-23)' and rust['compiler'] == 'rustc 1.88.0 (6b00bc388 2025-06-23)', 'separate actual compilers')
    downloaded = o.load((directory/'go-download.stdout').read_bytes())
    o.require(all(downloaded.get(k) == v for k,v in selected['go']['module'].items()) and downloaded.get('Replace') is None and go['download'] == selected['go']['module'] and (directory/'go-cache.stdout').read_bytes().strip() == b'all modules verified', 'public module h1 identity and cache verification')
    graph = x.public_graph((directory/'go-modules.stdout').read_bytes(), selected['go']['critical_modules'])
    o.require(o.canonical(go['modules']) == o.canonical(graph) and [r['Path'] for r in graph if r.get('Main') is True] == [selected['go']['module']['Path']] and next(r for r in graph if r.get('Main') is True).get('Dir') == str(groot), 'complete public test-main graph without replacements')
    listing = o.load((directory/'go-package.stdout').read_bytes())
    inputs = {k:listing.get(k,[]) for k in ['GoFiles','TestGoFiles','XTestGoFiles','IgnoredGoFiles','EmbedFiles']}
    expected_inputs = {p.rsplit('/',1)[1] for p in selected['go']['sources'] if p.startswith('pkg/agent/hpke/') and p.endswith('.go')}
    o.require(listing.get('ImportPath') == o.PACKAGE and go['package_inputs'] == inputs and set(p for names in inputs.values() for p in names) == expected_inputs and not any(listing.get(k) for k in ['CgoFiles','CFiles','CXXFiles','MFiles','HFiles','FFiles','SFiles','SysoFiles','SwigFiles','SwigCXXFiles']), 'actual complete selected Go package inputs')
    info = o.load((directory/'go-build-info.stdout').read_bytes()); x.go_identity(info)
    o.require(o.canonical(go['build_info']) == o.canonical(info), 'raw Go test BuildInfo; separate from module graph')
    o.require(rust['revision'] == selected['rust']['revision'] == (directory/'rust-revision.stdout').read_text().strip() and rust['tree'] == selected['rust']['tree'] == (directory/'rust-tree.stdout').read_text().strip() and rust['cargo_lock_sha256'] == selected['rust']['lock_sha256'] == o.sha((o.ROOT/selected['rust']['lock_path']).read_bytes()) and rbin == x.rust_binary((directory/'rust-build.stdout').read_bytes(), target), 'Rust source/lock/compiler executable selection')
    for language, proof, raw in [('go',go,go_raw),('rust',rust,rust_raw)]:
        o.require(proof['raw_test_sha256'] == o.sha(raw) and proof['selected_sources'] == selected[language]['sources'], 'raw execution and selected source linkage')
        for key in ['whole_source_sha256','test_binary_sha256']: o.require(type(proof[key]) is str and re.fullmatch('[0-9a-f]{64}', proof[key]) is not None, 'recorded source/executable digest; not binary attestation')
        o.require(type(proof['whole_source_files']) is int and proof['whole_source_files'] >= len(proof['selected_sources']), 'whole-source size')
    for language, proof in [('go',go),('rust',rust)]:
        whole = o.load((directory/(language+'-whole-sources.json')).read_bytes())
        o.require(type(whole) is dict and len(whole) == proof['whole_source_files'] and o.sha(o.canonical(whole)) == proof['whole_source_sha256'] and all(type(p) is str and not Path(p).is_absolute() and '..' not in Path(p).parts and type(h) is str and re.fullmatch('[0-9a-f]{64}',h) is not None for p,h in whole.items()) and all(whole.get(p) == h for p,h in selected[language]['sources'].items()), 'raw complete source manifest and selected input linkage')
        expected_whole = selected[language]['whole_sources']
        if language == 'rust':
            o.require(whole == {**expected_whole,'Cargo.lock':selected['rust']['lock_sha256']}, 'whole Rust source pinned to all Git blobs')
            tracked = [p for p in (directory/'rust-files.stdout').read_bytes().decode().split('\0') if p]
            o.require(len(tracked) == len(set(tracked)) and set(whole) == set(tracked)|{'Cargo.lock'} and 'Cargo.lock' not in tracked and whole['Cargo.lock'] == selected['rust']['lock_sha256'] == o.sha((directory/'rust-Cargo.lock').read_bytes()), 'whole Rust Git inputs plus separate acquired lock')
        else:
            o.require(whole == expected_whole, 'whole Go source pinned to all public ZIP entries'); x.module_identity(whole,selected['go']['module'])
            for name in ['go.mod','go.sum']: o.require(o.sha((directory/('go-module.'+name.split('.')[1])).read_bytes()) == whole[name], 'original public Go module declarations')
    print('Paired core evidence: Go15leaves/16named, Rust3named/15cases;2PARTIAL581NOT_RUN; operating trust NOT_BOUND')
    return report


def run(directory, rust_root):
    x.run_native(directory, rust_root)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in ['test_core_key_authority_observation','test_core_key_authority_execution'])
    previous = os.environ.get('CORE_KEY_AUTHORITY_EVIDENCE'); os.environ['CORE_KEY_AUTHORITY_EVIDENCE'] = str(directory)
    try: result = unittest.TextTestRunner(verbosity=2).run(suite)
    finally:
        if previous is None: os.environ.pop('CORE_KEY_AUTHORITY_EVIDENCE',None)
        else: os.environ['CORE_KEY_AUTHORITY_EVIDENCE'] = previous
    if not result.wasSuccessful() or result.skipped: raise SystemExit(1)
    verify(directory)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true'); parser.add_argument('--directory',type=Path,required=True); parser.add_argument('--rust-root',type=Path)
    args = parser.parse_args()
    if args.run:
        if args.rust_root is None: parser.error('--rust-root is required for native execution')
        run(args.directory.resolve(),args.rust_root)
    else: verify(args.directory.resolve())
