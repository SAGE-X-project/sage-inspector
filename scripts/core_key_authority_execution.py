"""Run reviewed fixed units from whole pinned public sources in remote CI."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import core_key_authority_observation as o
from ingress_refusal_observation import build_settings


def save(directory, name, raw):
    path = directory/name
    o.require(not path.is_symlink(), 'no evidence symlink')
    with path.open('xb') as stream: stream.write(raw)


def command(args, cwd, env, directory, name, trace, timeout=300):
    try: done = subprocess.run(args, cwd=cwd, env=env, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        save(directory,name+'.stdout',error.stdout or b''); save(directory,name+'.stderr',error.stderr or b'')
        raise ValueError('bounded command timeout; available raw output retained') from error
    save(directory, name+'.stdout', done.stdout); save(directory, name+'.stderr', done.stderr)
    row = {'name':name, 'args':args, 'cwd':str(cwd), 'returncode':done.returncode, 'stdout_sha256':o.sha(done.stdout), 'stderr_sha256':o.sha(done.stderr)}
    trace.append(row)
    o.require(done.returncode == 0 and len(done.stdout) <= 16777216 and len(done.stderr) <= 16777216, 'bounded successful command; raw output retained')
    return done.stdout


def file_tree(root, exclude_git=False):
    result = {}
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root).as_posix()
        if exclude_git and (rel == '.git' or rel.startswith('.git/')): continue
        o.require(not path.is_symlink(), 'no source symlink')
        if path.is_file(): result[rel] = o.sha(path.read_bytes())
    return result


def selected_sources(root, expected):
    actual = {p:o.sha((root/p).read_bytes()) for p in expected}
    o.require(actual == expected, 'selected public source bytes changed')
    return actual


def full_sources(root, expected, exclude_git=False):
    actual = file_tree(root, exclude_git)
    o.require(actual == expected, 'complete source bytes differ from pinned public ZIP/Git blobs')
    return actual


def hash1(files):
    o.require(type(files) is dict and all(type(name) is str and name.isascii() and '\n' not in name and '\r' not in name and type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest) is not None for name,digest in files.items()), 'Go dirhash file identities')
    text = ''.join(digest+'  '+name+'\n' for name,digest in sorted(files.items()))
    return 'h1:'+o.base64.b64encode(o.hashlib.sha256(text.encode()).digest()).decode()


def module_identity(files, module):
    prefix = module['Path']+'@'+module['Version']+'/'
    o.require(hash1({prefix+p:h for p,h in files.items()}) == module['Sum'] and hash1({'go.mod':files['go.mod']}) == module['GoModSum'], 'independent whole main-module and go.mod h1 identities')


def json_stream(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            o.require(key not in result, 'duplicate stream member')
            result[key] = value
        return result
    decoder = json.JSONDecoder(object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite stream number')))
    text = raw.decode(); result = []
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip()); result.append(value); text = text.lstrip()[end:]
    return result


def modules(raw):
    rows = json_stream(raw); seen = set()
    for row in rows:
        o.require(type(row) is dict and type(row.get('Path')) is str and row['Path'] not in seen and row.get('Replace') is None, 'unique public module graph without replacements')
        seen.add(row['Path'])
    return rows


def public_graph(raw, expected):
    graph = modules(raw); indexed = {r['Path']:r for r in graph}
    o.require(all(p in indexed and all(indexed[p].get(k) == v for k,v in values.items()) for p,values in expected.items()), 'pinned critical public dependency metadata')
    return graph


def go_identity(info):
    o.require(type(info) is dict and info.get('GoVersion') == 'go1.26.8' and info.get('Path') == o.PACKAGE+'.test' and build_settings(info).get('-race') == 'true', 'actual Go1.26.8 race test compiler; not dependency attestation')


def go_execute(directory, selected, env, trace):
    config = selected['go']; expected = config['module']; query = expected['Path']+'@'+expected['Version']
    compiler = command(['go','version'], o.ROOT, env, directory, 'go-compiler', trace)
    o.require(compiler.strip() == b'go version go1.26.8 linux/amd64', 'required remote Go compiler')
    downloaded = o.load(command(['go','mod','download','-json',query], directory, env, directory, 'go-download', trace))
    o.require(all(downloaded.get(k) == v for k,v in expected.items()) and downloaded.get('Replace') is None and type(downloaded.get('Dir')) is str, 'exact public download h1 identity')
    source = Path(downloaded['Dir']); original = full_sources(source, config['whole_sources']); module_identity(original, expected)
    save(directory,'go-whole-sources.json',(json.dumps(original,sort_keys=True)+'\n').encode())
    for name in ['go.mod','go.sum']: save(directory,'go-module.'+name.split('.')[1],(source/name).read_bytes())
    with tempfile.TemporaryDirectory(prefix='sage-core-key-authority-go-') as tmp:
        root = Path(tmp)/'module'; shutil.copytree(source, root)
        for folder in [root, *(p for p in root.rglob('*') if p.is_dir())]: folder.chmod(folder.stat().st_mode | 0o700)
        o.require(file_tree(root) == original, 'whole public module copy identity')
        before = selected_sources(root, config['sources'])
        cache = command(['go','mod','verify'], root, env, directory, 'go-cache', trace)
        o.require(cache.strip() == b'all modules verified', 'public module cache verification')
        graph = public_graph(command(['go','list','-mod=readonly','-m','-json','all'], root, env, directory, 'go-modules', trace), config['critical_modules'])
        mains = [r for r in graph if r.get('Main') is True]
        o.require(len(mains) == 1 and mains[0]['Path'] == expected['Path'] and mains[0].get('Dir') == str(root), 'public module is complete test main')
        listing = o.load(command(['go','list','-mod=readonly','-json','.'], root/'pkg/agent/hpke', env, directory, 'go-package', trace))
        inputs = {k:listing.get(k,[]) for k in ['GoFiles','TestGoFiles','XTestGoFiles','IgnoredGoFiles','EmbedFiles']}
        all_inputs = set(p for names in inputs.values() for p in names)
        expected_inputs = {p.rsplit('/',1)[1] for p in before if p.startswith('pkg/agent/hpke/') and p.endswith('.go')}
        o.require(listing.get('ImportPath') == o.PACKAGE and all_inputs == expected_inputs and not any(listing.get(k) for k in ['CgoFiles','CFiles','CXXFiles','MFiles','HFiles','FFiles','SFiles','SysoFiles','SwigFiles','SwigCXXFiles']), 'actual Go package input inventory')
        binary = Path(tmp)/'authority.test'
        command(['go','test','-mod=readonly','-race','-c','-o',str(binary),'./pkg/agent/hpke'], root, env, directory, 'go-build', trace)
        info_raw = command(['go','version','-m','-json',str(binary)], root, env, directory, 'go-build-info', trace)
        info = o.load(info_raw); go_identity(info)
        digest = o.sha(binary.read_bytes())
        raw = command(['go','tool','test2json','-t','-p',o.PACKAGE,str(binary),'-test.v=test2json','-test.run=^'+o.PARENT+'$','-test.count=1','-test.timeout=30s'], root, env, directory, 'go-tests', trace, 60)
        o.require((directory/'go-tests.stderr').read_bytes() == b'', 'empty actual test stderr')
        rows = o.go_witnesses(raw)
        o.require(o.sha(binary.read_bytes()) == digest and file_tree(root) == original and before == selected_sources(root, config['sources']) and file_tree(source) == original, 'whole Go sources and executable unchanged')
    return rows, {'download':{k:downloaded[k] for k in expected}, 'selected_sources':before, 'whole_source_sha256':o.sha(o.canonical(original)), 'whole_source_files':len(original), 'package_inputs':inputs, 'modules':graph, 'build_info':info, 'test_binary_sha256':digest, 'execution_directory':str(root), 'raw_test_sha256':o.sha(raw)}


def rust_binary(raw, target):
    candidates = []
    for line in raw.splitlines():
        row = o.load(line)
        if row.get('reason') == 'compiler-artifact' and row.get('executable') is not None:
            o.require(row.get('target',{}).get('name') == 'sage_crypto_core' and row.get('profile',{}).get('test') is True, 'Rust selected library-test executable')
            path = Path(row['executable']); o.require(path.is_absolute() and '..' not in path.parts and path.is_relative_to(target) and not path.is_symlink(), 'Rust executable within owned target directory'); candidates.append(path)
    o.require(len(candidates) == 1, 'one actual Rust test executable')
    return candidates[0]


def rust_execute(directory, selected, rust_root, env, trace):
    config = selected['rust']; root = rust_root.resolve()
    compiler = command(['rustc','--version'], root, env, directory, 'rust-compiler', trace)
    o.require(compiler.strip() == b'rustc 1.88.0 (6b00bc388 2025-06-23)', 'pinned Rust compiler')
    revision = command(['git','rev-parse','HEAD'], root, env, directory, 'rust-revision', trace).decode().strip()
    tree = command(['git','rev-parse','HEAD^{tree}'], root, env, directory, 'rust-tree', trace).decode().strip()
    tracked = command(['git','ls-files','-z'], root, env, directory, 'rust-files', trace).decode().split('\0'); tracked = [p for p in tracked if p]
    o.require(revision == config['revision'] and tree == config['tree'] and 'Cargo.lock' not in tracked, 'exact Rust revision/tree; acquired lock is not a Git blob')
    original = file_tree(root, True); lock = o.ROOT/config['lock_path']; lock_raw = lock.read_bytes()
    o.require(o.sha(lock_raw) == config['lock_sha256'] and set(tracked) == set(config['whole_sources']) and len(tracked) == len(set(tracked)) and original == {**config['whole_sources'], 'Cargo.lock':config['lock_sha256']}, 'whole exact Rust source tree with only owned lock input')
    before = selected_sources(root, config['sources'])
    save(directory,'rust-whole-sources.json',(json.dumps(original,sort_keys=True)+'\n').encode()); save(directory,'rust-Cargo.lock',lock_raw)
    with tempfile.TemporaryDirectory(prefix='sage-core-key-authority-rust-') as tmp:
        target = Path(tmp)/'target'
        build_raw = command(['cargo','test','--locked','--offline','--lib','--no-run','--message-format=json','--target-dir',str(target)], root, env, directory, 'rust-build', trace)
        binary = rust_binary(build_raw, target); digest = o.sha(binary.read_bytes())
        raw = command([str(binary),'handshake_key_authority_','--nocapture','--test-threads=1'], root, env, directory, 'rust-tests', trace, 60)
        o.require((directory/'rust-tests.stderr').read_bytes() == b'', 'empty actual Rust test stderr')
        rows = o.rust_witnesses(raw)
        o.require(o.sha(binary.read_bytes()) == digest and original == file_tree(root, True) and before == selected_sources(root, config['sources']) and (root/'Cargo.lock').read_bytes() == lock_raw, 'whole Rust source, lock and executable unchanged')
    return rows, {'revision':revision,'tree':tree,'selected_sources':before,'whole_source_sha256':o.sha(o.canonical(original)),'whole_source_files':len(original),'cargo_lock_sha256':o.sha(lock_raw),'test_binary_sha256':digest,'execution_directory':str(root),'target_directory':str(target),'test_executable':str(binary),'raw_test_sha256':o.sha(raw),'compiler':compiler.decode().strip()}


def environment():
    env = os.environ.copy()
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='-mod=readonly', GOPROXY='off', CGO_ENABLED='1', RUSTUP_TOOLCHAIN='1.88.0', CARGO_TERM_COLOR='never', CARGO_INCREMENTAL='0')
    for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_RUSTC_WRAPPER']: env.pop(key, None)
    return env


def run_native(directory, rust_root):
    selected = o.subject(); o.fixtures(); before = o.observer_sources(); env = environment(); trace = []
    o.require(directory.is_dir() and rust_root.is_dir(), 'existing owned evidence and checkout directories')
    revision = subprocess.check_output(['git','rev-parse','HEAD'], cwd=o.ROOT, text=True).strip()
    go, go_proof = go_execute(directory, selected, env, trace)
    rust, rust_proof = rust_execute(directory, selected, rust_root, env, trace)
    o.require(o.observer_sources() == before, 'observer sources unchanged during execution')
    report = o.assess(go, rust)
    o.require(report['status_counts'] == {'PARTIAL':2,'NOT_RUN':581}, 'both complete language groups required')
    report.update(evidence_kind='inspector-launched-paired-core-native-units', observer={'repository':'SAGE-X-project/sage-inspector','revision':revision,'source_sha256':before}, execution={'go':go_proof,'rust':rust_proof,'commands':trace,'capture_directory':str(directory),'environment':{k:env[k] for k in ['GOTOOLCHAIN','GOWORK','GOFLAGS','GOPROXY','CGO_ENABLED','RUSTUP_TOOLCHAIN','CARGO_TERM_COLOR','CARGO_INCREMENTAL']}})
    save(directory, 'core-key-authority-native.json', (json.dumps(report,indent=2)+'\n').encode())
    return report
