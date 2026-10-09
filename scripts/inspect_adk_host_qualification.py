"""Observe the pinned ADK separate-account host qualification on Linux arm64.

The qualification runs two signer processes, a receiver host, a caller host and
an operator under five Linux accounts for one compiled 2+3 calculator call. Its
Registry Source is a local JSON file and its calculator measurement accepts any
snapshot, so success is not Registry, measurement, deployment or conformance
evidence. Fresh observation needs a clean pinned ADK checkout, Linux arm64,
passwordless sudo and setpriv; it takes about eight minutes because of the
360-second replay quarantine.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

from inspect_intent_issuance import require
from inspect_public_mcp_host import strict_json
from inspect_root_capture_parity import ROOT, NORMATIVE_REVISION, check_source, sha

SCRIPT = 'core/guardhost/testdata/qualification/run-linux.sh'
BINARIES = {'adk-signer': './cmd/adk-signer', 'adk-approve': './cmd/adk-approve',
            'qualification': './core/guardhost/testdata/qualification'}
STATUS = 'SEPARATE_ACCOUNT_QUALIFICATION_OBSERVED'
BASE_SCOPE = {'effect': 'COMPILED_CALCULATOR_TWO_PLUS_THREE',
         'carriage': 'PRIVATE_NATIVE_MCP_LOOPBACK_TCP',
         'accounts': 'FIVE_LINUX_ACCOUNTS_ONE_KERNEL',
         'signing_custody': 'SEPARATE_ACCOUNT_SIGNER_PROCESSES',
         'kem_custody': 'RECEIVER_HOST_PROCESS',
         'policy_approval': 'EPHEMERAL_TEST_OPERATOR_KEY',
         'registry': 'SYNTHETIC_FILE_SOURCE',
         'measurement': 'ACCEPT_ALL_FIXTURE',
         'unapproved_refusal': 'CALLER_POLICY_BEFORE_ISSUANCE',
         'provider_bindings': 'IDENTITY_AND_MEASUREMENT_NOT_BOUND',
         'deployed_host_controls': 'NOT_RUN', 'deployed_registry': 'NOT_RUN',
         'full_conformance': 'NOT_ESTABLISHED'}
KEM_SCOPE = dict(BASE_SCOPE, kem_custody='SEPARATE_ACCOUNT_SIGNER_PROCESS')
MAX_LOG = 64 * 1024
HEX64 = '[0-9a-f]{64}'
# Every line the run must contain, in order. Values captured from one line are
# checked against later lines; anything else is refused.
PATTERNS = [
    ('host', r'### host Linux \S+ aarch64'),
    ('clock-start', r'### clock observation for the whole run'),
    ('keys', rf'### alice=(?P<alice>{HEX64}) bob=(?P<bob>{HEX64}) operator=(?P<operator>{HEX64}) kem=(?P<kem>{HEX64})'),
    ('approved', r'approved sequence 1'),
    ('signers', r'### signers'),
    ('signer-a', r'adk-signer ready (?P<signer_a>' + HEX64 + ')'),
    ('signer-b', r'adk-signer ready (?P<signer_b>' + HEX64 + ')'),
    ('receiver', r'### receiver'),
    ('receiver-ready', r'receiver ready 127\.0\.0\.1:7443 \S+'),
    ('isolation', r'### isolation checks'),
    ('iso-key', r'caller-cannot-read-signer-key'),
    ('iso-state', r'receiver-cannot-read-caller-state'),
    ('iso-socket', r'receiver-cannot-reach-signer-a'),
    ('iso-kem', r'receiver-cannot-read-kem-key'),
    ('caller', r'### caller \(waits for the 360 s replay quarantine\)'),
    ('caller-open', r'caller opened; waiting 6m5s for the replay quarantine \S+'),
    ('refused', r'unapproved call refused'),
    ('output', r'verified output \{"output":5,"success":true\}'),
    ('caller-exit', r'### caller-exit=0'),
    ('shutdown', r'### receiver state before shutdown'),
    ('running', r'receiver-was-running'),
    ('receiver-ready-again', r'receiver ready 127\.0\.0\.1:7443 \S+'),
    ('serve-returned', r'receiver serve returned \S+ context canceled signal context canceled'),
    ('receiver-stopped', r'receiver stopped'),
    ('clock', r'clock observed 8m0s backward-steps=0'),
]


# Each pinned ADK revision is a separate observation; earlier reports keep
# their own expected lines and scope.
PROFILES = {
    'ccc053c898ac83d741c7f667efe48c964f6b7532': {
        'go_revision': '7e8a0790d57ae709f8efee237db94bd4995d65ee',
        'go_module': 'v1.5.3-0.20261008173148-7e8a0790d57a',
        'report': ROOT / 'docs/evidence/adk-host-qualification.json',
        'patterns': [p for p in PATTERNS if p[0] != 'iso-kem'],
        'scope': BASE_SCOPE, 'isolation_checks': 3},
    '8111a00c964c9db3c7be4580fbe5308d4f8505b5': {
        'go_revision': 'c0bac1cb5c6ef7acdbdedcb89dc47c394b473705',
        'go_module': 'v1.5.3-0.20261009000821-c0bac1cb5c6e',
        'report': ROOT / 'docs/evidence/adk-host-qualification-kem-custody.json',
        'patterns': PATTERNS, 'scope': KEM_SCOPE, 'isolation_checks': 4},
}
LATEST = '8111a00c964c9db3c7be4580fbe5308d4f8505b5'
REPORT = PROFILES[LATEST]['report']
SCOPE = PROFILES[LATEST]['scope']


def check_log(raw, patterns=PATTERNS):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_LOG and raw.endswith(b'\n'), 'bounded complete log')
    text = raw.decode('utf-8')
    lines = text.split('\n')[:-1]
    require(len(lines) == len(patterns), 'exact qualification line count')
    values = {}
    for line, (name, pattern) in zip(lines, patterns):
        match = re.fullmatch(pattern, line)
        if match is None:
            raise ValueError('qualification line: ' + name)
        values.update(match.groupdict())
    require(values['signer_a'] == values['alice'] and values['signer_b'] == values['bob'] and
            len({values['alice'], values['bob'], values['operator'], values['kem']}) == 4,
            'signers serve the generated distinct identities')
    return values


def build(root, out, env):
    hashes = {}
    for name, package in BINARIES.items():
        subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-o', str(out / name), package],
                       cwd=root, env=env, check=True, timeout=600)
        hashes[name] = sha((out / name).read_bytes())
    return hashes


def module_version(root, env, expected):
    done = subprocess.run(['go', 'list', '-m', '-json', 'github.com/sage-x-project/sage'], cwd=root,
                          env=env, capture_output=True, check=True, timeout=60)
    module = strict_json(done.stdout)
    require('Replace' not in module and module.get('Version') == expected,
            'pinned public Go core module without replacement')
    return module['Version']


def inspect(adk_root, revision=LATEST):
    profile = PROFILES[revision]
    require(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64'), 'Linux arm64 host')
    root = check_source(adk_root, revision)
    require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'],
            cwd=root, text=True).strip(), 'untracked ADK build inputs')
    env = os.environ.copy()
    env.update(GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOWORK='off', CGO_ENABLED='0')
    compiler = subprocess.check_output(['go', 'version'], env=env, text=True).strip()
    require(compiler == 'go version go1.26.8 linux/arm64', 'pinned native Go compiler')
    module = module_version(root, env, profile['go_module'])
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        (temp / 'bin').mkdir()
        binaries = build(root, temp / 'bin', env)
        log = temp / 'qualification.log'
        run = subprocess.run(['sh', str(root / SCRIPT), str(temp / 'bin'), str(log)], cwd=root,
                             capture_output=True, timeout=900)
        raw = log.read_bytes()
        require(run.returncode == 0, 'qualification exit: ' + run.stdout.decode(errors='replace')[-2000:] +
                run.stderr.decode(errors='replace')[-2000:])
    check_source(root, revision)
    report = {'schema_version': 1, 'kind': 'adk-separate-account-host-qualification',
              'protocol_version': '0.10.0', 'normative_source_revision': NORMATIVE_REVISION,
              'adk_revision': revision, 'go_revision': profile['go_revision'], 'go_module': module,
              'compiler': compiler, 'kernel': platform.release(), 'script': SCRIPT,
              'script_sha256': sha((root / SCRIPT).read_bytes()), 'binaries_sha256': binaries,
              'log_hex': raw.hex(), 'log_sha256': sha(raw), 'status': STATUS, 'scope': dict(profile['scope'])}
    check_report(report)
    return report


def check_report(report):
    require(type(report) is dict and set(report) == {'schema_version', 'kind', 'protocol_version',
            'normative_source_revision', 'adk_revision', 'go_revision', 'go_module', 'compiler', 'kernel',
            'script', 'script_sha256', 'binaries_sha256', 'log_hex', 'log_sha256', 'status', 'scope'},
            'closed qualification report')
    profile = PROFILES.get(report['adk_revision'])
    require(profile is not None, 'reviewed ADK revision')
    require(report['schema_version'] == 1 and type(report['schema_version']) is int and
            report['kind'] == 'adk-separate-account-host-qualification' and
            report['protocol_version'] == '0.10.0' and report['normative_source_revision'] == NORMATIVE_REVISION and
            report['go_revision'] == profile['go_revision'] and
            report['go_module'] == profile['go_module'] and report['compiler'] == 'go version go1.26.8 linux/arm64' and
            report['script'] == SCRIPT and report['status'] == STATUS and report['scope'] == profile['scope'],
            'pinned revisions and bounded qualification scope')
    require(type(report['kernel']) is str and re.fullmatch(r'[0-9][0-9A-Za-z.+_-]{0,63}', report['kernel']),
            'kernel release')
    require(type(report['script_sha256']) is str and re.fullmatch(HEX64, report['script_sha256']) and
            type(report['binaries_sha256']) is dict and set(report['binaries_sha256']) == set(BINARIES) and
            all(type(v) is str and re.fullmatch(HEX64, v) for v in report['binaries_sha256'].values()),
            'script and binary hashes')
    require(type(report['log_hex']) is str and len(report['log_hex']) <= MAX_LOG * 2 and
            re.fullmatch('[0-9a-f]*', report['log_hex']) and len(report['log_hex']) % 2 == 0, 'bounded log hex')
    raw = bytes.fromhex(report['log_hex'])
    require(sha(raw) == report['log_sha256'], 'log hash')
    values = check_log(raw, profile['patterns'])
    require(raw.decode().split('\n')[0] == '### host Linux ' + report['kernel'] + ' aarch64',
            'kernel matches the observed host line')
    return {'status': report['status'], 'adk_revision': report['adk_revision'][:12], 'accounts': 5,
            'isolation_checks': profile['isolation_checks'],
            'operator': values['operator'][:16]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adk-root', type=Path)
    parser.add_argument('--revision', choices=sorted(PROFILES), default=LATEST)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output and not args.adk_root:
        parser.error('fresh execution required for output')
    if args.adk_root:
        report = inspect(args.adk_root, args.revision)
    else:
        report = strict_json((args.report or PROFILES[args.revision]['report']).read_bytes())
    summary = check_report(report)
    if args.output:
        with open(args.output, 'x') as out:
            out.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
