"""Validate the adopted MCP parent, child, interoperability and restart evidence."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from check_mcp_case_evidence import catalog_rows, load, require, safe_read, sha
from run_mcp_core_runtime import (NORMATIVE_CONTRACT_CASES, NORMATIVE_CONTRACTS,
                                  NORMATIVE_VALUES,
                                  PINS, observed, successful)

ROOT = Path(__file__).resolve().parents[1]
LANGUAGES = ('go', 'rust')
PAIRS = {left + '-to-' + right for left in LANGUAGES for right in LANGUAGES}
BASELINE = ROOT / 'verification/0.10.0/normative-baseline-lock.json'


def spec_revision():
    baseline = load(BASELINE.read_bytes())
    revision = baseline['spec']['revision']
    require(all(baseline['cores'][language]['revision'] == PINS[language]
                and NORMATIVE_VALUES[language]['spec_revision'] == revision
                for language in LANGUAGES), 'normative baseline mismatch')
    return revision


def runtime_evidence(base):
    raw = safe_read(base, 'report.json')
    report = load(raw)
    require(report.get('kind') == 'mcp-core-runtime-tests' and report.get('status') == 'PASS',
            'core runtime status')
    require(report.get('conformance') == 'NOT_ESTABLISHED'
            and report.get('catalog') == {'NOT_RUN': 71}
            and report.get('mandatory_children') == 'PINNED_CORE_ASSERTIONS',
            'core runtime claim promotion')
    require(successful(report.get('subjects')), 'incomplete core runtime')
    summary = {}
    for language in LANGUAGES:
        contract = NORMATIVE_CONTRACTS[language]
        require(report.get('normative_contract_sha256', {}).get(language) == sha(contract.read_bytes()),
                'normative contract hash: ' + language)
        require(safe_read(base, language + '-normative-review-contract.json') == contract.read_bytes(),
                'normative contract bytes: ' + language)
        children = set()
        for row in report['subjects'][language]['cases']:
            mapped = row.get('mandatory_children')
            if not mapped:
                continue
            require(mapped == NORMATIVE_CONTRACT_CASES[language].get(row.get('test')),
                    'mandatory child mapping: ' + language)
            require(row.get('status') == row.get('execution_status') == 'PASS'
                    and row.get('exit_code') == 0,
                    'mandatory child execution: ' + language)
            log = safe_read(base, row.get('log', ''))
            require(sha(log) == row.get('log_sha256')
                    and observed(language, row['test'], log.decode(), row['exit_code']),
                    'mandatory child log: ' + language)
            children.update(mapped)
        require(len(children) == 26, 'mandatory child count: ' + language)
        summary[language] = {'revision': PINS[language], 'status': 'PASS',
                             'mandatory_children': 26}
    return raw, summary


def parent_evidence(base, runtime_raw):
    raw = safe_read(base, 'report.json')
    report = load(raw)
    require(report.get('kind') == 'mcp-proposal-case-runtime-evidence'
            and report.get('status') == 'EVIDENCE_CHECKED', 'parent case status')
    require(report.get('historical_catalog') == {'NOT_RUN': 71}
            and report.get('runtime_case_counts') == {'PASS': 71, 'PARTIAL': 0, 'NOT_RUN': 0}
            and report.get('conformance') == 'NOT_ESTABLISHED', 'parent case claim promotion')
    require(report.get('runtime_report_sha256') == sha(runtime_raw), 'parent/runtime binding')
    cases = report.get('cases')
    require(type(cases) is list and len(cases) == 71
            and {row.get('id') for row in cases} == {row['id'] for row in catalog_rows()}
            and all(row.get('status') == 'PASS' for row in cases), 'parent case inventory')
    return raw


def evidence_file(base, relative, expected):
    path = base / relative
    require(path.resolve().is_relative_to(base.resolve()) and not path.is_symlink(),
            'interop evidence path')
    raw = path.read_bytes()
    require(len(raw) <= 16 * 1024 * 1024, 'interop evidence file too large')
    require(sha(raw) == expected, 'interop evidence hash')
    return raw


def validate_pair(base, row, restart=False):
    require(row.get('pair') in PAIRS and row.get('status') == 'PASS', 'interop pair status')
    require(row.get('effects') == (0 if restart else 1), 'protected effect count')
    if restart:
        mode = row.get('restart_mode')
        require(mode in ('server', 'client') and row.get('recovery') == mode,
                'restart mode')
        require(row.get('server_journal_unchanged') is True, 'server journal mutation')
        if mode == 'client':
            require(row.get('client_journal_unchanged') is True, 'client journal mutation')
            require(row.get('protected_exchanges') == 0, 'consumed client exchange')
        else:
            require(row.get('protected_exchanges') == 1, 'server recovery exchange')
        relative = Path('reopen-' + mode) / row['pair'] / 'frames.json'
    else:
        require(row.get('execution_transitions') == ['RESERVED', 'EXECUTING', 'COMPLETED'],
                'execution transition evidence')
        exchanges = row.get('protected_exchanges')
        require(exchanges in (1, 2) and row.get('terminal_records') == 1,
                'protected exchange evidence')
        require(row.get('setup_signature_checks') == 9
                and row.get('protected_signature_checks') == 2 + 2 * exchanges
                and row.get('independent_signatures') == 11 + 2 * exchanges,
                'signature evidence')
        relative = Path(row['pair']) / 'frames.json'
    files = row.get('files')
    require(type(files) is dict and 'frames.json' in files, 'raw frame inventory')
    frames = load(evidence_file(base, relative, files['frames.json']))
    require(set(frames) == {'requests', 'responses'}
            and type(frames['requests']) is list and type(frames['responses']) is list
            and len(frames['requests']) == len(frames['responses'])
            and len(frames['requests']) == (4 + (row['protected_exchanges'] if not restart
                                                  or row['restart_mode'] == 'server' else 0)),
            'raw frame evidence')
    require(row.get('frames') == len(frames['requests']) + len(frames['responses']),
            'frame count mismatch')
    for name in ('server.journal', 'client.journal'):
        if name in files:
            evidence_file(base, relative.parent / name, files[name])
    if restart:
        before = evidence_file(base, relative.parent / 'server.journal.before',
                               files['server.journal.before'])
        after = evidence_file(base, relative.parent / 'server.journal', files['server.journal'])
        require(before == after, 'server journal bytes changed')
        if row['restart_mode'] == 'client':
            before = evidence_file(base, relative.parent / 'client.journal.before',
                                   files['client.journal.before'])
            after = evidence_file(base, relative.parent / 'client.journal', files['client.journal'])
            require(before == after, 'client journal bytes changed')


def interop_evidence(base):
    raw = safe_read(base, 'report.json')
    report = load(raw)
    require(report.get('kind') == 'mcp-native-protected-interop'
            and report.get('status') == 'PASS'
            and report.get('protected_dispatch') == 'PASS'
            and report.get('completed_recovery') == 'SELECTED_ASSERTIONS_PASS'
            and report.get('conformance') == 'NOT_ESTABLISHED', 'protected interop status')
    require(set(report.get('subjects', {})) == set(LANGUAGES), 'interop core inventory')
    for language in LANGUAGES:
        require(report['subjects'][language].get('revision') == PINS[language]
                and report['subjects'][language].get('build', {}).get('status') == 'PASS',
                'interop core revision or build: ' + language)
    pairs = report.get('pairs')
    require(type(pairs) is list and len(pairs) == 4
            and {row.get('pair') for row in pairs} == PAIRS, 'protected pair inventory')
    for row in pairs:
        validate_pair(base, row)
    restart = report.get('restart')
    require(type(restart) is list and len(restart) == 8
            and {(row.get('restart_mode'), row.get('pair')) for row in restart}
            == {(mode, pair) for mode in ('server', 'client') for pair in PAIRS},
            'restart inventory')
    for row in restart:
        validate_pair(base, row, True)
    return raw


def inspect(runtime, parents, interop):
    revision = spec_revision()
    runtime_raw, children = runtime_evidence(runtime)
    parent_raw = parent_evidence(parents, runtime_raw)
    interop_raw = interop_evidence(interop)
    return {
        'schema_version': 1,
        'protocol_version': '0.10.0',
        'kind': 'mcp-binding-evidence',
        'status': 'EVIDENCE_CHECKED',
        'spec_revision': revision,
        'normative_baseline_sha256': sha(BASELINE.read_bytes()),
        'historical_catalog': {'NOT_RUN': 71},
        'current_parent_cases': {'PASS': 71, 'PARTIAL': 0, 'NOT_RUN': 0},
        'mandatory_children': children,
        'protected_pairs': {'PASS': 4},
        'restart_observations': {'PASS': 8},
        'runtime_report_sha256': sha(runtime_raw),
        'parent_report_sha256': sha(parent_raw),
        'interop_report_sha256': sha(interop_raw),
        'conformance': 'NOT_ESTABLISHED',
        'limitation': 'Selected pinned implementation and interoperability evidence is complete; full protocol conformance and external review remain unestablished.'
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('runtime', 'parents', 'interop', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        require(not output.exists() and not output.is_relative_to(ROOT),
                'use a new external output directory')
        report = inspect(args.runtime.resolve(strict=True), args.parents.resolve(strict=True),
                         args.interop.resolve(strict=True))
        output.mkdir(parents=True, exist_ok=False)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, UnicodeError,
            subprocess.SubprocessError) as error:
        print('MCP binding evidence FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('MCP binding evidence checked: 71 parent cases, 26 children per core, '
          '4 protected pairs and 8 restart observations; conformance NOT_ESTABLISHED.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
