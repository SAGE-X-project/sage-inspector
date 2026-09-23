"""Validate all authenticated non-HTTP MCP setup proposal cases."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from check_mcp_catalog import BASE as CATALOG_BASE, catalog
from run_mcp_core_runtime import (PINS, SETUP_CONTRACT, SETUP_CONTRACT_CASES,
                                  SETUP_VALUE, observed, successful)

ROOT = Path(__file__).resolve().parents[1]
CATALOG_MANIFEST = CATALOG_BASE / 'manifest.json'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(value, fields, message):
    require(type(value) is dict and set(value) == set(fields), message)


def safe_read(base, name, limit=32 * 1024 * 1024):
    require(type(name) is str and name and '/' not in name and '\\' not in name, 'invalid evidence file')
    path = base / name
    require(path.resolve().is_relative_to(base.resolve()) and not path.is_symlink(), 'evidence path')
    raw = path.read_bytes()
    require(len(raw) <= limit, 'evidence file too large')
    return raw


def catalog_rows():
    manifest_raw = CATALOG_MANIFEST.read_bytes()
    manifest = json.loads(manifest_raw)
    plans = {}
    for name, expected in manifest['files'].items():
        raw = (CATALOG_BASE / name).read_bytes()
        require(sha(raw) == expected, 'catalog source drift: ' + name)
        if name in ('cases.json', 'addendum-cases.json', 'resolutions.json'):
            plans[name] = json.loads(raw)
    return manifest_raw, catalog(plans)


def validate_contract(value):
    exact(value, ('schema_version','protocol_version','kind','catalog_manifest_sha256',
                  'historical_catalog','case_counts','external_review','adoption','conformance',
                  'cores','interop','policy_cases','assessments'), 'contract fields')
    require(value['schema_version'] == 1 and value['protocol_version'] == '0.10.0', 'contract version')
    require(value['kind'] == 'mcp-setup-case-contract', 'contract kind')
    require(value['historical_catalog'] == {'NOT_RUN':71}, 'historical catalog')
    require(value['case_counts'] == {'PASS':58,'PARTIAL':0,'NOT_RUN':0}, 'case counts')
    require(value['external_review'] == 'NOT_PERFORMED', 'external review promotion')
    require(value['adoption'] == 'PROPOSAL_NOT_ADOPTED', 'adoption promotion')
    require(value['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')
    require(set(value['cores']) == set(PINS), 'core inventory')
    for language, pin in PINS.items():
        core = value['cores'][language]
        require(core['revision'] == pin, 'core revision: ' + language)
        require(type(core['files']) is dict and core['files'], 'core files: ' + language)
        require(all(type(n) is str and '/' in n and len(h) == 64 for n,h in core['files'].items()), 'core hashes')
    require(set(value['policy_cases']) == {'mset-08-proposal-scope','mset-08-http-not-defined','mset-08-historical-evidence'}, 'policy cases')
    require(set(value['interop']['cases']) == {'madd-cross-language-setup','madd-restart-consumption'}, 'interop cases')
    require(value['interop']['required_pairs'] == ['go-to-go','go-to-rust','rust-to-go','rust-to-rust'], 'interop pairs')
    require(value['interop']['restart_modes'] == ['client','server'], 'restart modes')
    rows = {row['id']: row for row in value['assessments']}
    require(len(rows) == len(value['assessments']) == 58, 'assessment inventory')
    for ident, row in rows.items():
        exact(row, ('id','source','status','evidence_kind','claim','requirements'), 'assessment fields')
        require(row['status'] == 'PASS' and row['source'] in ('original','addendum'), 'assessment state')
        require(type(row['claim']) is str and 30 <= len(row['claim']) <= 400, 'assessment claim')
        kind = row['evidence_kind']
        require(kind in ('core','interop','policy'), 'evidence kind')
        if kind == 'core':
            require(len(row['requirements']) == 2, 'core requirements')
            require({q['language'] for q in row['requirements']} == set(PINS), 'language coverage')
            for requirement in row['requirements']:
                exact(requirement, ('language','test'), 'requirement fields')
                language, test = requirement['language'], requirement['test']
                require(ident in SETUP_CONTRACT_CASES[language].get(test, []), 'test mapping')
        else:
            require(row['requirements'] == [], 'non-core requirements')
    return value


def validate_runtime(base):
    report = json.loads(safe_read(base, 'report.json'))
    require(report.get('kind') == 'mcp-core-runtime-tests' and report.get('status') == 'PASS', 'runtime status')
    require(report.get('setup_case_contract_sha256') == sha(SETUP_CONTRACT.read_bytes()), 'runtime contract')
    require(safe_read(base, 'setup-case-contract.json') == SETUP_CONTRACT.read_bytes(), 'preserved setup contract')
    subjects = report.get('subjects')
    require(successful(subjects), 'incomplete core runtime')
    for language, pin in PINS.items():
        subject = subjects[language]
        require(subject.get('revision') == pin, 'runtime revision: ' + language)
        require(subject.get('setup_case_files') == SETUP_VALUE['cores'][language]['files'], 'runtime source hashes')
    return report


def validate_interop(base):
    report = json.loads(safe_read(base, 'report.json'))
    require(report.get('kind') == 'mcp-native-protected-interop' and report.get('status') == 'PASS', 'interop status')
    require(report.get('protected_dispatch') == 'PASS', 'protected interop')
    require(report.get('completed_recovery') == 'SELECTED_ASSERTIONS_PASS', 'restart recovery')
    require(set(report.get('subjects', {})) == set(PINS), 'interop subjects')
    for language, pin in PINS.items():
        require(report['subjects'][language].get('revision') == pin, 'interop revision: ' + language)
    pairs = report.get('pairs', [])
    require([row.get('pair') for row in pairs] == SETUP_VALUE['interop']['required_pairs'], 'interop pair inventory')
    for row in pairs:
        exchanges = row.get('protected_exchanges')
        require(row.get('status') == 'PASS' and exchanges in (1, 2), 'interop pair evidence')
        require(row.get('frames') == 8 + 2 * exchanges, 'protected frame count')
        require(row.get('setup_signature_checks') == 9, 'setup signature count')
        require(row.get('protected_signature_checks') == 2 + 2 * exchanges, 'protected signature count')
        require(row.get('independent_signatures') ==
                row['setup_signature_checks'] + row['protected_signature_checks'], 'signature total')
        require(row.get('effects') == 1 and row.get('terminal_records') == 1, 'protected effect evidence')
        require(row.get('execution_transitions') == ['RESERVED','EXECUTING','COMPLETED'], 'journal transitions')
        require(row.get('decrypted_records') == 6 + 2 * exchanges and
                row.get('decrypted_setup_exchanges') == 3 and
                row.get('decrypted_protected_exchanges') == exchanges and
                row.get('decrypted_result_signatures') == exchanges and
                row.get('peer_secret_match') is True, 'independent record evidence')
        require(row.get('exit_codes') == [0, 0], 'interop process status')
    restart = report.get('restart', [])
    require(len(restart) == 8 and all(row.get('status') == 'PASS' for row in restart), 'restart inventory')
    expected_restart = {(mode, pair) for mode in SETUP_VALUE['interop']['restart_modes']
                        for pair in SETUP_VALUE['interop']['required_pairs']}
    require({(row.get('restart_mode'), row.get('pair')) for row in restart} == expected_restart,
            'restart matrix')
    return report


def validate_policy(ident, consolidated, historical):
    require(type(consolidated) is str, 'consolidated proposal')
    if ident == 'mset-08-proposal-scope':
        require('Status: **PROPOSAL_NOT_ADOPTED**' in consolidated, 'proposal scope status')
        return 'proposal remains explicitly unadopted'
    if ident == 'mset-08-http-not-defined':
        require('## MSET-08 — Adoption and excluded HTTP behavior' in consolidated, 'MSET-08 section')
        require('This proposal selects non-HTTP behavior only.' in consolidated, 'non-HTTP scope')
        require('It does not define chapter 08 HTTP' in consolidated, 'HTTP exclusion')
        return 'chapter 08 HTTP behavior remains explicitly excluded'
    if ident == 'mset-08-historical-evidence':
        require(historical == {'NOT_RUN':71}, 'historical evidence state')
        return 'historical catalog remains 71 NOT_RUN'
    raise ValueError('unknown policy case: ' + ident)


def inspect(runtime, interop):
    contract_raw = SETUP_CONTRACT.read_bytes()
    contract = validate_contract(json.loads(contract_raw))
    manifest_raw, catalog_cases = catalog_rows()
    require(sha(manifest_raw) == contract['catalog_manifest_sha256'], 'catalog manifest binding')
    consolidated = (CATALOG_BASE / 'consolidated.md').read_text()
    candidates = {row['id']: row for row in catalog_cases
                  if row['source'] in ('cases.json','addendum-cases.json')}
    require(len(candidates) == 58, 'MSET catalog inventory')
    require(set(candidates) == {row['id'] for row in contract['assessments']}, 'MSET case identity')
    runtime_report = validate_runtime(runtime)
    interop_report = validate_interop(interop)
    output=[]
    for assessment in contract['assessments']:
        ident=assessment['id']; kind=assessment['evidence_kind']; evidence=[]
        if kind == 'core':
            for requirement in assessment['requirements']:
                language,test=requirement['language'],requirement['test']
                matches=[row for row in runtime_report['subjects'][language]['cases'] if row.get('test') == test]
                require(len(matches) == 1, 'missing or duplicate core evidence: ' + ident)
                row=matches[0]
                require(row.get('status') == 'PASS' and row.get('execution_status') == 'PASS', 'failed core evidence: ' + ident)
                require(ident in row.get('setup_cases', []), 'runtime setup mapping: ' + ident)
                log=safe_read(runtime,row['log'])
                require(sha(log) == row['log_sha256'] and observed(language,test,log.decode(),row['exit_code']), 'core log: ' + ident)
                evidence.append({'kind':'core-test','language':language,'revision':PINS[language],
                                 'test':test,'log':row['log'],'log_sha256':row['log_sha256']})
        elif kind == 'interop':
            evidence=[{'kind':'native-protected-interop','report_sha256':sha(safe_read(interop,'report.json')),
                       'pairs':len(interop_report['pairs']),'restart_runs':len(interop_report['restart'])}]
        else:
            require(contract['adoption'] == 'PROPOSAL_NOT_ADOPTED' and contract['conformance'] == 'NOT_ESTABLISHED', 'policy state')
            observation = validate_policy(ident, consolidated, contract['historical_catalog'])
            evidence=[{'kind':'policy-assertion','catalog_manifest_sha256':sha(manifest_raw),
                       'adoption':contract['adoption'],'conformance':contract['conformance'],
                       'observation':observation}]
        output.append({'id':ident,'source':assessment['source'],'status':'PASS','claim':assessment['claim'],'evidence':evidence})
    require(len(output)==58 and all(row['status']=='PASS' for row in output), 'MSET results')
    return {'schema_version':1,'kind':'mcp-setup-case-evidence','status':'EVIDENCE_CHECKED',
            'historical_catalog':{'NOT_RUN':71},'case_counts':{'PASS':58,'PARTIAL':0,'NOT_RUN':0},
            'external_review':'NOT_PERFORMED','adoption':'PROPOSAL_NOT_ADOPTED','conformance':'NOT_ESTABLISHED',
            'contract_sha256':sha(contract_raw),'runtime_report_sha256':sha(safe_read(runtime,'report.json')),
            'interop_report_sha256':sha(safe_read(interop,'report.json')),'cases':output,
            'limitation':'All MSET proposal cases have selected implementation, interoperability or policy evidence; the proposal remains unadopted and full protocol conformance is not established.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--interop',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        runtime=args.runtime.resolve(strict=True); interop=args.interop.resolve(strict=True); output=args.output.resolve()
        require(runtime.is_dir() and interop.is_dir(), 'evidence directories')
        require(not output.exists() and not output.is_relative_to(ROOT), 'new external output required')
        report=inspect(runtime,interop); output.mkdir(parents=True)
        (output/'contract.json').write_bytes(SETUP_CONTRACT.read_bytes())
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    except (ValueError,KeyError,TypeError,OSError,UnicodeError,json.JSONDecodeError) as error:
        print('MCP setup case evidence FAIL: '+str(error),file=sys.stderr); return 1
    print('MCP setup case evidence checked: 58 PASS, 0 PARTIAL, 0 NOT_RUN; conformance NOT_ESTABLISHED.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
