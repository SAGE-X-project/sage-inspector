"""Validate the bounded internal review of MCP proposal adoption readiness."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'verification/0.10.0/mcp-consolidated-proposal'
CONTRACT = ROOT / 'verification/0.10.0/mcp-adoption-review-contract.json'
SETUP_CONTRACT = ROOT / 'verification/0.10.0/mcp-setup-case-contract.json'
AGGREGATE_CONTRACT = ROOT / 'verification/0.10.0/mcp-case-evidence-contract.json'
EXPECTED_IDS = {f'ADOPT-{number:02d}' for number in range(1, 7)}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(value, fields, message):
    require(type(value) is dict and set(value) == set(fields), message)


def load(raw):
    def reject(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate JSON member')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=reject,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite number')))


def normalized(value):
    return ' '.join(value.split())


def validate_contract(value, proposal):
    exact(value, ('schema_version','protocol_version','kind','method','source','review_scope',
                  'internal_review','external_review','adoption','conformance',
                  'adoption_readiness','finding_counts','findings'), 'contract fields')
    require(value['schema_version'] == 1 and value['protocol_version'] == '0.10.0', 'contract version')
    require(value['kind'] == 'mcp-adoption-readiness-review' and
            value['method'] == 'INTERNAL_BOUNDED_REREVIEW', 'review identity')
    require(value['internal_review'] == 'COMPLETE_WITH_FINDINGS', 'internal review status')
    require(value['external_review'] == 'NOT_PERFORMED', 'external review promotion')
    require(value['adoption'] == 'PROPOSAL_NOT_ADOPTED', 'adoption promotion')
    require(value['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')
    require(value['adoption_readiness'] == 'BLOCKED', 'readiness promotion')
    require(value['finding_counts'] == {'HIGH':4,'MEDIUM':2,'OPEN':5,'PENDING_EXTERNAL':1},
            'finding counts')
    exact(value['source'], ('repository','revision','manifest_sha256','consolidated_sha256',
                            'tool_sha256','setup_evidence_contract_sha256',
                            'aggregate_evidence_contract_sha256'), 'source fields')
    source = value['source']
    require(source['repository'] == 'SAGE-X-project/sage-spec' and len(source['revision']) == 40,
            'source identity')
    require(source['manifest_sha256'] == sha((BASE/'manifest.json').read_bytes()), 'manifest binding')
    require(source['consolidated_sha256'] == sha((BASE/'consolidated.md').read_bytes()),
            'proposal binding')
    require(source['tool_sha256'] == sha((BASE/'tool.json').read_bytes()), 'descriptor binding')
    require(source['setup_evidence_contract_sha256'] == sha(SETUP_CONTRACT.read_bytes()),
            'setup evidence binding')
    require(source['aggregate_evidence_contract_sha256'] == sha(AGGREGATE_CONTRACT.read_bytes()),
            'aggregate evidence binding')
    manifest = load((BASE/'manifest.json').read_text())
    require(manifest['repository'] == source['repository'] and manifest['revision'] == source['revision'],
            'manifest provenance')
    require(manifest['status'] == 'PROPOSAL_NOT_ADOPTED', 'manifest adoption promotion')
    require(manifest['files']['consolidated.md'] == source['consolidated_sha256'] and
            manifest['files']['tool.json'] == source['tool_sha256'], 'manifest file binding')
    require(len(value['review_scope']) == 6 and len(set(value['review_scope'])) == 6,
            'review scope')
    rows = value['findings']
    require(type(rows) is list and len(rows) == 6, 'finding inventory')
    require({row.get('id') for row in rows} == EXPECTED_IDS, 'finding identity')
    proposal = normalized(proposal)
    for row in rows:
        exact(row, ('id','category','severity','status','title','anchors','observation',
                    'required_resolution','required_validation'), 'finding fields')
        require(row['severity'] in ('HIGH','MEDIUM'), 'finding severity')
        require(row['status'] in ('OPEN','PENDING_EXTERNAL'), 'finding status')
        require(type(row['anchors']) is list and row['anchors'], 'finding anchors')
        for anchor in row['anchors']:
            require(type(anchor) is str and normalized(anchor) in proposal, 'finding anchor: '+row['id'])
        require(all(type(row[field]) is str and len(row[field]) >= 20
                    for field in ('title','observation','required_resolution')), 'finding explanation')
        require(type(row['required_validation']) is list and len(row['required_validation']) == 4
                and len(set(row['required_validation'])) == 4, 'finding validation')
    require(sum(row['severity']=='HIGH' for row in rows) == 4 and
            sum(row['severity']=='MEDIUM' for row in rows) == 2 and
            sum(row['status']=='OPEN' for row in rows) == 5 and
            sum(row['status']=='PENDING_EXTERNAL' for row in rows) == 1, 'derived finding counts')
    return value


def inspect():
    contract_raw = CONTRACT.read_bytes()
    proposal_raw = (BASE/'consolidated.md').read_bytes()
    contract = validate_contract(load(contract_raw.decode()), proposal_raw.decode())
    return {
        'schema_version': 1,
        'kind': 'mcp-adoption-readiness-review-report',
        'status': 'REVIEW_CHECKED',
        'internal_review': contract['internal_review'],
        'external_review': contract['external_review'],
        'adoption': contract['adoption'],
        'conformance': contract['conformance'],
        'adoption_readiness': contract['adoption_readiness'],
        'finding_counts': contract['finding_counts'],
        'contract_sha256': sha(contract_raw),
        'proposal_sha256': sha(proposal_raw),
        'findings': [{'id':row['id'],'severity':row['severity'],'status':row['status'],
                      'title':row['title']} for row in contract['findings']],
        'limitation': 'Internal bounded document review only; it is not external independent review, normative adoption, protocol execution or conformance.'
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        require(not output.exists() and not output.is_relative_to(ROOT), 'new external output required')
        report = inspect()
        output.mkdir(parents=True, exist_ok=False)
        (output/'contract.json').write_bytes(CONTRACT.read_bytes())
        (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    except (ValueError,KeyError,TypeError,OSError,UnicodeError,json.JSONDecodeError) as error:
        print('MCP adoption review FAIL: '+str(error), file=sys.stderr)
        return 1
    print('MCP adoption review checked: 4 HIGH, 2 MEDIUM; adoption BLOCKED; external review NOT_PERFORMED.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
