"""Reproduce a pinned manual Registry mapping assessment without running a contract.

A successful query is not deployment compatibility or connection authorization.
The fixed review has no route that upgrades source observations to conformance.
"""
import argparse
import copy
import json
from pathlib import Path

import inspect_registry_contract_preflight as preflight

REVIEW = preflight.ROOT / 'verification/0.10.0/registry-mapping-review/review.json'
REVIEW_SHA = '9307dbfafdc8fba530dc82240874acfc96928e86d9369efb59aaad2b020f3469'
MAX_REVIEW = 128 << 10


def review(path=REVIEW):
    raw = Path(path).read_bytes()
    preflight.require(len(raw) <= MAX_REVIEW and preflight.sha(raw) == REVIEW_SHA,
                      'reviewed mapping ledger changed')
    return json.loads(raw)


def report(sources, ledger):
    """Validate exact source provenance before replaying human-reviewed conclusions."""
    preflight.require(ledger == review(), 'reviewed mapping ledger changed')
    source = preflight.report(sources, preflight.catalog())
    for span in ledger['reviewed_spans']:
        raw = sources[span['repository']][span['path']]
        lines = raw.splitlines(keepends=True)
        preflight.require(1 <= span['line'] <= span['end_line'] <= len(lines) and
                          preflight.sha(b''.join(lines[span['line'] - 1:span['end_line']])) == span['sha256'],
                          'reviewed mapping span changed')
    preflight.require(ledger['preflight_catalog_sha256'] == source['catalog_sha256'],
                      'mapping/source catalog mismatch')
    ids = [row['id'] for row in ledger['obligations']]
    preflight.require(ids == [row['id'] for row in source['findings']], 'mapping obligations drift')
    result = copy.deepcopy(ledger)
    result.update(
        kind='REGISTRY_MAPPING_SOURCE_REVIEW', review_sha256=REVIEW_SHA,
        source_query_status=source['source_query_status'],
        repositories=source['repositories'],
        classification_counts={name: sum(row['classification'] == name for row in ledger['obligations'])
                               for name in ('READ_MAPPING_REQUIRED', 'WRITE_SEMANTICS_REQUIRED',
                                            'PROVIDER_BINDING_REQUIRED')},
        required_evidence_count=sum(len(row['required_evidence']) for row in ledger['obligations']),
        mapping_review_status='SOURCE_REVIEW_COMPLETE',
        read_only_projection_sufficient=False,
        binding_readiness='UNRESOLVED',
        connection_authorization='NOT_GRANTED',
        selected_deployment=None, selected_host=None,
        live_chain_verification='NOT_RUN', contract_compilation='NOT_RUN', contract_execution='NOT_RUN',
        loaded_instance_attestation='NOT_RUN', effect_observations=None,
        deployed_host_controls=source['deployed_host_controls'],
        independent_hop_execution='NOT_RUN', full_conformance='NOT_ESTABLISHED',
        limitations=[
            'Bounded manual source conclusions are reproduced by hashes, not inferred by a Solidity semantic analyzer.',
            'All six projection candidates and all required evidence remain unbound; source-query success closes no deployment or host control.',
            'The reviewed contract revision cannot be assumed compatible through a reader-only field projection.',
            'No claim about an unspecified deployed address, future complete binding or contract compiler equivalence is established.',
            'No inspected contract, tool, loader, RPC or attack-capable program executes.',
            'Later contract upgrades and separate normative design work retain the approved program order.',
        ],
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('contracts', 'spec', 'go', 'adk'):
        parser.add_argument('--' + name + '-root', type=Path, required=True)
    parser.add_argument('--check', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sources = {name: preflight.read_repository(getattr(args, name + '_root'), declaration)
               for name, declaration in preflight.catalog()['repositories'].items()}
    result = report(sources, review())
    if args.check:
        preflight.require(result == json.loads(args.check.read_text()), 'saved mapping report drift')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('Reviewed all 7 mapping areas and 21 evidence requirements; connection remains UNRESOLVED')


if __name__ == '__main__':
    main()
