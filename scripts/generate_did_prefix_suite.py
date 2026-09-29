"""Pin canonical DID controls beside mixed-case prefix checks for both cores."""

import argparse
import json
from pathlib import Path

from current_spec_catalog import ROOT, catalog, index, require
from latest_spec_catalog import LATEST_BASE, LATEST_REVISION


OUTPUT = 'vectors/0.10.0/did-prefix.json'
CANONICAL = 'did:sage:web:agents.example.com:alice'


def suite(root=ROOT, spec_root=None):
    manifest, trace, _ = catalog(root, spec_root, base_relative=LATEST_BASE)
    require(manifest['spec_revision'] == LATEST_REVISION, 'DID prefix source revision')
    cases = index(trace['cases'], 'latest spec case')
    did_case = cases['msca-did-prefix-case']
    url_case = cases['msca-did-url-prefix-case']
    require(did_case['rule_id'] == url_case['rule_id'] == 'ID-01' and
            did_case['mode'] == url_case['mode'] == 'unit_and_bounded_local_runtime' and
            'DID:sage:' in did_case['input'] and 'did:SAGE:' in did_case['input'] and
            'mixed-case did:sage prefix' in url_case['input'],
            'DID prefix case meaning changed')

    def case(name, operation, did, accepted, source_case, key_url=False):
        control = {'did_url': did, 'expected_peer': CANONICAL,
                   'supported_kinds': ['eip155', 'web']} if key_url else {
                       'did': did, 'supported_kinds': ['eip155', 'web']}
        return {
            'id': name, 'operation': operation, 'rule_ids': ['ID-01'],
            'source_ids': ['did-prefix-spec'],
            'derivation': ('Pinned ' + source_case + ' with an unchanged canonical '
                           'web control. Rejecting a changed prefix alone is not '
                           'complete case evidence.'),
            'input': control,
            'expected': {'verdict': 'ACCEPT' if accepted else 'REJECT',
                         'output': {'valid': True} if accepted else {}},
        }

    key_url = CANONICAL + '#signing-1'
    return {
        'schema_version': 1, 'protocol_version': '0.10.0',
        'profile': 'primitive-foundation', 'id': 'sage-did-prefix-0.10.0',
        'sources': [{'id': 'did-prefix-spec', 'kind': 'spec-derived',
                     'uri': 'sage-spec/spec/06-did-sage.md',
                     'reference': LATEST_REVISION +
                     ' ID-01 and msca-did-prefix-case/msca-did-url-prefix-case; '
                     'synthetic local identifiers only.'}],
        'cases': [
            case('did-prefix-control', 'sage.did.validate', CANONICAL, True,
                 'msca-did-prefix-case'),
            case('did-prefix-scheme', 'sage.did.validate',
                 'DID' + CANONICAL[3:], False, 'msca-did-prefix-case'),
            case('did-prefix-method', 'sage.did.validate',
                 CANONICAL.replace('did:sage:', 'did:SAGE:', 1), False,
                 'msca-did-prefix-case'),
            case('did-url-prefix-control', 'sage.did-url.validate', key_url, True,
                 'msca-did-url-prefix-case', key_url=True),
            case('did-url-prefix-scheme', 'sage.did-url.validate',
                 'DID' + key_url[3:], False, 'msca-did-url-prefix-case',
                 key_url=True),
            case('did-url-prefix-method', 'sage.did-url.validate',
                 key_url.replace('did:sage:', 'did:SAGE:', 1), False,
                 'msca-did-url-prefix-case', key_url=True),
        ],
    }


def check(root=ROOT, spec_root=None):
    expected = (json.dumps(suite(root, spec_root), indent=2) + '\n').encode()
    require((root / OUTPUT).read_bytes() == expected, 'DID prefix suite bytes differ')
    return {'cases': 6, 'normative_parents': 2,
            'implementation_conformance': 'NOT_ESTABLISHED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    try:
        if args.write:
            (ROOT / OUTPUT).write_text(json.dumps(suite(spec_root=args.spec_root),
                                                  indent=2) + '\n')
        print(json.dumps(check(spec_root=args.spec_root), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, 'DID prefix suite FAIL: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
