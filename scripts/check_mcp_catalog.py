"""Inspect pinned proposal membership; never execute or promote protocol cases."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from inspect_guard_binding import load, require

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'verification/0.10.0/mcp-consolidated-proposal'
MANIFEST_SHA = '5727834113a41ef910d4a5c5487457b6e3ae9f89ac36e86946a6e72ae28c1f35'
REVISION = '70abcda876879697cae91f1182ce5c9148211e8d'
FILES = {'consolidated.md', 'cases.json', 'addendum-cases.json', 'resolutions.json', 'tool.json'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def catalog(plans):
    rows = []
    seen = set()
    groups = [('cases.json', 40, 'mset-', 'rule'),
              ('addendum-cases.json', 18, 'madd-', 'obligation'),
              ('resolutions.json', 13, 'mres-', 'finding')]
    for name, count, prefix, relation in groups:
        plan = plans[name]
        require(plan['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')
        if name == 'cases.json':
            require(plan['status'] == 'NOT_RUN', 'plan promotion')
        else:
            require(plan.get('adoption', plan.get('status')) == 'PROPOSAL_NOT_ADOPTED', 'adoption promotion')
            require(plan['external_review'] == 'NOT_PERFORMED' and plan['lifecycle'] == {'NOT_RUN': 37}, 'review/history promotion')
        require(len(plan['cases']) == count, 'case count')
        for c in plan['cases']:
            ident = c['id']
            require(ident.startswith(prefix) and ident not in seen, 'case identity')
            require(c['status'] == 'NOT_RUN', 'case promotion')
            require(isinstance(c[relation], str) and c[relation], 'case relation')
            seen.add(ident)
            rows.append(dict(id=ident, source=name, relation=c[relation], status='NOT_RUN'))
    require(len(seen) == 71, 'combined count')
    return rows


def inspect(base=BASE):
    raw = (base / 'manifest.json').read_bytes()
    require(sha(raw) == MANIFEST_SHA, 'manifest identity')
    manifest = load(raw)
    require(manifest['repository'] == 'SAGE-X-project/sage-spec' and
            manifest['revision'] == REVISION and manifest['status'] == 'PROPOSAL_NOT_ADOPTED', 'source provenance')
    require(set(manifest['files']) == FILES, 'snapshot membership')
    data = {}
    for name, digest in manifest['files'].items():
        raw = (base / name).read_bytes()
        require(sha(raw) == digest, 'snapshot hash: ' + name)
        if name.endswith('.json'):
            data[name] = load(raw)
    rows = catalog(data)
    return dict(kind='mcp-proposal-catalog', status='CATALOG_CHECKED', baseline=manifest,
                inspector_revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                checker_sha256=sha(Path(__file__).read_bytes()), actual_core_execution=False,
                protocol_execution='NOT_RUN', external_review=False, adoption='PROPOSAL_NOT_ADOPTED',
                conformance='NOT_ESTABLISHED', lifecycle={'NOT_RUN': 37}, proposal_cases={'NOT_RUN': 71},
                case_groups={'original': 40, 'addendum': 18, 'resolutions': 13}, cases=rows,
                limitation='Source and case membership only; not normative adoption, semantics or protocol execution.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        out = args.output.resolve()
        require(not out.exists() and not out.is_relative_to(ROOT), 'use a new output directory outside the repository')
        report = inspect()
        out.mkdir(parents=True, exist_ok=False)
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'Catalog FAIL: {error}', file=sys.stderr)
        return 1
    print('CATALOG_CHECKED: 71 protocol cases NOT_RUN; no core execution.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
