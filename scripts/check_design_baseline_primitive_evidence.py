"""Check saved design-baseline observations of the 0.10.0 primitive profile.

The observations were captured by run_design_baseline_cases.py at
RUNNER_REVISION against pinned Go and Rust cores, with adapters built with
the strictdid010 tag/feature. The check re-assesses them against the frozen
design baseline and compares the saved assessment byte for byte. With
--rerun, it compares the outcomes of a fresh run of the same cores with the
saved outcomes, case by case.
"""

import argparse
import json
from pathlib import Path
import sys

from current_spec_catalog import ROOT, load, require, sha
from design_baseline_evidence import assess

BASE = ROOT / 'docs/evidence/design-baseline/primitive-010'
LOCK = ROOT / 'verification/0.10.0/design-baseline-primitive-010/Cargo.lock'
LOCK_SHA256 = '48f9a82c56b0236c95a5bc438afb48b86eb28077820de0e946f81fb040cd149b'
RUNNER_REVISION = 'c033b42cfbb1774a99223bf36935c507659c3c58'
SUBJECTS = {
    'go': ('SAGE-X-project/sage', '6971de244ed87e0803f256d1616e22044d68afa8'),
    'rust': ('SAGE-X-project/rs-sage-core', '9294d17c3de54f36a239ee2318891b719a749631'),
}
# Frozen copies of the runner, the bridge and the bridge's modules at
# RUNNER_REVISION.
ARTIFACTS = {
    'runner/run_design_baseline_cases.py':
        'af2262e8ea637e126a5b45f6d89698ba466a4a0d45e95a36cace068bd8868cac',
    'runner/current_spec_primitive_bridge.py':
        'f786bef91860608180c59d54a2cb3971b65e3efd5e873ee954ebb5ab4a81c924',
    'runner/current_spec_catalog.py':
        '3aee39e7e10597d04d595688bd1fe1c3b138550d2bfd35ea46c513b4e68f4091',
    'runner/current_spec_evidence.py':
        '2930c2680e1260c2063690b470089e7bfb1ce3ab876a5ff2f6ddec33465125fd',
}
COUNTS = {'PASS': 0, 'FAIL': 0, 'PARTIAL': 73, 'UNSUPPORTED': 1, 'NOT_RUN': 415}
OBSERVATIONS = 74
UNSUPPORTED = {'HPKE-03-N01'}


def outcomes(directory):
    manifest = load((directory / 'manifest.json').read_bytes())
    return {row['id']: load((directory / row['path']).read_bytes())['actual']
            for row in manifest['observations']}


def check(lang, base=BASE):
    directory = base / lang
    manifest = load((directory / 'manifest.json').read_bytes())
    repository, revision = SUBJECTS[lang]
    require(manifest['subject']['repository'] == repository and
            manifest['subject']['revision'] == revision and
            manifest['runner_revision'] == RUNNER_REVISION and
            {item['path']: item['sha256'] for item in manifest['artifacts']} == ARTIFACTS and
            len(manifest['observations']) == OBSERVATIONS,
            lang + ' subject, runner or artifact identity')
    report = assess(ROOT, directory)
    require((directory / 'assessed.json').read_text() ==
            json.dumps(report, indent=2) + '\n', lang + ' saved assessment drift')
    require(report['counts'] == COUNTS, lang + ' counts')
    unsupported = {row['id'] for row in report['tracks'] if row['status'] == 'UNSUPPORTED'}
    require(unsupported == UNSUPPORTED, lang + ' unsupported cases')
    return report


def compare(lang, fresh, base=BASE):
    manifest = load((fresh / 'manifest.json').read_bytes())
    require(tuple(manifest['subject'][key] for key in ('repository', 'revision')) ==
            SUBJECTS[lang], lang + ' rerun subject')
    assess(ROOT, fresh)
    require(outcomes(fresh) == outcomes(base / lang), lang + ' rerun outcome drift')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rerun', nargs=2, action='append', metavar=('LANG', 'DIR'),
                        help='Compare a fresh run directory (go or rust) with saved outcomes')
    args = parser.parse_args()
    try:
        require(sha(LOCK.read_bytes()) == LOCK_SHA256, 'pinned Rust adapter lock')
        reports = {lang: check(lang) for lang in SUBJECTS}
        require({row['id']: row['status'] for row in reports['go']['tracks']} ==
                {row['id']: row['status'] for row in reports['rust']['tracks']},
                'Go and Rust case statuses differ')
        for lang, directory in args.rerun or []:
            require(lang in SUBJECTS, 'rerun language')
            compare(lang, Path(directory))
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        print('Design baseline primitive evidence FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('Design baseline primitive evidence: ' + json.dumps(COUNTS) +
          ' per core; conformance NOT_ESTABLISHED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
