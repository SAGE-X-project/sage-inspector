"""Check the bounded Go signature observation without promoting conformance."""

import copy
import json

from current_spec_catalog import ROOT
from observe_current_spec_msg01_go_tag import REPORT, check_report, fixture


def test_fixture_and_report():
    control, digest = fixture()
    assert control['expected']['output']['base_hex'] and len(digest) == 64
    report = json.loads((ROOT / REPORT).read_bytes())
    assert check_report(report)
    for field, value in [('conformance', 'PASS'), ('scope', 'full-message')]:
        changed = copy.deepcopy(report)
        changed[field] = value
        try:
            check_report(changed)
        except ValueError:
            pass
        else:
            raise AssertionError('unsupported scope was promoted')
    changed = copy.deepcopy(report)
    changed['observations']['changed_tag']['signature_valid'] = True
    try:
        check_report(changed)
    except ValueError:
        pass
    else:
        raise AssertionError('changed tag was accepted')


if __name__ == '__main__':
    test_fixture_and_report()
