#!/usr/bin/env python3
"""Evaluate a declared Execution Guard capability boundary, not a live host."""

import argparse
import json
from pathlib import Path
import sys


ASSETS = frozenset(('original_request', 'policy', 'signing_key',
                    'component_manifest', 'verifier', 'dispatch_gate'))
PATHS = frozenset(('subprocess', 'network', 'file', 'retry', 'parallel',
                   'subagent'))
UNTRUSTED = frozenset(('plugin', 'skill', 'mcp', 'model', 'child'))
TRUSTED = frozenset(('trusted_client', 'trusted_admin', 'trusted_server',
                     'trusted_dispatch_gate'))


def inspect(description):
    """Return explicit defects; a clean declaration alone proves no isolation."""
    if type(description) is not dict or set(description) != {
            'untrusted_principals', 'protected_assets', 'effect_paths',
            'hook', 'server'}:
        return ['invalid boundary description']
    principals = description['untrusted_principals']
    if type(principals) is not list or set(principals) != UNTRUSTED or \
            len(principals) != len(UNTRUSTED):
        return ['untrusted principal set incomplete']
    defects = []
    assets = description['protected_assets']
    if type(assets) is not dict or set(assets) != ASSETS:
        defects.append('protected asset inventory incomplete')
    else:
        for name in sorted(ASSETS):
            acl = assets[name]
            if type(acl) is not dict or set(acl) != {'readers', 'writers'} or \
                    any(type(acl.get(field)) is not list or
                        any(type(principal) is not str for principal in acl[field])
                        for field in ('readers', 'writers')):
                defects.append(name + ': invalid capability list')
                continue
            if name == 'signing_key' and \
                    any(principal in UNTRUSTED for principal in acl['readers']):
                defects.append('signing key readable by untrusted principal')
            if any(principal in UNTRUSTED for principal in acl['writers']):
                defects.append(name + ': writable by untrusted principal')
            if any(principal not in TRUSTED | UNTRUSTED
                   for principal in acl['readers'] + acl['writers']):
                defects.append(name + ': unclassified principal')
            if not acl['readers'] or not acl['writers']:
                defects.append(name + ': no trusted owner')
    paths = description['effect_paths']
    if type(paths) is not dict or set(paths) != PATHS:
        defects.append('protected effect path inventory incomplete')
    else:
        for path in sorted(PATHS):
            route = paths[path]
            if type(route) is not dict or route != {
                    'mediated_by': 'trusted_dispatch_gate',
                    'bypass_credentials_exposed': False}:
                defects.append(path + ': unmediated effect path')
    hook = description['hook']
    if type(hook) is not dict or set(hook) != {'mandatory', 'writers'} or \
            hook['mandatory'] is not True or type(hook['writers']) is not list or \
            set(hook['writers']) != {'trusted_admin'}:
        defects.append('mandatory hook can be bypassed or changed')
    server = description['server']
    if type(server) is not dict or server != {
            'verifier_boundary': 'trusted_server',
            'dispatcher_boundary': 'trusted_server',
            'tool_boundary': 'isolated_untrusted',
            'tool_has_host_privilege': False}:
        defects.append('server verifier or tool capability boundary is unsafe')
    return defects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = args.input.read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError('boundary description exceeds 1 MiB')
        description = json.loads(raw)
        defects = inspect(description)
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({'schema_version': 1,
                      'kind': 'declared-capability-review',
                      'verdict': 'ACCEPT' if not defects else 'REJECT',
                      'defects': defects,
                      'deployment_conformance': 'NOT_ESTABLISHED'},
                     separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
