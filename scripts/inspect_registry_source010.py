"""Inspect bounded, operator-supplied registry observation evidence, without RPC.

This validates an evidence contract, not node consensus, record proofs or trust.
No input is converted into an authoritative core Snapshot or authorization grant.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 4 * 1024 * 1024
MAX_INT = 9007199254740991


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, names):
    require(type(value) is dict and set(value) == set(names.split()), 'unexpected object members')


def text(value, maximum=256):
    require(type(value) is str and 0 < len(value) <= maximum
            and all(32 <= ord(c) <= 126 for c in value), 'invalid bounded ASCII text')


def integer(value, maximum=MAX_INT):
    require(type(value) is int and 0 <= value <= maximum, 'invalid integer')


def hexhash(value):
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value), 'invalid digest')


def decode(raw):
    require(len(raw) <= LIMIT, 'input exceeds bound')

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON member')
            result[key] = value
        return result

    def constant(value):
        raise ValueError('nonfinite JSON number: ' + value)

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid JSON encoding or depth') from error


def binding(raw):
    b = decode(raw)
    exact(b, 'schema_version protocol_version environment source trust_model chain_id registry_address code_hash upgrade_policy read_abi_sha256 write_abi_sha256 operator_scopes transaction_authorization readiness_policy finality_policy readiness_max_age_ms observer_revision observer_sha256')
    require(type(b['schema_version']) is int and b['schema_version'] == 1
            and b['protocol_version'] == '0.10.0', 'binding version')
    require(b['environment'] in ('synthetic', 'deployed'), 'environment')
    require(b['trust_model'] in ('self-validated-node', 'explicitly-trusted-resolver'), 'trust model')
    require(type(b['chain_id']) is str and re.fullmatch(r'[1-9][0-9]{0,31}', b['chain_id']), 'chain ID')
    require(type(b['registry_address']) is str and re.fullmatch(r'0x[0-9a-f]{40}', b['registry_address']), 'registry address')
    for field in ('code_hash', 'read_abi_sha256', 'write_abi_sha256', 'observer_sha256'):
        hexhash(b[field])
    for field in ('source', 'upgrade_policy', 'operator_scopes', 'transaction_authorization', 'readiness_policy', 'finality_policy', 'observer_revision'):
        text(b[field])
    integer(b['readiness_max_age_ms'], 60000)
    require(b['readiness_max_age_ms'] > 0, 'readiness policy age')
    return b


def observations(raw, b, binding_hash):
    bundle = decode(raw)
    exact(bundle, 'schema_version binding_sha256 observer_sha256 artifacts observations')
    require(type(bundle['schema_version']) is int and bundle['schema_version'] == 1, 'bundle version')
    require(bundle['binding_sha256'] == binding_hash and bundle['observer_sha256'] == b['observer_sha256'], 'binding or observer mismatch')
    artifacts = bundle['artifacts']
    require(type(artifacts) is dict and 1 <= len(artifacts) <= 512, 'artifact count')
    for digest, encoded in artifacts.items():
        hexhash(digest)
        require(type(encoded) is str and 0 < len(encoded) <= 131072
                and len(encoded) % 2 == 0 and re.fullmatch('[0-9a-f]+', encoded), 'artifact encoding')
        require(sha(bytes.fromhex(encoded)) == digest, 'artifact digest mismatch')
    rows = bundle['observations']
    require(type(rows) is list and 1 <= len(rows) <= 128, 'observation count')
    epochs, operations, watermarks, used = set(), set(), {}, set()
    record_blocks = {}
    epoch = None
    last_end = last_utc = last_height = None
    last_block = None
    metrics = []
    registry = 'eip155:' + b['chain_id'] + ':' + b['registry_address']
    for row in rows:
        exact(row, 'operation_id epoch epoch_started_ms source chain_id registry_address code_hash readiness_ms start_ms acquired_ms gate_ms utc_ms block_height block_hash keys_block_hash finalized conflicting did version record_digest state readiness_evidence finality_evidence record_evidence publication')
        for field in ('operation_id', 'epoch', 'source', 'did'):
            text(row[field])
        require(row['operation_id'] not in operations, 'reused operation')
        operations.add(row['operation_id'])
        for field in ('epoch_started_ms', 'readiness_ms', 'start_ms', 'acquired_ms', 'gate_ms', 'utc_ms', 'block_height'):
            integer(row[field])
        for field in ('block_hash', 'keys_block_hash', 'record_digest'):
            hexhash(row[field])
        require(row['source'] == b['source'] and row['chain_id'] == b['chain_id']
                and row['registry_address'] == b['registry_address'] and row['code_hash'] == b['code_hash'], 'source or deployment mismatch')
        prefix = 'did:sage:' + registry + ':'
        require(row['did'].startswith(prefix), 'DID registry mismatch')
        agent = row['did'][len(prefix):]
        require(re.fullmatch(r'[A-Za-z0-9._-]{1,64}', agent) and agent not in ('.', '..'), 'agent identifier')
        require(row['finalized'] is True and row['conflicting'] is False, 'unfinalized or conflicting observation')
        require(row['block_hash'] == row['keys_block_hash'], 'mixed block observation')
        version = row['version']
        require(type(version) is str and re.fullmatch(r'[1-9][0-9]{0,19}', version)
                and int(version) <= 18446744073709551615, 'record version')
        require(row['state'] in ('created', 'active', 'deactivated'), 'record state')
        require(row['record_digest'] == row['record_evidence'], 'record digest is not tied to raw evidence')
        if epoch != row['epoch']:
            require(row['epoch'] not in epochs, 'reused process epoch')
            epochs.add(row['epoch'])
            epoch, epoch_start, last_end = row['epoch'], row['epoch_started_ms'], None
        require(row['epoch_started_ms'] == epoch_start, 'changed epoch start')
        require(epoch_start <= row['readiness_ms'] <= row['acquired_ms'], 'readiness not established after restart')
        require(epoch_start <= row['start_ms'] <= row['acquired_ms'] <= row['gate_ms'], 'clock ordering')
        require(row['gate_ms'] - row['acquired_ms'] <= 5000, 'stale authorization observation')
        require(row['gate_ms'] - row['readiness_ms'] <= b['readiness_max_age_ms'], 'readiness expired')
        require(last_end is None or row['start_ms'] >= last_end, 'serial observation clock rollback')
        require(last_utc is None or row['utc_ms'] >= last_utc, 'UTC rollback')
        require(last_height is None or row['block_height'] >= last_height, 'finalized block rollback')
        require(last_height != row['block_height'] or last_block == row['block_hash'], 'finalized block conflict')
        previous = watermarks.get(row['did'])
        current = (int(version), row['record_digest'], row['state'])
        if previous:
            require(current[0] >= previous[0], 'record rollback')
            require(current[0] != previous[0] or current == previous, 'same-version conflict')
            require(previous[2] != 'deactivated' or current == previous, 'terminal record changed')
        previous_block = record_blocks.get(row['did'])
        require(previous_block != row['block_height'] or current == previous, 'record changed within finalized block')
        record_blocks[row['did']] = row['block_height']
        watermarks[row['did']] = current
        last_end, last_utc = row['gate_ms'], row['utc_ms']
        last_height, last_block = row['block_height'], row['block_hash']
        for field in ('readiness_evidence', 'finality_evidence', 'record_evidence'):
            require(row[field] in artifacts, 'missing evidence artifact')
            used.add(row[field])
        latency = None
        publication = row['publication']
        if publication is not None:
            exact(publication, 'epoch submitted_ms finalized_ms evidence')
            require(publication['epoch'] == epoch, 'cross-clock publication measurement')
            integer(publication['submitted_ms']); integer(publication['finalized_ms'])
            require(epoch_start <= publication['submitted_ms'] <= publication['finalized_ms'] <= row['acquired_ms'], 'publication ordering')
            require(publication['evidence'] in artifacts, 'missing publication artifact')
            used.add(publication['evidence'])
            latency = publication['finalized_ms'] - publication['submitted_ms']
        metrics.append(dict(operation_id=row['operation_id'], read_ms=row['acquired_ms']-row['start_ms'],
                            observation_age_ms=row['gate_ms']-row['acquired_ms'],
                            publication_to_finality_ms=latency,
                            publication_measurement='NOT_RUN' if latency is None else 'DECLARED'))
    require(used == set(artifacts), 'unreferenced evidence artifact')
    return metrics


def inspect(binding_path, bundle_path, output):
    output = output.resolve()
    require(ROOT / 'docs/evidence' not in (output, *output.parents), 'preserve historical evidence')
    output.mkdir(parents=True, exist_ok=False)
    report = dict(schema_version=1, protocol_version='0.10.0', kind='registry-source-evidence',
                  status='NOT_RUN', conformance='NOT_ESTABLISHED', actual_core_execution=False,
                  live_chain_verification='NOT_RUN', measurements=[], files={},
                  scope='Operator-declared evidence consistency only; no consensus, full record proof, ABI semantics or source trust certification.')
    try:
        if binding_path is None:
            require(bundle_path is None, 'observations require a binding')
            report['reason'] = 'No deployment binding supplied.'
        else:
            raw = read_bounded(binding_path)
            (output/'binding.json').write_bytes(raw)
            report['files']['binding.json'] = sha(raw)
            b = binding(raw)
            report['environment'] = b['environment']
            if bundle_path is None:
                report['reason'] = 'No observation evidence supplied.'
            else:
                raw = read_bounded(bundle_path)
                (output/'observations.json').write_bytes(raw)
                report['files']['observations.json'] = sha(raw)
                report['measurements'] = observations(raw, b, report['files']['binding.json'])
                report['status'] = 'EVIDENCE_VALIDATED'
    except (ValueError, OSError, TypeError, KeyError) as error:
        report.update(status='FAIL', reason=str(error))
    finally:
        (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def read_bounded(path):
    with path.open('rb') as stream:
        raw = stream.read(LIMIT+1)
    require(len(raw) <= LIMIT, 'input exceeds bound')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding', type=Path)
    parser.add_argument('--observations', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.binding, args.observations, args.output)
        print(json.dumps(dict(status=result['status'], conformance=result['conformance'])))
        return {'EVIDENCE_VALIDATED': 0, 'FAIL': 1, 'NOT_RUN': 3}[result['status']]
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
