"""Run the abstract admission model, without executing the proposed protocol."""
import argparse
import json
from pathlib import Path
import sys
from check_mcp_catalog import ROOT, inspect, sha
from mcp_owner_model import explore


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    try:
        if out.exists() or out.is_relative_to(ROOT):
            raise ValueError('use a new output directory outside the repository')
        baseline = inspect()
        out.mkdir(parents=True, exist_ok=False)
    except (ValueError, KeyError, OSError) as error:
        p.exit(2, str(error) + '\n')
    report = dict(kind='mcp-owner-abstract-model', status='RUNNING',
                  baseline=baseline['baseline'], inspector_revision=baseline['inspector_revision'],
                  model_sha256=sha((ROOT / 'scripts/mcp_owner_model.py').read_bytes()),
                  actual_core_execution=False, external_review=False, protocol_execution='NOT_RUN',
                  adoption='PROPOSAL_NOT_ADOPTED', conformance='NOT_ESTABLISHED',
                  proposal_cases={'NOT_RUN': 71}, lifecycle={'NOT_RUN': 37},
                  limitations=['One owner and invocation; no reconnect or concurrent runtime.',
                               'Abstract ledger/effect counters; no durable storage or real tool effects.',
                               'Trusted authentication and authority assumed; algorithms not verified.',
                               'Discrete clock and fixed deadlines; not arbitrary timing or scheduler proof.',
                               'Scaled time units do not verify the production 30-second bound.'])
    try:
        report['exploration'] = explore()
        report['status'] = 'MODEL_CHECKED'
    except Exception as error:
        report.update(status='FAIL', counterexample=str(error))
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(report['status'] + ': abstract owner only; 71 protocol cases NOT_RUN')
    return 0 if report['status'] == 'MODEL_CHECKED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
