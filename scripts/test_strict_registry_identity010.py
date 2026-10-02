"""Observe strict DID/key-URL admission through two real 0.10.0 Registry Gates.

The adapters use synthetic trusted dependencies. No deployed source or signed
application message is claimed by this report.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "vectors/0.10.0/strict-registry-identity010.json"
BASE = ROOT / "vectors/0.10.0/registry010.json"
SPEC_REVISION = "fa006fd917ad365eb554a27f4178301cd66e2379"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def revision(path):
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=path, text=True
    ).strip()


def validate_suite(suite):
    assert suite["schema_version"] == 1
    assert suite["protocol_version"] == "0.10.0"
    cases = suite["cases"]
    assert len(cases) == 8
    assert len({case["id"] for case in cases}) == len(cases)
    assert [case["id"] for case in cases] == [
        "canonical-exact-signer", "legacy-kind", "noncanonical-chain",
        "different-registry", "missing-key-fragment", "extra-key-fragment",
        "key-of-other-agent", "invalid-key-name",
    ]
    for case in cases:
        allowed = {"id", "action", "did", "expected_verdict", "expected_journal_version"}
        if case["action"] == "select":
            allowed.add("signing_url")
        else:
            assert case["action"] == "observe"
        assert set(case) == allowed
        assert case["expected_verdict"] in {"ACCEPT", "REJECT"}
        assert case["expected_journal_version"] == ("2" if case["expected_verdict"] == "ACCEPT" else "0")


def request_for(case, base):
    request = copy.deepcopy(base)
    request["action"] = case["action"]
    request["did"] = case["did"]
    if case["action"] == "select":
        request["signing_url"] = case["signing_url"]
        request["require_kem"] = False
    else:
        request.pop("signing_url", None)
        request.pop("require_kem", None)
    return request


def run_case(program, case, base, journal):
    requests = [
        {"id": "decision", "request": request_for(case, base)},
        {"id": "journal", "request": {"action": "inspect", "did": base["did"]}},
    ]
    wire = "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in requests)
    try:
        process = subprocess.run(
            [str(program), str(journal), "create"], input=wire,
            capture_output=True, text=True, timeout=15, check=False,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "id": case["id"], "status": "FAIL", "timeout": True,
            "input_sha256": hashlib.sha256(wire.encode()).hexdigest(),
            "stdout": str(error.stdout), "stderr": str(error.stderr),
        }
    try:
        actual = [json.loads(line) for line in process.stdout.splitlines()]
    except json.JSONDecodeError:
        actual = []
    expected_output = (
        {"signing_keyid": case["signing_url"], "kem_keyid": ""}
        if case["expected_verdict"] == "ACCEPT" else {}
    )
    expected = [
        {"id": "decision", "verdict": case["expected_verdict"], "output": expected_output},
        {"id": "journal", "verdict": "ACCEPT", "output": {
            "highest_finalized_version": case["expected_journal_version"],
            "tombstone": False,
        }},
    ]
    return {
        "id": case["id"], "exit_code": process.returncode,
        "input_sha256": hashlib.sha256(wire.encode()).hexdigest(),
        "stdout": process.stdout, "stderr": process.stderr,
        "status": "PASS" if process.returncode == 0 and actual == expected else "FAIL",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("go", "rust", "spec"):
        parser.add_argument(f"--{name}-root", required=True, type=Path)
    for name in ("go", "rust"):
        parser.add_argument(f"--{name}-revision", required=True)
        parser.add_argument(f"--{name}-adapter", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    assert revision(args.spec_root) == SPEC_REVISION
    suite = json.loads(SUITE.read_text())
    validate_suite(suite)
    fixture = json.loads(BASE.read_text())
    base = next(case for case in fixture["cases"] if case["id"] == "kem-required")["steps"][0]["request"]
    assert base["did"] == suite["cases"][0]["did"]
    report = {
        "kind": "strict-registry-identity010-observation",
        "conformance": "NOT_ESTABLISHED",
        "scope": suite["scope"],
        "spec_revision": SPEC_REVISION,
        "suite_sha256": sha256(SUITE),
        "base_fixture_sha256": sha256(BASE),
        "subjects": {},
    }
    with tempfile.TemporaryDirectory() as temp:
        for name in ("go", "rust"):
            root = getattr(args, f"{name}_root")
            pinned = getattr(args, f"{name}_revision")
            program = getattr(args, f"{name}_adapter")
            assert revision(root) == pinned, f"{name} core revision changed"
            assert not subprocess.check_output(["git", "diff", "HEAD", "--"], cwd=root), f"{name} core source changed"
            cases = [run_case(program, case, base, Path(temp) / f"{name}-{case['id']}") for case in suite["cases"]]
            report["subjects"][name] = {
                "revision": pinned,
                "executable_sha256": sha256(program),
                "cases": cases,
                "passed": sum(case["status"] == "PASS" for case in cases),
            }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    assert all(subject["passed"] == 8 for subject in report["subjects"].values()), "identity observation failed"
    print(json.dumps({"conformance": report["conformance"], "go": 8, "rust": 8}))


if __name__ == "__main__":
    main()
