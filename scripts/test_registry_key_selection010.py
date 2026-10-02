"""Run independent key-selection cases through the actual Go and Rust Gates.

The fixture Source and Clock are synthetic trusted dependencies. These cases
do not verify a signed application message or establish Registry deployment.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "vectors/0.10.0/registry-key-selection010.json"
BASE = ROOT / "vectors/0.10.0/registry010.json"
SPEC_REVISION = "fa006fd917ad365eb554a27f4178301cd66e2379"
CASE_IDS = (
    "exact-active-signer",
    "missing-signer-no-fallback",
    "revoked-signer-no-fallback",
    "expired-signer-no-fallback",
    "kem-key-cannot-sign",
    "inactive-record-cannot-sign",
    "missing-kem-cannot-establish-session",
)
ALTERNATIVE_MATERIAL = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def revision(path):
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


def validate_suite(suite):
    assert suite["schema_version"] == 1
    assert suite["protocol_version"] == "0.10.0"
    assert tuple(case["id"] for case in suite["cases"]) == CASE_IDS
    assert [case["expected_verdict"] for case in suite["cases"]] == ["ACCEPT"] + ["REJECT"] * 6
    for case in suite["cases"]:
        assert set(case) <= {
            "id", "signing_key", "selected_key_state", "selected_key_expires",
            "alternative_signer", "record_state", "require_kem", "kem_key_state",
            "expected_verdict", "expected_journal_version",
        }
        assert {"id", "signing_key", "expected_verdict", "expected_journal_version"} <= set(case)
        assert case["signing_key"] in {"signing-1", "signing-2", "kem-1"}
        assert case["expected_verdict"] in {"ACCEPT", "REJECT"}
        assert case["expected_journal_version"] == "2"
        assert case.get("selected_key_state", "accepted") in {"accepted", "revoked"}
        assert case.get("kem_key_state", "accepted") in {"accepted", "revoked"}
        assert case.get("record_state", "active") in {"active", "created"}
        assert case.get("selected_key_expires", 100) == 100
        assert type(case.get("alternative_signer", False)) is bool
        assert type(case.get("require_kem", False)) is bool


def request_for(case, base):
    request = copy.deepcopy(base)
    request["require_kem"] = case.get("require_kem", False)
    request["signing_url"] = request["did"] + "#" + case["signing_key"]
    snapshot = request["snapshot"]
    snapshot["state"] = case.get("record_state", "active")
    keys = snapshot["keys"]
    for key in keys:
        if key["name"] == "signing-1":
            key["state"] = case.get("selected_key_state", "accepted")
            if "selected_key_expires" in case:
                key["expires"] = case["selected_key_expires"]
        elif key["name"] == "kem-1":
            key["state"] = case.get("kem_key_state", "accepted")
    if case.get("alternative_signer", False):
        keys.append({
            "name": "signing-2", "alg": "ed25519",
            "material": ALTERNATIVE_MATERIAL, "state": "accepted",
        })
    return request


def run_case(program, case, base, journal):
    did = base["did"]
    requests = [
        {"id": "decision", "request": request_for(case, base)},
        {"id": "journal", "request": {"action": "inspect", "did": did}},
    ]
    wire = "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in requests)
    try:
        process = subprocess.run(
            [str(program), str(journal), "create"], input=wire,
            capture_output=True, text=True, timeout=15, check=False,
        )
    except subprocess.TimeoutExpired as error:
        return {"id": case["id"], "status": "FAIL", "timeout": True,
                "input_sha256": hashlib.sha256(wire.encode()).hexdigest(),
                "stdout": str(error.stdout), "stderr": str(error.stderr)}
    try:
        actual = [json.loads(line) for line in process.stdout.splitlines()]
    except json.JSONDecodeError:
        actual = []
    output = ({"signing_keyid": did + "#" + case["signing_key"], "kem_keyid": ""}
              if case["expected_verdict"] == "ACCEPT" else {})
    expected = [
        {"id": "decision", "verdict": case["expected_verdict"], "output": output},
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
    report = {
        "kind": "registry-key-selection010-observation",
        "conformance": "NOT_ESTABLISHED",
        "scope": suite["scope"], "spec_revision": SPEC_REVISION,
        "suite_sha256": sha256(SUITE), "base_fixture_sha256": sha256(BASE),
        "subjects": {},
    }
    with tempfile.TemporaryDirectory() as temp:
        for name in ("go", "rust"):
            root = getattr(args, f"{name}_root")
            pinned = getattr(args, f"{name}_revision")
            program = getattr(args, f"{name}_adapter")
            assert revision(root) == pinned, f"{name} revision changed"
            assert not subprocess.check_output(["git", "diff", "HEAD", "--"], cwd=root), f"{name} source changed"
            cases = [run_case(program, case, base, Path(temp) / f"{name}-{case['id']}")
                     for case in suite["cases"]]
            report["subjects"][name] = {
                "revision": pinned, "executable_sha256": sha256(program),
                "cases": cases, "passed": sum(case["status"] == "PASS" for case in cases),
            }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    assert all(subject["passed"] == len(CASE_IDS) for subject in report["subjects"].values())
    print(json.dumps({"conformance": report["conformance"], "go": len(CASE_IDS), "rust": len(CASE_IDS)}))


if __name__ == "__main__":
    main()
