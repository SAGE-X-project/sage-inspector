"""Observe signed DID and peer binding in bounded Go/Rust handshake receivers.

Only two explicitly public test seeds are used. This is a closed local
fixture exercise, not a generic message-forging tool or deployed host test.
"""

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile

from test_completion010 import ALICE, BOB, Actor, canonical, decode, encode, independent, sign, verify


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "vectors/0.10.0/signed-peer-binding010.json"
COMPLETION = ROOT / "vectors/0.10.0/completion010.json"
SPEC_REVISION = "fa006fd917ad365eb554a27f4178301cd66e2379"
GO_REVISION = "fbd9b2169c72d62c62dcbaa2336275d08a5735a8"
RUST_REVISION = "0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f"
DOMAIN = b"sage-wire-request|0.10.0\n"
EXPECTED = (
    ("exact-signed-request", "none", "ACCEPT"),
    ("signed-sender-disagrees-with-handshake", "sender", "REJECT"),
    ("signed-key-url-disagrees-with-handshake", "key-url", "REJECT"),
    ("signed-recipient-disagrees-with-handshake", "recipient", "REJECT"),
    ("signature-uses-another-agent-key", "other-key-signature", "REJECT"),
    ("signed-request-addresses-another-peer", "peer", "REJECT"),
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def revision(path):
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


def validate_suite(suite):
    assert suite["schema_version"] == 1
    assert suite["protocol_version"] == "0.10.0"
    assert tuple((c["id"], c["mutation"], c["expected_verdict"]) for c in suite["cases"]) == EXPECTED
    assert all(set(c) == {"id", "mutation", "expected_verdict"} for c in suite["cases"])


def changed_request(request, mutation):
    if mutation == "none":
        return request, 1
    wire = json.loads(request)
    key = 1
    if mutation == "sender":
        wire["did"] = BOB
        wire["kid"] = BOB + "#signing-1"
        key = 2
    elif mutation == "key-url":
        wire["kid"] = ALICE + "#other"
    elif mutation == "recipient":
        wire["recipient"] = ALICE
    elif mutation == "other-key-signature":
        key = 2
    elif mutation == "peer":
        body = json.loads(decode(wire["payload"]))
        body["respDid"] = ALICE
        wire["payload"] = encode(canonical(body))
        wire["recipient"] = ALICE
    else:
        raise AssertionError(mutation)
    wire.pop("signature")
    wire["signature"] = encode(sign(DOMAIN + canonical(wire), key))
    output = canonical(wire)
    unsigned = dict(wire)
    signature = decode(unsigned.pop("signature"))
    verify(DOMAIN + canonical(unsigned), signature, key)
    return output, key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("go", "rust", "spec"):
        parser.add_argument(f"--{name}-root", required=True, type=Path)
    for name in ("go", "rust"):
        parser.add_argument(f"--{name}-adapter", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert revision(args.spec_root) == SPEC_REVISION
    suite = json.loads(SUITE.read_text())
    validate_suite(suite)
    programs = {name: getattr(args, f"{name}_adapter").resolve() for name in ("go", "rust")}
    roots = {name: getattr(args, f"{name}_root") for name in programs}
    revisions = {"go": GO_REVISION, "rust": RUST_REVISION}
    for name, root in roots.items():
        assert revision(root) == revisions[name], f"{name} core revision changed"
        assert not subprocess.check_output(["git", "diff", "HEAD", "--"], cwd=root), f"{name} core source changed"
        copy = root / ("pkg/agent/hpke/testdata/completion010.json" if name == "go"
                       else "tests/fixtures/completion010.json")
        assert sha256(copy) == sha256(COMPLETION), f"{name} handshake fixture changed"
    output = args.output.resolve()
    assert not output.exists(), "output directory already exists"
    output.mkdir(parents=True)
    report = {
        "kind": "signed-peer-binding010-observation",
        "status": "RUNNING", "conformance": "NOT_ESTABLISHED", "scope": suite["scope"],
        "spec_revision": SPEC_REVISION, "suite_sha256": sha256(SUITE),
        "completion_fixture_sha256": sha256(COMPLETION),
        "runner_sha256": sha256(Path(__file__)),
        "shared_runner_sha256": sha256(ROOT / "scripts/test_completion010.py"),
        "subjects": {name: {"revision": revisions[name], "executable_sha256": sha256(programs[name])}
                     for name in programs},
        "cases": [], "raw": "raw.jsonl",
    }
    raw = (output / "raw.jsonl").open("w")

    def log(value):
        raw.write(json.dumps(value, separators=(",", ":")) + "\n")
        raw.flush()

    def save():
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    save()
    try:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            for sender, receiver in itertools.product(programs, repeat=2):
                for case in suite["cases"]:
                    label = f"{sender}-to-{receiver}-{case['id']}"
                    alice = Actor(label + "-init", "alice", temp / (label + "-a"), programs[sender], log)
                    bob = Actor(label + "-resp", "bob", temp / (label + "-b"), programs[receiver], log)
                    try:
                        request = bytes.fromhex(alice.call("start")["wire_hex"])
                        altered, signing_key = changed_request(request, case["mutation"])
                        expected = case["expected_verdict"]
                        result = bob.call("respond", expected, wire_hex=altered.hex())
                        counts = bob.call("http-inspect")
                        assert counts["handshakes"] == (1 if expected == "ACCEPT" else 0)
                        assert counts["records"] == 0
                        assert counts["session"] == ("RESPONSE_SENT" if expected == "ACCEPT" else "NONE")
                        if expected == "ACCEPT":
                            response = bytes.fromhex(result["wire_hex"])
                            independent(request, response)
                        else:
                            assert result == {}
                        report["cases"].append({
                            "id": label, "status": "PASS", "expected_verdict": expected,
                            "observed_handshakes": counts["handshakes"],
                            "observed_records": counts["records"], "signing_test_key": signing_key,
                            "request_sha256": hashlib.sha256(altered).hexdigest(),
                        })
                        save()
                    finally:
                        try:
                            alice.close()
                        finally:
                            bob.close()
        assert len(report["cases"]) == 4 * len(EXPECTED)
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", reason=str(error))
        raise
    finally:
        raw.close()
        report["raw_sha256"] = sha256(output / "raw.jsonl")
        save()
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]),
                      "conformance": report["conformance"]}))


if __name__ == "__main__":
    main()
