"""Observe bounded HTTP handshake identity checks with public fixture keys only."""

import argparse
import base64
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile

from http_tls010 import parse, render
from test_completion010 import Actor, ROOT, digest, independent, verify
from test_http_handshake010 import configure, observe, wire
from test_http_session010 import audit, body, headers, mutate, resign, signature_base


SUITE = ROOT / "vectors/0.10.0/http-handshake-identity010.json"
COMPLETION = ROOT / "vectors/0.10.0/completion010.json"
SPEC_REVISION = "fa006fd917ad365eb554a27f4178301cd66e2379"
REVISIONS = {
    "go": "fbd9b2169c72d62c62dcbaa2336275d08a5735a8",
    "rust": "0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f",
}
TARGET = "https://agent.example/messages"
EXPECTED = (
    ("valid", "request", "none", "ACCEPT"),
    ("request-did-header", "request", "did", "REJECT"),
    ("request-keyid", "request", "wrong-keyid", "REJECT"),
    ("request-algorithm", "request", "wrong-alg", "REJECT"),
    ("request-other-signer", "request", "other-signer", "REJECT"),
    ("response-did-header", "response", "did", "REJECT"),
    ("response-keyid", "response", "wrong-keyid", "REJECT"),
    ("response-algorithm", "response", "wrong-alg", "REJECT"),
    ("response-other-signer", "response", "other-signer", "REJECT"),
)


def revision(path):
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


def altered(message, mutation, key, request=None):
    if mutation == "other-signer":
        result = json.loads(json.dumps(message))
        resign(result, 3 - key, request)
    else:
        result = mutate(message, mutation, key, request)
    # The independent test key verifies the HTTP signature even for a
    # semantically invalid DID, algorithm or keyid declaration.
    actual_key = 3 - key if mutation == "other-signer" else key
    signature = base64.b64decode(headers(result)["signature"][6:-1], validate=True)
    verify(signature_base(result, request), signature, actual_key)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("go", "rust", "spec"):
        parser.add_argument(f"--{name}-root", required=True, type=Path)
    for name in ("go", "rust"):
        parser.add_argument(f"--{name}-adapter", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    suite = json.loads(SUITE.read_text())
    assert suite["schema_version"] == 1 and suite["protocol_version"] == "0.10.0"
    assert tuple((c["id"], c["phase"], c["mutation"], c["expected_verdict"]) for c in suite["cases"]) == EXPECTED
    assert all(set(c) == {"id", "phase", "mutation", "expected_verdict"} for c in suite["cases"])
    assert revision(args.spec_root) == SPEC_REVISION
    programs = {name: getattr(args, f"{name}_adapter").resolve() for name in REVISIONS}
    for name, expected in REVISIONS.items():
        root = getattr(args, f"{name}_root")
        assert revision(root) == expected, f"{name} core revision changed"
        assert not subprocess.check_output(["git", "diff", "HEAD", "--"], cwd=root), f"{name} core source changed"
        copy = root / ("pkg/agent/hpke/testdata/completion010.json" if name == "go" else "tests/fixtures/completion010.json")
        assert digest(copy) == digest(COMPLETION), f"{name} handshake fixture changed"
    output = args.output.resolve()
    assert not output.exists(), "output directory already exists"
    output.mkdir(parents=True)
    report = {
        "kind": "http-handshake-identity010-observation", "status": "RUNNING",
        "conformance": "NOT_ESTABLISHED", "scope": suite["scope"],
        "spec_revision": SPEC_REVISION, "suite_sha256": digest(SUITE),
        "completion_fixture_sha256": digest(COMPLETION),
        "runner_sha256": digest(Path(__file__)),
        "helper_sha256": {
            name: digest(ROOT / "scripts" / name) for name in (
                "test_completion010.py", "test_http_handshake010.py",
                "test_http_session010.py", "http_tls010.py",
            )
        },
        "subjects": {name: {"revision": REVISIONS[name], "executable_sha256": digest(program)}
                     for name, program in programs.items()},
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
                        configure(alice, bob, TARGET)
                        request = wire(alice, "http-start")
                        request_message = parse(request, TARGET)
                        audit(request_message, 1)
                        if case["phase"] == "request" and case["mutation"] != "none":
                            message = altered(request_message, case["mutation"], 1)
                            altered_wire = render(message)
                            bob.call("http-respond-raw", "REJECT", wire_hex=altered_wire.hex())
                            observe(bob, 0, 0, "NONE")
                        else:
                            response = wire(bob, "http-respond-raw", wire_hex=request.hex())
                            response_message = parse(response, TARGET, True)
                            audit(response_message, 2, request_message)
                            independent(body(request_message), body(response_message))
                            observe(bob, 1, 0, "RESPONSE_SENT")
                            if case["phase"] == "response":
                                response_message = altered(response_message, case["mutation"], 2, request_message)
                                response = render(response_message)
                                altered_wire = response
                                alice.call("http-complete-raw", "REJECT", wire_hex=response.hex())
                                counts = observe(alice, 0, 0, "NONE")
                                assert counts["pending"] == "CLOSED"
                            else:
                                alice.call("http-complete-raw", wire_hex=response.hex())
                                observe(alice, 1, 0, "ESTABLISHED")
                                altered_wire = request
                        report["cases"].append({"id": label, "status": "PASS", "expected_verdict": case["expected_verdict"], "observed_wire_sha256": hashlib.sha256(altered_wire).hexdigest()})
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
        report["raw_sha256"] = digest(output / "raw.jsonl")
        save()
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "conformance": report["conformance"]}))


if __name__ == "__main__":
    main()
