"""Observe MCP session peer and key bindings using fixed public test keys."""

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile

from test_completion010 import Actor, ALICE, BOB, ROOT, canonical, decode, digest, encode, independent, sign, verify
from test_mcp_session010 import VERSION, rpc_fixture, response


SUITE = ROOT / "vectors/0.10.0/mcp-session-identity010.json"
COMPLETION = ROOT / "vectors/0.10.0/completion010.json"
SPEC_REVISION = "fa006fd917ad365eb554a27f4178301cd66e2379"
REVISIONS = {
    "go": "fbd9b2169c72d62c62dcbaa2336275d08a5735a8",
    "rust": "0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f",
}
EXPECTED = (
    ("valid", "request", "none", "ACCEPT"),
    ("request-did", "request", "did", "REJECT"),
    ("request-key", "request", "kid", "REJECT"),
    ("request-recipient", "request", "recipient", "REJECT"),
    ("request-role", "request", "role", "REJECT"),
    ("request-other-signer", "request", "other-signer", "REJECT"),
    ("response-did", "response", "did", "REJECT"),
    ("response-key", "response", "kid", "REJECT"),
    ("response-recipient", "response", "recipient", "REJECT"),
    ("response-role", "response", "role", "REJECT"),
    ("response-other-signer", "response", "other-signer", "REJECT"),
)
DOMAINS = {
    "request": b"sage-wire-request|0.10.0\n",
    "response": b"sage-wire-response|0.10.0\n",
}


def revision(path):
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


def verify_outer(raw, phase, key):
    message = json.loads(raw)
    signature = decode(message.pop("signature"))
    verify(DOMAINS[phase] + canonical(message), signature, key)


def signed_outer(raw, phase, mutation, key):
    message = json.loads(raw)
    assert message["did"] == (ALICE if key == 1 else BOB)
    assert message["recipient"] == (BOB if key == 1 else ALICE)
    if mutation == "did":
        message["did"] = message["recipient"]
    elif mutation == "kid":
        message["kid"] = message["did"] + "#other"
    elif mutation == "recipient":
        message["recipient"] = message["did"]
    elif mutation == "role":
        message["role"] = "responder" if key == 1 else "initiator"
    elif mutation != "other-signer":
        raise AssertionError(mutation)
    message.pop("signature")
    actual_key = 3 - key if mutation == "other-signer" else key
    message["signature"] = encode(sign(DOMAINS[phase] + canonical(message), actual_key))
    changed = canonical(message)
    verify_outer(changed, phase, actual_key)
    return changed


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
        "kind": "mcp-session-identity010-observation", "status": "RUNNING",
        "conformance": "NOT_ESTABLISHED", "scope": suite["scope"],
        "spec_revision": SPEC_REVISION, "suite_sha256": digest(SUITE),
        "completion_fixture_sha256": digest(COMPLETION),
        "runner_sha256": digest(Path(__file__)),
        "helper_sha256": {name: digest(ROOT / "scripts" / name) for name in (
            "test_completion010.py", "test_mcp_session010.py",
        )},
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
        intent = rpc_fixture()
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            for sender, receiver in itertools.product(programs, repeat=2):
                for case in suite["cases"]:
                    label = f"{sender}-to-{receiver}-{case['id']}"
                    alice = Actor(label + "-init", "alice", temp / (label + "-a"), programs[sender], log)
                    bob = Actor(label + "-resp", "bob", temp / (label + "-b"), programs[receiver], log)
                    try:
                        request = alice.call("start")["wire_hex"]
                        handshake = bob.call("respond", wire_hex=request)["wire_hex"]
                        alice.call("complete", wire_hex=handshake)
                        independent(bytes.fromhex(request), bytes.fromhex(handshake))
                        rpc_id = "00000000-0000-4000-8000-000000000101"
                        rpc = b" " + canonical({"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call", "params": {
                            "name": "sage_secure_call", "arguments": {"envelope": intent},
                        }}) + b"\n"
                        request_wire = bytes.fromhex(alice.call("mcp-seal", target=VERSION, message_id=rpc_id, wire_hex=rpc.hex())["wire_hex"])
                        verify_outer(request_wire, "request", 1)
                        expected_wire = request_wire
                        if case["phase"] == "request" and case["mutation"] != "none":
                            expected_wire = signed_outer(request_wire, "request", case["mutation"], 1)
                            bob.call("mcp-open", "REJECT", target=VERSION, wire_hex=expected_wire.hex())
                            assert bob.call("record-inspect") == {"state": "RESPONSE_SENT", "reservations": 0}
                        opened = bob.call("mcp-open", target=VERSION, wire_hex=request_wire.hex())
                        assert opened == {"rpc_id": rpc_id, "rpc_hex": rpc.hex()}
                        assert bob.call("record-inspect") == {"state": "ESTABLISHED", "reservations": 1}
                        reply = b" " + canonical(response(intent, rpc_id, "completed")) + b"\n"
                        response_wire = bytes.fromhex(bob.call("mcp-reply", message_id=rpc_id, wire_hex=reply.hex())["wire_hex"])
                        verify_outer(response_wire, "response", 2)
                        if case["phase"] == "response":
                            expected_wire = signed_outer(response_wire, "response", case["mutation"], 2)
                            alice.call("mcp-open-reply", "REJECT", message_id=rpc_id, wire_hex=expected_wire.hex())
                            assert alice.call("record-inspect") == {"state": "ESTABLISHED", "reservations": 0}
                        opened_reply = alice.call("mcp-open-reply", message_id=rpc_id, wire_hex=response_wire.hex())
                        assert bytes.fromhex(opened_reply["wire_hex"]) == reply
                        assert alice.call("record-inspect") == {"state": "ESTABLISHED", "reservations": 1}
                        report["cases"].append({
                            "id": label, "status": "PASS", "expected_verdict": case["expected_verdict"],
                            "observed_wire_sha256": hashlib.sha256(expected_wire).hexdigest(),
                            "request_reservations": 1, "response_reservations": 1,
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
        report["raw_sha256"] = digest(output / "raw.jsonl")
        save()
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "conformance": report["conformance"]}))


if __name__ == "__main__":
    main()
