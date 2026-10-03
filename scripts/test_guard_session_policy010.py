"""Observe policy admission after protected local MCP delivery in current cores."""

import argparse
import copy
import hashlib
import itertools
import json
import subprocess
import tempfile
from pathlib import Path

from test_completion010 import canonical, decode, digest, encode
from test_guard_dispatch010 import expected_effect
from test_guard_results010 import state, validate_storage
from test_guard_session010 import GuardProcess, NODE, Session, VERSION


ROOT = Path(__file__).resolve().parents[1]
SPEC_REVISION = "fa006fd917ad365eb554a27f4178301cd66e2379"
REVISIONS = {
    "go": "fbd9b2169c72d62c62dcbaa2336275d08a5735a8",
    "rust": "0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f",
}
SUITE = ROOT / "vectors/0.10.0/guard-session-policy010.json"
FIXTURE = ROOT / "vectors/0.10.0/guard-rpc.json"
EMPTY_JOURNAL = b"sage-execution-ledger|0.10.0\n"
EXPECTED_CASES = (
    ("allow", True, True, "ACCEPT"),
    ("deny", False, False, "REJECT"),
    ("revoke-after-open", True, False, "REJECT"),
)


def revision(root):
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def check_guard_result(result, allowed, intent):
    expected = {
        "ok": allowed, "created": allowed, "committed": allowed,
        "state": "EXECUTING" if allowed else "",
        "intent_digest": digest_bytes(intent) if allowed else "",
        "effects": [expected_effect(intent, "old")] if allowed else [],
        "result_hex": "", "signs": 0,
    }
    assert result == expected, ("Guard admission mismatch", result)


def digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_public(message, signature, public):
    query = {"message_hex": message.hex(), "signature_hex": signature.hex(), "public": public}
    subprocess.run(["node", "-e", NODE], input=json.dumps(query), text=True,
                   capture_output=True, check=True, timeout=10)


def check_handshake(request, response, alice_public, bob_public):
    initiator = json.loads(request)
    responder = json.loads(response)
    verify_public(b"sage-wire-request|0.10.0\n" + canonical({k: v for k, v in initiator.items()
                                                                 if k != "signature"}),
                  decode(initiator["signature"]), alice_public)
    verify_public(b"sage-wire-response|0.10.0\n" + canonical({k: v for k, v in responder.items()
                                                                  if k != "signature"}),
                  decode(responder["signature"]), bob_public)
    assert responder["message_id"] == initiator["id"]
    assert responder["request_hash"] == encode(hashlib.sha256(request).digest())
    initial = json.loads(decode(initiator["payload"]))
    complete = json.loads(decode(responder["data"]))
    verify_public(b"sage-hpke-complete|0.10.0\n" + canonical({k: v for k, v in complete.items()
                                                               if k != "sigB64"}),
                  decode(complete["sigB64"]), bob_public)
    assert all(complete["transcript"][key] == value for key, value in initial.items())


def check_denied_reply(result):
    assert result == {
        "ok": False, "created": False, "committed": False,
        "state": "", "intent_digest": "", "effects": [],
        "result_hex": "", "signs": 0,
    }, ("denied request produced a reply or effect", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("go", "rust", "spec"):
        parser.add_argument(f"--{name}-root", type=Path, required=True)
    for name in ("go", "rust"):
        parser.add_argument(f"--{name}-session", type=Path, required=True)
        parser.add_argument(f"--{name}-guard", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    suite = json.loads(SUITE.read_text())
    assert suite["schema_version"] == 1 and suite["protocol_version"] == "0.10.0"
    assert tuple((c["id"], c["policy_at_setup"], c["policy_after_open"], c["expected_verdict"])
                 for c in suite["cases"]) == EXPECTED_CASES
    assert all(set(c) == {"id", "policy_at_setup", "policy_after_open", "expected_verdict"}
               for c in suite["cases"])
    assert revision(args.spec_root) == SPEC_REVISION
    fixture = json.loads(FIXTURE.read_text())
    intent = bytes.fromhex(fixture["input"]["envelope_hex"])
    envelope = json.loads(intent)
    assert envelope["intent"]["issuer"] == fixture["input"]["expected_issuer"]
    assert envelope["intent"]["recipient"] == fixture["input"]["expected_recipient"]
    programs = {
        name: {
            "session": getattr(args, f"{name}_session").resolve(strict=True),
            "guard": getattr(args, f"{name}_guard").resolve(strict=True),
        } for name in REVISIONS
    }
    for name, expected in REVISIONS.items():
        core = getattr(args, f"{name}_root")
        assert revision(core) == expected, f"{name} core revision changed"
        assert not subprocess.check_output(["git", "diff", "HEAD", "--"], cwd=core), f"{name} core changed"
        copy_path = core / ("pkg/agent/guard010/testdata/guard-rpc.json" if name == "go"
                            else "src/guard010/testdata/guard-rpc.json")
        assert digest(copy_path) == digest(FIXTURE), f"{name} Guard fixture changed"
    output = args.output.resolve()
    assert not output.is_relative_to(ROOT / "docs/evidence"), "preserve historical evidence"
    assert not output.exists(), "output directory already exists"
    output.mkdir(parents=True)
    report = {
        "kind": "guard-session-policy010-observation", "status": "RUNNING",
        "conformance": "NOT_ESTABLISHED", "deployed_host": "NOT_RUN",
        "scope": suite["scope"], "spec_revision": SPEC_REVISION,
        "suite_sha256": digest(SUITE), "fixture_sha256": digest(FIXTURE),
        "runner_sha256": digest(Path(__file__)),
        "helper_sha256": {name: digest(ROOT / "scripts" / name) for name in (
            "test_completion010.py", "test_guard_session010.py",
            "test_guard_dispatch010.py", "test_guard_results010.py",
        )},
        "subjects": {name: {"revision": REVISIONS[name],
                            "session_sha256": digest(programs[name]["session"]),
                            "guard_sha256": digest(programs[name]["guard"])} for name in REVISIONS},
        "cases": [], "raw": "raw.jsonl",
    }
    raw = (output / "raw.jsonl").open("x")

    def log(value):
        raw.write(json.dumps(value, separators=(",", ":")) + "\n")
        raw.flush()

    def save():
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    save()
    try:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            for sender, receiver in itertools.product(REVISIONS, repeat=2):
                for case in suite["cases"]:
                    label = f"{sender}-to-{receiver}-{case['id']}"
                    alice = Session(label + "-alice", "alice", temp / (label + "-alice"),
                                    programs[sender]["session"], log, profile="guard-fixture")
                    bob = Session(label + "-bob", "bob", temp / (label + "-bob"),
                                  programs[receiver]["session"], log, profile="guard-fixture")
                    journal = temp / (label + "-guard")
                    guard = GuardProcess(programs[receiver]["guard"], journal, "create", label + "-guard", log)
                    try:
                        config = copy.deepcopy(fixture["input"])
                        config["policy_allow"] = case["policy_at_setup"]
                        assert guard.call({"action": "configure", "instance": "old", "input": config})["ok"]
                        assert guard.call({"action": "rpc_setup", "mcp_version": VERSION})["ok"]
                        request = bytes.fromhex(alice.call("start")["wire_hex"])
                        response = bytes.fromhex(bob.call("respond", wire_hex=request.hex())["wire_hex"])
                        alice.call("complete", wire_hex=response.hex())
                        check_handshake(request, response, fixture["input"]["public_key_hex"],
                                        fixture["public_key_hex"])
                        rpc_id = fixture["id"]
                        rpc = b" " + canonical({"jsonrpc": "2.0", "id": rpc_id,
                                                "method": "tools/call", "params": {
                                                    "name": "sage_secure_call", "arguments": {
                                                        "envelope": envelope}}}) + b"\n"
                        wire = bytes.fromhex(alice.call("mcp-seal", target=VERSION,
                                                         message_id=rpc_id, wire_hex=rpc.hex())["wire_hex"])
                        outer = json.loads(wire)
                        proof = decode(outer.pop("signature"))
                        assert outer["did"] == fixture["input"]["expected_issuer"]
                        assert outer["recipient"] == fixture["input"]["expected_recipient"]
                        verify_public(b"sage-wire-request|0.10.0\n" + canonical(outer), proof,
                                      fixture["input"]["public_key_hex"])
                        verify_public(b"sage-execution-intent|0.10.0\0" + canonical(envelope["intent"]),
                                      decode(envelope["proof"]), fixture["input"]["public_key_hex"])
                        opened = bob.call("mcp-open", target=VERSION, wire_hex=wire.hex())
                        assert opened == {"rpc_id": rpc_id, "rpc_hex": rpc.hex()}
                        assert bob.call("record-inspect") == {"state": "ESTABLISHED", "reservations": 1}
                        if case["policy_after_open"] != case["policy_at_setup"]:
                            config["policy_allow"] = case["policy_after_open"]
                            assert guard.call({"action": "configure", "instance": "old", "input": config})["ok"]
                        delivered = guard.call({"action": "rpc_dispatch", "id": opened["rpc_id"],
                                                "envelope_hex": opened["rpc_hex"], "slot": 0})
                        allowed = case["expected_verdict"] == "ACCEPT"
                        check_guard_result(delivered, allowed, intent)
                        if allowed:
                            validate_storage(journal.read_bytes(), intent, [state("RESERVED"), state("EXECUTING")])
                        else:
                            check_denied_reply(guard.call({"action": "rpc_reply", "slot": 0}))
                            assert journal.read_bytes() == EMPTY_JOURNAL, "denied Guard admission wrote a journal row"
                        report["cases"].append({
                            "id": label, "status": "PASS", "expected_verdict": case["expected_verdict"],
                            "transport_reservations": 1, "guard_effects": len(delivered["effects"]),
                            "request_sha256": digest_bytes(rpc), "wire_sha256": digest_bytes(wire),
                            "journal_sha256": digest(journal),
                        })
                        save()
                    finally:
                        try:
                            alice.close()
                        finally:
                            try:
                                bob.close()
                            finally:
                                guard.close()
        assert len(report["cases"]) == 4 * len(EXPECTED_CASES)
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", reason=str(error))
        raise
    finally:
        raw.close()
        report["raw_sha256"] = digest(output / "raw.jsonl")
        save()
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]),
                      "conformance": report["conformance"]}))


if __name__ == "__main__":
    main()
