# Current-spec key-withdrawal replay observation

The [signed replay fixture](../vectors/0.10.0/exec-key-rotation.json) commits
one inert dispatch with an active key, then reopens the same local ledger after
the trusted key authority marks that key inactive. The exact original signed
intent is offered again. Both pinned Go and Rust cores reject that second
attempt, record `UNKNOWN`, and make no additional dispatch. The independent
checker verifies the signature, exact replay bytes, and that key activity is
the only changed authority input.

The [revision-bound observations](evidence/current-spec/exec-key-rotation/)
are `PARTIAL`; reassess with
`python3 -B scripts/check_current_spec_key_rotation_evidence.py`.
They do not establish a distributed rotation source, real transport, or
external tool effects.
