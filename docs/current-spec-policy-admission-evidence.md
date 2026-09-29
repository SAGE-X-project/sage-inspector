# Current-spec policy admission observations

The [two signed intent fixtures](../vectors/0.10.0/exec-policy-admission.json)
separate a claimed digest from trusted local authorization. `EXEC-02-N03`
has a matching approved policy digest but a local policy denial. `CST-02-05`
is validly signed yet names a policy digest other than the locally approved
mapping. The independent checker verifies both signatures and the exact
policy commitments.

Pinned Go and Rust primitive adapters reject both inputs. The
[revision-bound observations](evidence/current-spec/exec-policy-admission/)
are `PARTIAL`; reassess them with
`python3 -B scripts/check_current_spec_policy_admission_evidence.py`.
The primitive seam does not observe host policy-store isolation, a peer's
attempt to install a mapping, epoch administration, or a deployed effect path.
