# Fixture provenance

The frozen expected bytes in0.10.0/foundation.json are attributed per case.

- RFC5869 Appendix A.1–A.3: HKDF SHA-256 inputs, PRK and OKM.
- RFC6234: SHA-256 abc expected digest.
- RFC4648 sections3.5,5,10: encoding rules and examples, adapted to the explicitly
  unpadded SAGE profile. Invalid pad bits/padding are rule-derived negative cases.
- sage-spec02/08: syntax and canonical binary-encoding rejection requirements.

RFC texts are published by the RFC Editor under the IETF Trust terms linked from
those publications. See https://trustee.ietf.org/license-info . These fixtures
contain selected test data and source attribution, not copied implementations.
Expected values are never regenerated from the SAGE core. New fixtures must record
an independent source/derivation; changing version strings does not update old vectors.

The jcs-signatures suite adds RFC8032 section7.1 public bytes, RFC8785 numeric
examples and test-only mathematical constructions. Attribution and independent
checks are described in ../docs/jcs-signature-vectors.md.

HTTP fixtures use synthetic messages, a public RFC8032 test seed and independently
constructed RFC9421 bases and SHA-256 Content-Digest values. See ../docs/http-signature-vectors.md.

HPKE fixtures include selected RFC9180 Appendix A.2.1 public test private keys and
exported values, RFC5869 Appendix A.1 HKDF anchors, and synthetic SAGE0.10.0
transcripts using public deterministic test entropy. No production secrets are used.
See ../docs/hpke-inspection.md for independent derivation and scope.

The reconciled REG-08 media fixture is an exact pinned copy of the SAGE
0.10.0 normative design's `verification/vectors/web-registry-media-0.10.0.json`
at `sage-spec` revision `dcdd028b5160de5e32eb1f43cf1f71eed3fc4744`.
Inspector checks its source bytes and independently evaluates the bounded
header decisions. Those expected values do not come from either core, and
the fixture is not evidence of a complete web Registry read.

The strict Registry Gate identity suite is manually classified from
`sage-spec` revision `fa006fd917ad365eb554a27f4178301cd66e2379`
ID-01, ID-02 and the key-reference parsing step of ID-03. Its canonical
eip155 identifier and key name are synthetic. Expected journal state is
derived from the rule that malformed identifiers are rejected before
authoritative observation; it is not copied from either core.

The Registry key-selection suite is manually classified from the same
`sage-spec` revision, ID-03 and REG-02. Its key status and expiry boundaries,
no-substitution expectations and journal effects are fixed independently of
the cores. The additional public Ed25519 key is derived from the public test
seed consisting of 32 bytes of `0x11`; no production key material is used.
