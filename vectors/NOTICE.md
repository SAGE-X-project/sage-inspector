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
