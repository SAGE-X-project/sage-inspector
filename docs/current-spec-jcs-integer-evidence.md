# Current-spec protocol integer observations

Five `JCS-02` fixtures use valid Ed25519-signed Guard intent envelopes. Each
negative fixture contains a signed control that the receiving core must accept
and a separately signed candidate changing exactly one protocol integer field.
The positive fixture exercises the largest permitted safe integer. Inspector
does not send the expected outcome to either core. OpenSSL independently
verifies every control and candidate signature before the observations are
admitted; no signing private key is stored in this repository.

| Case | Changed condition | Go `sage` | Rust `rs-sage-core` |
| --- | --- | --- | --- |
| JCS-02-P | Safe upper boundary | PARTIAL | PARTIAL |
| JCS-02-N01 | Fractional `created` | PARTIAL | PARTIAL |
| JCS-02-N02 | Negative `created` | PARTIAL | PARTIAL |
| JCS-02-N03 | `expires` above safe range | PARTIAL | PARTIAL |
| JCS-02-N04 | String `created` | PARTIAL | PARTIAL |

All controls were accepted and all negative candidates were rejected. These
results establish only the sampled Guard intent field path. They do not cover
every protocol structure or protected dispatch effect, so none is a full
JCS-02 pass. The [preserved twelve-case Go/Rust run](evidence/current-spec/jcs-integers/)
also includes the seven JCS-01 fixtures. Its assessed Go result is four `FAIL`,
eight `PARTIAL`, and 469 `NOT_RUN`; Rust is two `FAIL`, ten `PARTIAL`, and 469
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`. Recheck the signed
vectors and raw observations with
`python3 -B scripts/check_current_spec_jcs_integer_evidence.py`.
