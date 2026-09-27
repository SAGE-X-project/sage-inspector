# Current-spec record format and complete AAD

SESSION-03 fixes the sequence prefix, derived nonce, ChaCha20-Poly1305 tag,
directional key, and complete AAD construction. A record is 36 bytes through
8 MiB. Caller AAD can be at most 4033 bytes because 63 fixed bytes make the
complete 4096-byte limit. A 4034-byte caller AAD exceeds that limit on both
send and receive.

Eight revision-bound fixtures cover the six SESSION-03 cases and two related
CST-03 boundary cases. They use the independently audited session record
vectors for a known-answer record, a nonconforming nonce with a valid tag,
wrong direction, changed caller AAD, the 4097-byte AAD, a short record,
an oversized plaintext recipe, and exact 4033/4034-byte sender/receiver
boundaries. A bounded bridge combines the paired short/oversized and AAD
observations without implementing record cryptography in Inspector.

Core record acceptance or rejection is a cryptographic and size-bound
observation. It does not prove that the transport layer creates caller AAD
from the specified JCS projection, verifies the signed envelope and pinned
tuple, or prevents protected effects after a rejected record. Those portions
need an instrumented receiver and remain outside the present primitive
adapter evidence. The independent Node audit validates fixture calculations,
not core behavior.
