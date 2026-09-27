# Current-spec directional session keys and lifetime

SESSION-02 derives separate c2s and s2c record keys with a fixed generation
change at every 256 sequence numbers. The receiver rejects sequence 1000 and
the sender closes before emitting it. Absolute session age is at most one
hour, idle age at most ten minutes, and responder confirmation cannot restart
the clocks created with provisional key state.

Six revision-bound fixtures cover five SESSION-02 cases and the related
CST-05 confirmation-clock case. The positive fixture opens independently
computed records at sequences 255, 256, and 999 in both directions against
each actual core. A separate fixture opens a validly formed sequence-1000
record and expects rejection. The remaining cases bind exact absolute and
idle clock boundaries, fixed rekey configuration, and provisional
confirmation timing to independently audited state scenarios.

Record opening proves the key schedule and receiver's sequence cap only for
the tested records. It does not prove independent live counters, sender-side
closure, full envelope validation, or monotonic session lifetime. Current
primitive adapters expose no clock, policy, or provisional-state verifier,
so those cases remain `UNSUPPORTED`. The independent session audit checks
fixture expectations rather than core behavior.
