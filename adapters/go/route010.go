package main

// profile010 observes 0.10.0 entry points only. Fixture operations named
// after historical core calls route to their 0.10.0 replacements; operations
// whose only core implementation is a legacy API are reported UNSUPPORTED.
// RFC 9421 operations keep the core rfc9421 package, which has no 0.10.0
// replacement and implements the 0.10.0 message rules.
const profile010 = "primitive-foundation-010"

// route010 returns the operation to evaluate under profile010, or "" for
// UNSUPPORTED. ok is false for operations that already use a current API.
func route010(op string) (routed string, ok bool) {
	switch op {
	case "json.syntax", "jcs.canonicalize":
		return op + ".guard010", true
	case "sage.did.validate":
		if !strictDID010 {
			return "", true
		}
		return "sage.did.validate010", true
	case "sage.hpke.combine":
		return "sage.hpke.schedule010.combine", true
	case "sage.session.record.open", "sage.session.record.seal", "sage.session.record.export",
		"legacy.session.export-sequence", "legacy.session.receive-sequence",
		// Legacy SAGE-PoP has no 0.10.0 verifier; registry010 only builds the
		// 0.10.0 challenge bytes.
		"sage.registry.pop.verify":
		return "", true
	}
	return "", false
}
