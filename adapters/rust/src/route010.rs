//! The `primitive-foundation-010` profile observes 0.10.0 entry points only.
//! Fixture operations named after historical core calls route to their 0.10.0
//! replacements; operations whose only core implementation is a legacy API are
//! reported UNSUPPORTED. RFC 9421 operations keep the core `rfc9421` module,
//! which has no 0.10.0 replacement and implements the 0.10.0 message rules.
pub const PROFILE: &str = "primitive-foundation-010";

/// `None` keeps the operation, `Some(None)` is UNSUPPORTED and
/// `Some(Some(op))` evaluates `op` instead.
pub fn route(op: &str) -> Option<Option<&'static str>> {
    match op {
        "json.syntax" => Some(Some("json.syntax.guard010")),
        "jcs.canonicalize" => Some(Some("jcs.canonicalize.guard010")),
        // Without `strictdid010` the core may predate the 0.10.0 DID parser.
        "sage.did.validate" if cfg!(feature = "strictdid010") => Some(Some("sage.did.validate010")),
        "sage.did.validate" => Some(None),
        "sage.hpke.combine" => Some(Some("sage.hpke.schedule010.combine")),
        "sage.session.record.open"
        | "sage.session.record.seal"
        | "sage.session.record.export"
        | "legacy.session.export-sequence"
        | "legacy.session.receive-sequence"
        // Legacy SAGE-PoP has no 0.10.0 verifier; registry010 only builds the
        // 0.10.0 challenge bytes.
        | "sage.registry.pop.verify"
        // The general X25519 primitive returns an all-zero shared value; the
        // 0.10.0 derivation rejects it internally and exposes no standalone
        // exchange.
        | "x25519.exchange" => Some(None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::route;

    #[test]
    fn historical_operations_route_to_010_entry_points() {
        assert_eq!(
            route("jcs.canonicalize"),
            Some(Some("jcs.canonicalize.guard010"))
        );
        assert_eq!(route("json.syntax"), Some(Some("json.syntax.guard010")));
        assert_eq!(
            route("sage.hpke.combine"),
            Some(Some("sage.hpke.schedule010.combine"))
        );
        assert_eq!(route("sage.http.verify"), None);
    }

    #[test]
    fn legacy_only_operations_are_unsupported() {
        for op in [
            "sage.session.record.open",
            "sage.session.record.seal",
            "sage.session.record.export",
            "legacy.session.export-sequence",
            "legacy.session.receive-sequence",
            "sage.registry.pop.verify",
            "x25519.exchange",
        ] {
            assert_eq!(route(op), Some(None), "{op}");
        }
    }

    #[test]
    fn did_route_follows_strictdid010_feature() {
        let expected = if cfg!(feature = "strictdid010") {
            Some(Some("sage.did.validate010"))
        } else {
            Some(None)
        };
        assert_eq!(route("sage.did.validate"), expected);
    }
}
