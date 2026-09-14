use sage_crypto_core::session::{SecureSession, SessionConfig};
use serde_json::{json, Value};

// Legacy record API projection: the core has no transcript/tuple parameter.
pub fn observe(
    op: &str,
    input: Value,
) -> Result<(&'static str, Value), Box<dyn std::error::Error>> {
    let field = |n: &str| {
        input
            .get(n)
            .and_then(Value::as_str)
            .ok_or("invalid string control")
    };
    let seed = hex::decode(field("seed_hex")?)?;
    let th = hex::decode(field("th_hex")?)?;
    if seed.len() != 32 || th.len() != 32 {
        return Err("invalid trusted key control".into());
    }
    let direction = field("direction")?;
    if direction != "c2s" && direction != "s2c" {
        return Err("invalid direction".into());
    }
    let caller = hex::decode(field("caller_aad_hex")?)?;
    if caller.len() > 4034 {
        return Err("fixture AAD exceeds transport bound".into());
    }
    let sending = op != "sage.session.record.open";
    let core = SecureSession::from_exporter_with_role(
        field("sid")?.into(),
        &seed,
        (direction == "c2s") == sending,
        SessionConfig::default(),
    )?;
    if !sending {
        let wire = hex::decode(field("record_hex")?)?;
        return Ok(match core.decrypt_with_aad_inbound(&wire, &caller) {
            Ok(p) => ("ACCEPT", json!({"plaintext_hex":hex::encode(p)})),
            Err(_) => ("REJECT", json!({})),
        });
    }
    let recipe = input.get("plaintext").ok_or("missing recipe")?;
    let byte = recipe
        .get("byte")
        .and_then(Value::as_u64)
        .filter(|b| *b <= 255)
        .ok_or("invalid byte")?;
    let len = recipe
        .get("length")
        .and_then(Value::as_u64)
        .filter(|n| *n <= 8 * 1024 * 1024 - 35)
        .ok_or("invalid length")?;
    Ok(
        match core.encrypt_with_aad_outbound(&vec![byte as u8; len as usize], &caller) {
            Ok(w) => (
                "ACCEPT",
                if op == "sage.session.record.export" {
                    json!({"record_hex":hex::encode(&w),"record_sha256":sage_crypto_core::hpke::sha256_hash_hex(&w),"record_bytes":w.len()})
                } else {
                    json!({"record_sha256":sage_crypto_core::hpke::sha256_hash_hex(&w),"record_bytes":w.len()})
                },
            ),
            Err(_) => ("REJECT", json!({})),
        },
    )
}
