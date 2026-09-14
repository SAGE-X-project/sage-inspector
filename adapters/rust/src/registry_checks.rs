use sage_crypto_core::{crypto::KeyType, did};
use serde_json::{json, Value};
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
    let id = field("did")?;
    let valid = if op == "sage.did.validate" {
        did::validate_did(id)
    } else {
        if field("alg")? != "ed25519" {
            return Ok(("UNSUPPORTED", json!({})));
        }
        field("name")?;
        did::verify_key_pop(
            id,
            KeyType::Ed25519,
            &hex::decode(field("public_key_hex")?)?,
            &hex::decode(field("signature_hex")?)?,
        )
        .is_ok()
    };
    Ok(if valid {
        ("ACCEPT", json!({"valid":true}))
    } else {
        ("REJECT", json!({}))
    })
}
