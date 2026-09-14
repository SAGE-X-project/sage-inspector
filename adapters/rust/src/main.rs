mod hpke_checks;
mod http_checks;
mod session_checks;
use sage_crypto_core::crypto::{KeyType, PublicKey, Signature, Verifier};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    protocol_version: String,
    profile: String,
    case_id: String,
    operation: String,
    input: Value,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin().take((4 << 20) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 4 << 20 {
        return Err("oversized request".into());
    }
    let q: Request = serde_json::from_slice(&bytes)?;
    if q.schema_version != 1
        || q.protocol_version != "0.10.0"
        || q.profile != "primitive-foundation"
        || q.case_id.is_empty()
    {
        return Err("invalid request".into());
    }
    let (verdict, output) = if [
        "rfc9421.base",
        "sage.content-digest",
        "rfc9421.archived.verify",
        "sage.http.verify",
    ]
    .contains(&q.operation.as_str())
    {
        http_checks::observe(&q.operation, q.input)?
    } else if ["rfc9180.export", "sage.hpke.combine", "x25519.exchange"]
        .contains(&q.operation.as_str())
    {
        hpke_checks::observe(&q.operation, q.input)?
    } else if ["sage.session.record.open", "sage.session.record.seal"]
        .contains(&q.operation.as_str())
    {
        session_checks::observe(&q.operation, q.input)?
    } else if q.operation == "sha256" {
        let data = hex::decode(
            q.input
                .get("data_hex")
                .and_then(Value::as_str)
                .ok_or("missing data_hex")?,
        )?;
        (
            "ACCEPT",
            json!({"sha256_hex":sage_crypto_core::hpke::sha256_hash_hex(&data)}),
        )
    } else if q.operation == "json.syntax" || q.operation == "jcs.canonicalize" {
        let data = hex::decode(
            q.input
                .get("document_hex")
                .and_then(Value::as_str)
                .ok_or("missing document_hex")?,
        )?;
        match sage_crypto_core::jcs::canonicalize(&data) {
            Ok(value) => (
                "ACCEPT",
                if q.operation == "json.syntax" {
                    json!({"valid":true})
                } else {
                    json!({"canonical_hex":hex::encode(value)})
                },
            ),
            Err(_) => ("REJECT", json!({})),
        }
    } else if q.operation == "signature.verify" {
        let field = |name| {
            q.input
                .get(name)
                .and_then(Value::as_str)
                .ok_or("missing signature input")
        };
        let alg = field("algorithm")?;
        let kind = match alg {
            "ed25519" => Some(KeyType::Ed25519),
            "ecdsa-p256-sha256" => Some(KeyType::P256),
            "sage-secp256k1-keccak256" => Some(KeyType::Secp256k1),
            _ => None,
        };
        if let Some(kind) = kind {
            let pk = hex::decode(field("public_key_hex")?)?;
            let sig = hex::decode(field("signature_hex")?)?;
            let msg = hex::decode(field("message_hex")?)?;
            let valid = PublicKey::from_bytes(kind, &pk)
                .and_then(|key| {
                    Signature::from_bytes(kind, &sig)
                        .and_then(|signature| key.verify(&msg, &signature))
                })
                .is_ok();
            if valid {
                ("ACCEPT", json!({"valid":true}))
            } else {
                ("REJECT", json!({}))
            }
        } else {
            ("UNSUPPORTED", json!({}))
        }
    } else {
        ("UNSUPPORTED", json!({}))
    };
    println!(
        "{}",
        json!({"schema_version":1,"case_id":q.case_id,"verdict":verdict,"output":output})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(2)
    }
}
