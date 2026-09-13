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
    let (verdict, output) = if q.operation == "sha256" {
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
    } else if q.operation == "json.syntax" {
        let data = hex::decode(
            q.input
                .get("document_hex")
                .and_then(Value::as_str)
                .ok_or("missing document_hex")?,
        )?;
        match sage_crypto_core::jcs::canonicalize(&data) {
            Ok(_) => ("ACCEPT", json!({"valid":true})),
            Err(_) => ("REJECT", json!({})),
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
