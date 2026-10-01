//! Isolated Inspector adapter for the strict 0.10.0 DID parser.

use sage_crypto_core::did::{parse_did_010, parse_did_url_010};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u8,
    protocol_version: String,
    profile: String,
    case_id: String,
    operation: String,
    input: Value,
}

#[derive(Serialize)]
struct Response {
    schema_version: u8,
    case_id: String,
    verdict: &'static str,
    output: Value,
}

fn run(input: &str) -> Result<Response, String> {
    let request: Request = serde_json::from_str(input).map_err(|error| error.to_string())?;
    if request.schema_version != 1
        || request.protocol_version != "0.10.0"
        || request.profile != "primitive-foundation"
        || request.case_id.is_empty()
    {
        return Err("invalid inspector request".into());
    }
    let fields = request.input.as_object().ok_or("invalid inspector input")?;
    let (verdict, output) = match request.operation.as_str() {
        "sage.did010.parse" => {
            if fields.len() != 1 {
                return Err("invalid DID input".into());
            }
            let raw = fields
                .get("did")
                .and_then(Value::as_str)
                .ok_or("invalid DID input")?;
            match parse_did_010(raw) {
                Ok(did) => (
                    "ACCEPT",
                    json!({"kind": did.kind, "locator": did.locator, "agent_id": did.agent_id}),
                ),
                Err(_) => ("REJECT", json!({})),
            }
        }
        "sage.did-url010.parse" => {
            if fields.len() != 1 {
                return Err("invalid DID URL input".into());
            }
            let raw = fields
                .get("did_url")
                .and_then(Value::as_str)
                .ok_or("invalid DID URL input")?;
            match parse_did_url_010(raw) {
                Ok(url) => (
                    "ACCEPT",
                    json!({"kind": url.did.kind, "locator": url.did.locator,
                        "agent_id": url.did.agent_id, "key_id": url.key_id}),
                ),
                Err(_) => ("REJECT", json!({})),
            }
        }
        _ => return Err("unsupported inspector operation".into()),
    };
    Ok(Response {
        schema_version: 1,
        case_id: request.case_id,
        verdict,
        output,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = String::new();
    io::stdin().take((4 << 20) + 1).read_to_string(&mut data)?;
    if data.len() > 4 << 20 {
        return Err("inspector request exceeds 4 MiB".into());
    }
    let response = run(&data)?;
    serde_json::to_writer(io::stdout(), &response)?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn accepts_canonical_did_and_rejects_legacy_alias() {
        let request = |did: &str| {
            format!(
                "{{\"schema_version\":1,\"protocol_version\":\"0.10.0\",\"profile\":\"primitive-foundation\",\"case_id\":\"one\",\"operation\":\"sage.did010.parse\",\"input\":{{\"did\":\"{did}\"}}}}"
            )
        };
        assert_eq!(
            run(&request("did:sage:web:example.com:agent"))
                .unwrap()
                .verdict,
            "ACCEPT"
        );
        assert_eq!(
            run(&request("did:sage:ETH:0xabc")).unwrap().verdict,
            "REJECT"
        );
    }
}
