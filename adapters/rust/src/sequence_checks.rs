use sage_crypto_core::session::{SecureSession, Session, SessionConfig};
use serde_json::{json, Value};

// Core-owned replay/lifecycle state persists for the entire batch.
pub fn observe(
    op: &str,
    input: Value,
) -> Result<(&'static str, Value), Box<dyn std::error::Error>> {
    let field = |name| {
        input
            .get(name)
            .and_then(Value::as_str)
            .ok_or("missing sequence control")
    };
    let seed = hex::decode(field("seed_hex")?)?;
    let direction = field("direction")?;
    let sid = field("sid")?;
    let aad = hex::decode(field("caller_aad_hex")?)?;
    if seed.len() != 32
        || sid.is_empty()
        || !["c2s", "s2c"].contains(&direction)
        || aad.len() > 1024
    {
        return Err("invalid sequence controls".into());
    }
    let sending = op == "legacy.session.export-sequence";
    let mut core = SecureSession::from_exporter_with_role(
        sid.into(),
        &seed,
        (direction == "c2s") == sending,
        SessionConfig::default(),
    )?;
    if sending {
        let messages = input
            .get("messages_hex")
            .and_then(Value::as_array)
            .ok_or("missing messages")?;
        if messages.is_empty() || messages.len() > 16 {
            return Err("invalid batch size".into());
        }
        let mut records = Vec::new();
        for message in messages {
            let plain = hex::decode(message.as_str().ok_or("invalid message")?)?;
            if plain.len() > 512 {
                return Err("invalid message size".into());
            }
            match core.encrypt_with_aad_outbound(&plain, &aad) {
                Ok(record) => records.push(hex::encode(record)),
                Err(_) => return Ok(("REJECT", json!({}))),
            }
        }
        return Ok(("ACCEPT", json!({"records_hex":records})));
    }
    let actions = input
        .get("actions")
        .and_then(Value::as_array)
        .ok_or("missing actions")?;
    if actions.is_empty() || actions.len() > 32 {
        return Err("invalid batch size".into());
    }
    let mut results = Vec::new();
    for action in actions {
        match action.get("kind").and_then(Value::as_str) {
            Some("parallel_open") => {
                results.push(crate::parallel_checks::open(
                    &core,
                    action
                        .get("records_hex")
                        .ok_or("missing parallel records")?,
                    &aad,
                )?);
            }
            Some("close") => {
                core.close()?;
                results.push(json!({"verdict":"ACCEPT","output":{}}));
            }
            Some("open") => {
                let record = hex::decode(
                    action
                        .get("record_hex")
                        .and_then(Value::as_str)
                        .ok_or("missing record")?,
                )?;
                if record.len() > 2048 {
                    return Err("invalid record size".into());
                }
                results.push(match core.decrypt_with_aad_inbound(&record, &aad) {
                    Ok(plain) => {
                        json!({"verdict":"ACCEPT","output":{"plaintext_hex":hex::encode(plain)}})
                    }
                    Err(_) => json!({"verdict":"REJECT","output":{}}),
                });
            }
            _ => return Err("unknown sequence action".into()),
        }
    }
    Ok(("ACCEPT", json!({"results":results})))
}
