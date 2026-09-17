use sage_crypto_core::hpke;
use serde_json::{json, Value};

type Error = Box<dyn std::error::Error>;

pub fn observe(op: &str, input: Value) -> Result<(&'static str, Value), Error> {
    let names: &[&str] = match op {
        "sage.hpke.schedule010.combine" => &["exporter_hex", "ss_e2e_hex", "th_hex"],
        "sage.hpke.schedule010.ack" => &["seed_hex", "th_hex"],
        "sage.hpke.schedule010.verify" => &["seed_hex", "th_hex", "ack_tag_hex"],
        _ => return Ok(("UNSUPPORTED", json!({}))),
    };
    let obj = input.as_object().ok_or("invalid schedule input")?;
    if obj.len() != names.len() {
        return Err("invalid schedule input fields".into());
    }
    let values: Vec<Vec<u8>> = names
        .iter()
        .map(|name| {
            hex::decode(
                obj.get(*name)
                    .and_then(Value::as_str)
                    .ok_or("invalid schedule input")?,
            )
            .map_err(|_| -> Error { "invalid schedule input hex".into() })
        })
        .collect::<Result<_, Error>>()?;
    if op == "sage.hpke.schedule010.verify" {
        return Ok(
            if hpke::verify_ack_tag_010(&values[0], &values[1], &values[2]) {
                ("ACCEPT", json!({"valid": true}))
            } else {
                ("REJECT", json!({}))
            },
        );
    }
    let result = if op == "sage.hpke.schedule010.combine" {
        hpke::combine_secrets_010(&values[0], &values[1], &values[2])
            .map(|seed| json!({"seed_hex": hex::encode(&*seed)}))
    } else {
        hpke::make_ack_tag_010(&values[0], &values[1])
            .map(|tag| json!({"ack_tag_hex": hex::encode(tag)}))
    };
    Ok(match result {
        Ok(output) => ("ACCEPT", output),
        Err(_) => ("REJECT", json!({})),
    })
}
