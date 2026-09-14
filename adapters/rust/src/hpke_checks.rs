use sage_crypto_core::{crypto::X25519KeyPair, hpke};
use serde_json::{json, Value};

type Error = Box<dyn std::error::Error>;

pub fn observe(op: &str, input: Value) -> Result<(&'static str, Value), Error> {
    let decode = |name| -> Result<Vec<u8>, Error> {
        Ok(hex::decode(
            input
                .get(name)
                .and_then(Value::as_str)
                .ok_or("missing HPKE input")?,
        )?)
    };
    let (result, field) = match op {
        "rfc9180.export" => {
            let private: [u8; 32] = decode("private_key_hex")?
                .try_into()
                .map_err(|_| "invalid private control")?;
            let enc = decode("enc_hex")?;
            let info = decode("info_hex")?;
            let context = decode("export_context_hex")?;
            (
                hpke::kem_open(&private, &enc, &info, &context).map(|v| v.to_vec()),
                "exporter_hex",
            )
        }
        "sage.hpke.combine" => {
            let exporter = decode("exporter_hex")?;
            let shared = decode("ss_e2e_hex")?;
            let th = decode("th_hex")?;
            // Preserve the selected API's actual old schedule and validation behavior.
            (
                hpke::combine_secrets(&exporter, &shared, &th).map(|v| v.to_vec()),
                "seed_hex",
            )
        }
        "x25519.exchange" => {
            let private = decode("private_key_hex")?;
            let public = decode("public_key_hex")?;
            let pair = X25519KeyPair::from_bytes(&private)?;
            (pair.diffie_hellman(&public), "shared_secret_hex")
        }
        _ => return Ok(("UNSUPPORTED", json!({}))),
    };
    Ok(match result {
        Ok(bytes) => ("ACCEPT", json!({field: hex::encode(bytes)})),
        Err(_) => ("REJECT", json!({})),
    })
}
