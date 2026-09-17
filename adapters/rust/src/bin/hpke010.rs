//! Bounded local test process, never a network service.
use sage_crypto_core::{crypto::X25519KeyPair, hpke};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{self, BufRead, Read, Write};
type Error = Box<dyn std::error::Error>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: String,
    operation: String,
    input: Value,
}
fn result(v: hpke::Derivation010) -> Value {
    json!({"transcript_hex":hex::encode(v.transcript),"th_hex":hex::encode(v.th),"seed_hex":hex::encode(&*v.seed),"ack_tag_hex":hex::encode(v.ack_tag),"sid":v.sid})
}
fn run(reader: impl BufRead, mut writer: impl Write) -> Result<(), Error> {
    let mut state = None;
    let mut started = false;
    let mut seen = HashSet::new();
    let mut reader = reader;
    for step in 0..=16 {
        // read_until through Take bounds allocation even without a newline.
        let mut line = Vec::new();
        let n = reader
            .by_ref()
            .take(256 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(());
        }
        if n > 256 * 1024 || step == 16 {
            return Err("input limit".into());
        }
        let q: Request = serde_json::from_slice(&line)?;
        if q.id.is_empty() || !seen.insert(q.id.clone()) {
            return Err("invalid request".into());
        }
        let names: &[&str] = match q.operation.as_str() {
            "domains" => &["binding_hex"],
            "respond" => &[
                "initiation_hex",
                "kem_private_hex",
                "e2e_private_hex",
                "kid",
            ],
            "respond-fresh" => &["initiation_hex", "kem_private_hex"],
            "start" => &["binding_hex", "kem_private_hex"],
            "finish" => &["transcript_hex"],
            _ => {
                writeln!(
                    writer,
                    "{}",
                    json!({"id":q.id,"verdict":"UNSUPPORTED","output":{}})
                )?;
                writer.flush()?;
                continue;
            }
        };
        let obj = q.input.as_object().ok_or("invalid controls")?;
        if obj.len() != names.len() {
            return Err("invalid controls".into());
        }
        for name in names {
            if !obj.get(*name).is_some_and(Value::is_string) {
                return Err("invalid control".into());
            }
        }
        let decode = |name: &str| -> Result<Vec<u8>, Error> {
            Ok(hex::decode(obj[name].as_str().ok_or("invalid control")?)
                .map_err(|_| "invalid hex control")?)
        };
        let value=match q.operation.as_str(){
   "domains"=>hpke::build_domains_010(&decode("binding_hex")?).map(|v|json!({"binding_hex":hex::encode(v.binding),"info_hex":hex::encode(v.info),"export_context_hex":hex::encode(v.export_context)})),
   "respond"=>hpke::derive_responder_010(&decode("initiation_hex")?,&decode("kem_private_hex")?,&decode("e2e_private_hex")?,obj["kid"].as_str().unwrap()).map(result),
   "respond-fresh"=>hpke::respond_fresh_010(&decode("initiation_hex")?,&decode("kem_private_hex")?).map(result),
   "start"=>{
    if started{return Err("state replacement".into())}started=true;
    // Public-test private control supplies only its public key to the sender.
    let key=X25519KeyPair::from_bytes(&decode("kem_private_hex")?)?;
    hpke::start_initiator_010(&decode("binding_hex")?,key.public_key_bytes()).map(|(s,init)|{state=Some(s);json!({"initiation_hex":hex::encode(init)})})
   },
   "finish"=>state.take().ok_or("missing sender state")?.derive(&decode("transcript_hex")?).map(result),
   _=>unreachable!()
  };
        let (verdict, output) = match value {
            Ok(v) => ("ACCEPT", v),
            Err(_) => ("REJECT", json!({})),
        };
        writeln!(
            writer,
            "{}",
            json!({"id":q.id,"verdict":verdict,"output":output})
        )?;
        writer.flush()?;
    }
    Ok(())
}
fn main() {
    if let Err(e) = run(io::stdin().lock(), io::stdout().lock()) {
        eprintln!("{e}");
        std::process::exit(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_controls_have_no_observation() {
        for input in [
            r#"{"id":"x","operation":"domains","input":{"binding_hex":null}}"#,
            r#"{"id":"x","operation":"domains","input":{"binding_hex":"zz"}}"#,
            r#"{"id":"x","operation":"finish","input":{"transcript_hex":"00"}}"#,
        ] {
            let mut out = Vec::new();
            assert!(run(input.as_bytes(), &mut out).is_err());
            assert!(out.is_empty());
        }
    }
    #[test]
    fn missing_operations_stay_unsupported() {
        let mut out = Vec::new();
        run(
            br#"{"id":"x","operation":"authenticate","input":{}}"#.as_slice(),
            &mut out,
        )
        .unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["verdict"], "UNSUPPORTED");
    }
}
