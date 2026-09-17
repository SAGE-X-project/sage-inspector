//! Bounded schema2 bridge. All record decisions belong to the real core.
use sage_crypto_core::session::RecordSession010;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{self, BufRead, Write};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    protocol_version: String,
    profile: String,
    case_id: String,
    step_id: String,
    operation: String,
    input: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    seed_hex: String,
    th_hex: String,
    initiator: bool,
}
#[derive(Default)]
struct Bridge {
    core: Option<RecordSession010>,
    opened: u64,
    sealed: u64,
    closed: u64,
}
impl Bridge {
    fn observe(
        &mut self,
        q: &Request,
    ) -> Result<(&'static str, Value), Box<dyn std::error::Error>> {
        if q.operation == "record010.create" {
            if self.core.is_some() {
                return Err("session replacement is forbidden".into());
            }
            let c: Create = serde_json::from_value(q.input.clone())?;
            let core = RecordSession010::new(
                &hex::decode(c.seed_hex)?,
                &hex::decode(c.th_hex)?,
                c.initiator,
            )?;
            let out = json!({"session_id":core.id()});
            self.core = Some(core);
            return Ok(("ACCEPT", out));
        }
        if !["record010.open", "record010.seal", "record010.close"].contains(&q.operation.as_str())
        {
            return Ok(("UNSUPPORTED", json!({})));
        }
        let core = self.core.as_mut().ok_or("create a record session first")?;
        let fields = q.input.as_object().ok_or("object required")?;
        if q.operation == "record010.close" {
            if !fields.is_empty() {
                return Err("invalid close controls".into());
            }
            core.close();
            self.closed += 1;
            return Ok(("ACCEPT", json!({})));
        }
        let field = if q.operation == "record010.open" {
            "record_hex"
        } else {
            "plaintext_hex"
        };
        if fields.len() != 2
            || !fields.contains_key(field)
            || !fields.contains_key("caller_aad_hex")
        {
            return Err("invalid record controls".into());
        }
        let data = hex::decode(fields[field].as_str().ok_or("string required")?)?;
        let aad = hex::decode(fields["caller_aad_hex"].as_str().ok_or("string required")?)?;
        if q.operation == "record010.open" {
            return Ok(match core.open(&data, &aad) {
                Ok(p) => {
                    self.opened += 1;
                    ("ACCEPT", json!({"plaintext_hex":hex::encode(p)}))
                }
                Err(_) => ("REJECT", json!({})),
            });
        }
        Ok(match core.seal(&data, &aad) {
            Ok(w) => {
                self.sealed += 1;
                ("ACCEPT", json!({"record_hex":hex::encode(w)}))
            }
            Err(_) => ("REJECT", json!({})),
        })
    }
}
fn run(reader: impl BufRead, mut writer: impl Write) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = reader;
    let mut bridge = Bridge::default();
    let mut case = String::new();
    let mut seen = HashSet::new();
    loop {
        // Bound allocation while reading, before parsing any request.
        let mut line = Vec::new();
        loop {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                break;
            }
            let n = buf
                .iter()
                .position(|b| *b == b'\n')
                .map_or(buf.len(), |p| p + 1);
            if line.len() + n > 4 * 1024 * 1024 {
                return Err("oversized request".into());
            }
            let done = buf[n - 1] == b'\n';
            line.extend_from_slice(&buf[..n]);
            reader.consume(n);
            if done {
                break;
            }
        }
        if line.is_empty() {
            break;
        }
        let q: Request = serde_json::from_slice(&line)?;
        if q.schema_version != 2
            || q.protocol_version != "0.10.0"
            || q.profile != "stateful-scenario"
            || q.case_id.is_empty()
            || q.step_id.is_empty()
            || seen.len() >= 128
            || !seen.insert(q.step_id.clone())
        {
            return Err("invalid step header".into());
        }
        if case.is_empty() {
            case = q.case_id.clone();
        }
        if case != q.case_id {
            return Err("case changed".into());
        }
        let (verdict, output) = bridge.observe(&q)?;
        writeln!(
            writer,
            "{}",
            json!({"schema_version":2,"case_id":q.case_id,"step_id":q.step_id,"verdict":verdict,"output":output,"effects":{"core_open_success":bridge.opened,"core_seal_success":bridge.sealed,"core_close_calls":bridge.closed}})
        )?;
        writer.flush()?;
    }
    if let Some(core) = bridge.core.as_mut() {
        core.close();
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
    fn unsupported_does_not_invent_state() {
        let q=json!({"schema_version":2,"protocol_version":"0.10.0","profile":"stateful-scenario","case_id":"test","step_id":"one","operation":"record010.inspect","input":{}}).to_string()+"\n";
        let mut out = Vec::new();
        run(q.as_bytes(), &mut out).unwrap();
        let value: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["verdict"], "UNSUPPORTED");
        assert_eq!(value["effects"]["core_open_success"], 0);
    }
    #[test]
    fn invalid_stream_has_no_observation() {
        for q in [
            json!({"schema_version":1}),
            json!({"schema_version":2,"protocol_version":"0.10.0","profile":"stateful-scenario","case_id":"test","step_id":"one","operation":"record010.close","input":{}}),
        ] {
            let text = q.to_string() + "\n";
            let mut out = Vec::new();
            assert!(run(text.as_bytes(), &mut out).is_err());
            assert!(out.is_empty());
        }
    }
}
