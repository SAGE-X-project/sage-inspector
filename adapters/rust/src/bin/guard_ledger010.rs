use sage_crypto_core::guard010::{self as g, Authority, Bindings, IntentPolicy};
use serde_json::{json, Value};
// Test-only trusted-service seams. These controls are not production authority.
struct Fixture(Value);
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}
impl Authority for Fixture {
    fn now(&mut self) -> g::Result<i64> {
        if self.0["clock_trusted"] != true {
            return Err(g::Invalid);
        };
        self.0["now"].as_i64().ok_or(g::Invalid)
    }
    fn active_key(&mut self, issuer: &str, _kid: &str) -> g::Result<[u8; 32]> {
        if self.0["active_key"] != true
            || (!s(&self.0, "expected_issuer").is_empty()
                && s(&self.0, "expected_issuer") != issuer)
        {
            return Err(g::Invalid);
        };
        hex::decode(s(&self.0, "public_key_hex"))
            .map_err(|_| g::Invalid)?
            .try_into()
            .map_err(|_| g::Invalid)
    }
}
impl IntentPolicy for Fixture {
    fn bindings(&mut self, issuer: &str, _request_id: &str) -> g::Result<Bindings> {
        if issuer != s(&self.0, "expected_issuer") {
            return Err(g::Invalid);
        };
        Ok(Bindings {
            original: s(&self.0, "original_digest").into(),
            policy: serde_json::to_vec(&self.0["approved_policy"]).map_err(|_| g::Invalid)?,
            manifest: serde_json::to_vec(&self.0["approved_manifest"]).map_err(|_| g::Invalid)?,
        })
    }
    fn authorize(&mut self, _issuer: &str, tool: &str, args: &[u8]) -> g::Result<()> {
        let schema = &self.0["tool_schema"];
        if self.0["policy_allow"] != true || s(schema, "tool") != tool {
            return Err(g::Invalid);
        };
        let v: Value = serde_json::from_slice(args).map_err(|_| g::Invalid)?;
        let a = v.as_object().ok_or(g::Invalid)?;
        for k in schema["required"].as_array().ok_or(g::Invalid)? {
            if !a.contains_key(k.as_str().ok_or(g::Invalid)?) {
                return Err(g::Invalid);
            }
        }
        for (k, v) in a {
            if schema["properties"][k] != "string" || !v.is_string() {
                return Err(g::Invalid);
            }
        }
        Ok(())
    }
}

use serde::Deserialize;
use std::io::{self, BufRead, Write};
use std::path::Path;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    #[serde(default)]
    input: Value,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !matches!(args[2].as_str(), "create" | "reopen") {
        return Err("arguments".into());
    }
    let path = Path::new(&args[1]);
    let recipient = "did:sage:web:agents.example.com:executor";
    let mut l = g::GuardLedger::open(path, args[2] == "create", recipient)?;
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    let mut count = 0;
    loop {
        let mut line = Vec::new();
        let n = std::io::Read::take(&mut input, (4 << 20) + 1).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        count += 1;
        if n > 4 << 20 || count > 64 {
            return Err("input bounds".into());
        };
        let q: Request = serde_json::from_slice(&line)?;
        let mut r = json!({"ok":false,"created":false,"state":"","intent_digest":""});
        match q.action.as_str() {
            "reserve" => {
                let raw = hex::decode(s(&q.input, "envelope_hex"))?;
                if let Ok(v) = l.reserve(&raw, &mut Fixture(q.input.clone()), &mut Fixture(q.input))
                {
                    r = json!({"ok":true,"created":v.created(),"state":v.state(),"intent_digest":v.intent_digest()})
                }
            }
            "reopen" => {
                l.close()?;
                l = g::GuardLedger::open(path, false, recipient)?;
                r["ok"] = json!(true)
            }
            _ => return Err("action".into()),
        };
        writeln!(out, "{r}")?;
        out.flush()?;
    }
    l.close()?;
    Ok(())
}
fn main() {
    if run().is_err() {
        std::process::exit(2)
    }
}
