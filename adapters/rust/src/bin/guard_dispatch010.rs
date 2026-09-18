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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
// Bounded fixture-only sink. No external tool, shell or network execution.
struct Sink {
    fixture: Value,
    instance: String,
    path: PathBuf,
    effects: Arc<Mutex<Vec<Value>>>,
}
impl g::Component for Sink {
    fn check(&mut self, manifest: &str, tool: &str) -> g::Result<()> {
        let raw = serde_json::to_vec(&self.fixture["approved_manifest"]).map_err(|_| g::Invalid)?;
        let digest = g::verify_manifest(
            &raw,
            &[
                g::Artifact {
                    path: "engine.bin".into(),
                    bytes: b"public pinned evaluator".to_vec(),
                },
                g::Artifact {
                    path: "rules.json".into(),
                    bytes: br#"{"allow":["read"]}"#.to_vec(),
                },
            ],
        )?;
        if digest != manifest || tool != "read" {
            return Err(g::Invalid);
        };
        Ok(())
    }
    fn commit(&mut self, i: &g::Invocation) -> g::Result<()> {
        let raw = std::fs::read_to_string(&self.path).map_err(|_| g::Invalid)?;
        let row: Value =
            serde_json::from_str(raw.lines().last().ok_or(g::Invalid)?).map_err(|_| g::Invalid)?;
        if row["state"] != "EXECUTING" {
            return Err(g::Invalid);
        };
        self.effects.lock().map_err(|_|g::Invalid)?.push(json!({"instance":self.instance,"envelope_hex":hex::encode(i.canonical_intent()),"arguments_hex":hex::encode(i.arguments()),"tool":i.tool(),"manifest_digest":i.manifest_digest(),"intent_digest":i.intent_digest()}));
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    #[serde(default)]
    input: Value,
    #[serde(default)]
    instance: String,
    #[serde(default)]
    envelope_hex: String,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !matches!(args[2].as_str(), "create" | "reopen") {
        return Err("arguments".into());
    }
    let path = Path::new(&args[1]);
    let effects = Arc::new(Mutex::new(Vec::<Value>::new()));
    let mut gate: Option<g::DispatchGate> = None;
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    let mut count = 0;
    loop {
        let mut line = Vec::new();
        let n = std::io::Read::take(&mut input, (4 << 20) + 1).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        };
        count += 1;
        if n > 4 << 20 || count > 64 {
            return Err("bounds".into());
        }
        let q: Request = serde_json::from_slice(&line)?;
        let mut r =
            json!({"ok":false,"created":false,"committed":false,"state":"","intent_digest":""});
        match q.action.as_str() {
            "configure" => {
                if !matches!(q.instance.as_str(), "old" | "new") {
                    return Err("instance".into());
                }
                let sink = Box::new(Sink {
                    fixture: q.input.clone(),
                    instance: q.instance,
                    path: path.into(),
                    effects: effects.clone(),
                });
                if let Some(gate) = &gate {
                    r["ok"] = json!(gate
                        .replace(
                            Box::new(Fixture(q.input.clone())),
                            Box::new(Fixture(q.input)),
                            sink
                        )
                        .is_ok())
                } else {
                    gate = Some(g::DispatchGate::open(
                        path,
                        args[2] == "create",
                        "did:sage:web:agents.example.com:executor",
                        Box::new(Fixture(q.input.clone())),
                        Box::new(Fixture(q.input)),
                        sink,
                    )?);
                    r["ok"] = json!(true)
                }
            }
            "retire" => r["ok"] = json!(gate.as_ref().ok_or("no gate")?.retire().is_ok()),
            "dispatch" => {
                if let Ok(v) = gate
                    .as_ref()
                    .ok_or("no gate")?
                    .dispatch(&hex::decode(q.envelope_hex)?)
                {
                    r = json!({"ok":true,"created":v.created(),"committed":v.committed(),"state":v.state(),"intent_digest":v.intent_digest()})
                }
            }
            _ => return Err("action".into()),
        }
        r["effects"] = json!(*effects.lock().map_err(|_| "poison")?);
        writeln!(out, "{r}")?;
        out.flush()?;
    }
    gate.ok_or("no gate")?.close()?;
    Ok(())
}
fn main() {
    if run().is_err() {
        std::process::exit(2)
    }
}
