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
    completion: Arc<Mutex<Option<g::Completion>>>,
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
        *self.completion.lock().map_err(|_| g::Invalid)? = Some(i.completion());
        self.effects.lock().map_err(|_|g::Invalid)?.push(json!({"instance":self.instance,"envelope_hex":hex::encode(i.canonical_intent()),"arguments_hex":hex::encode(i.arguments()),"tool":i.tool(),"manifest_digest":i.manifest_digest(),"intent_digest":i.intent_digest()}));
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    id: String,
    #[serde(default)]
    mcp_version: String,
    #[serde(default)]
    slot: usize,
    #[serde(default)]
    output: Value,
    #[serde(default)]
    now: i64,
    #[serde(default)]
    active: bool,
    #[serde(default)]
    fail: bool,
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
    let mut gate: Option<Arc<g::DispatchGate>> = None;
    let mut endpoint: Option<g::MCPEndpoint> = None;
    let mut rpc_receipts = std::collections::HashMap::<usize, g::MCPReceipt>::new();
    let completion = Arc::new(Mutex::new(None::<g::Completion>));
    let mut receipts = std::collections::HashMap::<usize, g::DispatchReceipt>::new();
    let mut signer = Signing {
        now: 1700000000,
        active: true,
        fail: false,
        signs: 0,
    };
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
        if q.slot >= 64 || (gate.is_none() && q.action != "configure") {
            return Err("command order".into());
        }
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
                    completion: completion.clone(),
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
                    gate = Some(Arc::new(g::DispatchGate::open(
                        path,
                        args[2] == "create",
                        "did:sage:web:agents.example.com:executor",
                        Box::new(Fixture(q.input.clone())),
                        Box::new(Fixture(q.input)),
                        sink,
                    )?));
                    r["ok"] = json!(true)
                }
            }
            "retire" => r["ok"] = json!(gate.as_ref().ok_or("no gate")?.retire().is_ok()),
            "signer" => {
                signer.now = q.now;
                signer.active = q.active;
                signer.fail = q.fail;
                r["ok"] = json!(true)
            }
            "finish" => {
                if let Some(token) = completion.lock().map_err(|_| "poison")?.as_ref() {
                    r["ok"] = json!(gate
                        .as_ref()
                        .ok_or("no gate")?
                        .finish(token, &serde_json::to_vec(&q.output)?, &mut signer)
                        .is_ok())
                }
            }
            "rpc_setup" => {
                if endpoint.is_some() {
                    return Err("already setup".into());
                }
                if let Ok(e) =
                    g::MCPEndpoint::new(&q.mcp_version, gate.as_ref().ok_or("no gate")?.clone())
                {
                    endpoint = Some(e);
                    r["ok"] = json!(true);
                }
            }
            "rpc_dispatch" => {
                let raw = hex::decode(q.envelope_hex)?;
                if let Some(e) = &endpoint {
                    if let Ok(v) = e.dispatch(&q.id, &raw) {
                        r = json!({"ok":true,"created":v.created(),"committed":v.committed(),"state":v.state(),"intent_digest":v.intent_digest()});
                        rpc_receipts.insert(q.slot, v);
                    }
                }
            }
            "rpc_reply" => {
                if let (Some(e), Some(v)) = (&endpoint, rpc_receipts.get_mut(&q.slot)) {
                    if let Ok(raw) = e.reply(v, &mut signer) {
                        r["ok"] = json!(true);
                        r["rpc_hex"] = json!(hex::encode(raw));
                    }
                }
            }
            "rpc_close" => {
                if let Some(e) = &endpoint {
                    r["ok"] = json!(e.close().is_ok())
                }
            }
            "reply" => {
                if let Some(receipt) = receipts.get_mut(&q.slot) {
                    if let Ok(raw) = gate.as_ref().ok_or("no gate")?.reply(receipt, &mut signer) {
                        r["ok"] = json!(true);
                        r["result_hex"] = json!(hex::encode(raw))
                    }
                }
            }
            "dispatch" | "reject" => {
                let gate = gate.as_ref().ok_or("no gate")?;
                let raw = hex::decode(q.envelope_hex)?;
                let result = if q.action == "reject" {
                    gate.reject(&raw, &mut signer)
                } else {
                    gate.dispatch(&raw)
                };
                if let Ok(v) = result {
                    r = json!({"ok":true,"created":v.created(),"committed":v.committed(),"state":v.state(),"intent_digest":v.intent_digest()});
                    receipts.insert(q.slot, v);
                }
            }
            _ => return Err("action".into()),
        }
        if r.get("result_hex").is_none() {
            r["result_hex"] = json!("")
        }
        r["signs"] = json!(signer.signs);
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

// Public deterministic fixture key, never a production credential.
struct Signing {
    now: i64,
    active: bool,
    fail: bool,
    signs: usize,
}
const EXECUTOR: &str = "did:sage:web:agents.example.com:executor";
const KID: &str = "did:sage:web:agents.example.com:executor#signing-1";
fn key() -> g::Result<sage_crypto_core::crypto::KeyPair> {
    sage_crypto_core::crypto::KeyPair::from_private_key_bytes(
        sage_crypto_core::crypto::KeyType::Ed25519,
        &hex::decode("7d92bffe55c942eef4d4cdf20d5a8927f43a09152f910eb246fc6a71f55f5173")
            .map_err(|_| g::Invalid)?,
    )
    .map_err(|_| g::Invalid)
}
impl Authority for Signing {
    fn now(&mut self) -> g::Result<i64> {
        Ok(self.now)
    }
    fn active_key(&mut self, issuer: &str, kid: &str) -> g::Result<[u8; 32]> {
        if !self.active || issuer != EXECUTOR || kid != KID {
            return Err(g::Invalid);
        };
        key()?.public_key_bytes().try_into().map_err(|_| g::Invalid)
    }
}
impl g::ResultSigner for Signing {
    fn key_id(&mut self) -> g::Result<String> {
        Ok(KID.into())
    }
    fn sign(&mut self, kid: &str, message: &[u8]) -> g::Result<Vec<u8>> {
        use sage_crypto_core::crypto::Signer;
        self.signs += 1;
        if self.fail || kid != KID {
            return Err(g::Invalid);
        };
        Ok(key()?.sign(message).map_err(|_| g::Invalid)?.to_bytes())
    }
}
