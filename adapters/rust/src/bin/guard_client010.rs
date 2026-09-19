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

use g::{Client, ClientClock, ClientInvocation, ClientSender, ClientServices, Invalid};
use serde::Deserialize;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
fn ensure(v: bool) -> g::Result<()> {
    if v {
        Ok(())
    } else {
        Err(Invalid)
    }
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    s(v, k)
}
#[derive(Clone)]
struct Services(Arc<Mutex<Value>>);
impl ClientClock for Services {
    fn sample(&mut self) -> g::Result<(i64, i64)> {
        let s = self.0.lock().unwrap();
        ensure(s["clock_ok"] == true)?;
        Ok((
            s["utc"].as_i64().ok_or(Invalid)?,
            s["mono"].as_i64().ok_or(Invalid)?,
        ))
    }
}
impl Authority for Services {
    fn now(&mut self) -> g::Result<i64> {
        Ok(self.sample()?.0 / 1000)
    }
    fn active_key(&mut self, issuer: &str, kid: &str) -> g::Result<[u8; 32]> {
        let s = self.0.lock().unwrap();
        if issuer == "did:sage:web:agents.example.com:executor" {
            ensure(s["result_active"] == true && kid == format!("{issuer}#signing-1"))?;
            hex::decode(text(&s, "public"))
                .map_err(|_| Invalid)?
                .try_into()
                .map_err(|_| Invalid)
        } else {
            Fixture(s["input"].clone()).active_key(issuer, kid)
        }
    }
}
impl IntentPolicy for Services {
    fn bindings(&mut self, i: &str, r: &str) -> g::Result<Bindings> {
        Fixture(self.0.lock().unwrap()["input"].clone()).bindings(i, r)
    }
    fn authorize(&mut self, i: &str, t: &str, a: &[u8]) -> g::Result<()> {
        Fixture(self.0.lock().unwrap()["input"].clone()).authorize(i, t, a)
    }
}
impl ClientSender for Services {
    fn commit(&mut self, id: &str, raw: &[u8]) -> g::Result<()> {
        let mut s = self.0.lock().unwrap();
        s["handoffs"] = json!(s["handoffs"].as_u64().unwrap_or(0) + 1);
        s["sent_id"] = json!(id);
        s["sent_intent"] = json!(hex::encode(raw));
        let delay = s["send_delay"].as_i64().unwrap_or(0);
        let u = s["utc"].as_i64().unwrap();
        let m = s["mono"].as_i64().unwrap();
        s["utc"] = json!(u + delay);
        s["mono"] = json!(m + delay);
        ensure(s["send_fail"] != true)
    }
}
impl Services {
    fn config(&self) -> ClientServices {
        ClientServices {
            intent_authority: Box::new(self.clone()),
            policy: Box::new(self.clone()),
            result_authority: Box::new(self.clone()),
            clock: Box::new(self.clone()),
            sender: Box::new(self.clone()),
        }
    }
}
fn observation() -> Value {
    json!({"ok":true,"id":"","intent_hex":"","status":"","first":false,"ignored":false,"output_hex":"","handoffs":0})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    mcp_version: String,
    action: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    input: Value,
    #[serde(default)]
    public_key_hex: String,
    #[serde(default)]
    utc: i64,
    #[serde(default)]
    mono: i64,
    #[serde(default)]
    field: String,
    #[serde(default)]
    value: bool,
    #[serde(default)]
    envelope_hex: String,
}
fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !matches!(args[2].as_str(), "create" | "reopen") {
        return Err("arguments".into());
    }
    let mut client: Option<Client> = None;
    let services = Services(Arc::new(Mutex::new(json!({}))));
    let mut tickets = std::collections::BTreeMap::<String, ClientInvocation>::new();
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
            return Err("bounds".into());
        };
        let q: Request = serde_json::from_slice(&line)?;
        if client.is_none() && q.action != "open" {
            return Err("order".into());
        };
        let mut o = observation();
        match q.action.as_str() {
            "open" => {
                if client.is_some() {
                    return Err("already open".into());
                };
                let raw = hex::decode(s(&q.input, "envelope_hex"))?;
                *services.0.lock().map_err(|_| "poison")? = json!({"input":q.input,"public":q.public_key_hex,"utc":q.utc,"mono":q.mono,"clock_ok":true,"result_active":true});
                client = Some(Client::open(
                    std::path::Path::new(&args[1]),
                    args[2] == "create",
                    &raw,
                    services.config(),
                )?);
            }
            "tick" => {
                let mut s = services.0.lock().map_err(|_| "poison")?;
                s["utc"] = json!(q.utc);
                s["mono"] = json!(q.mono)
            }
            "set" => {
                let mut s = services.0.lock().map_err(|_| "poison")?;
                match q.field.as_str() {
                    "intent_active" => s["input"]["active_key"] = json!(q.value),
                    "policy_allow" => s["input"]["policy_allow"] = json!(q.value),
                    "clock_ok" | "result_active" => s[q.field] = json!(q.value),
                    _ => return Err("field".into()),
                }
            }
            "begin" => match client.as_ref().ok_or("no client")?.begin(&q.id) {
                Ok(t) => {
                    o["id"] = services.0.lock().map_err(|_| "poison")?["sent_id"].clone();
                    o["intent_hex"] =
                        services.0.lock().map_err(|_| "poison")?["sent_intent"].clone();
                    tickets.insert(q.id, t);
                }
                Err(_) => o["ok"] = json!(false),
            },
            "accept" | "accept_mcp" => {
                let raw = hex::decode(q.envelope_hex)?;
                match tickets.get(&q.id).ok_or(Invalid).and_then(|t| {
                    let c = client.as_ref().ok_or(Invalid)?;
                    if q.action == "accept_mcp" {
                        c.accept_mcp(t, &q.mcp_version, &raw)
                    } else {
                        c.accept(t, &raw)
                    }
                }) {
                    Ok(d) => {
                        o["status"] = json!(d.status());
                        o["first"] = json!(d.first_terminal());
                        o["ignored"] = json!(d.ignored());
                        o["output_hex"] = json!(hex::encode(d.output()));
                    }
                    Err(_) => o["ok"] = json!(false),
                }
            }
            "failed" => {
                o["ok"] = json!(tickets
                    .get(&q.id)
                    .ok_or(Invalid)
                    .and_then(|t| client.as_ref().ok_or(Invalid)?.failed(t))
                    .is_ok())
            }
            "close" => o["ok"] = json!(client.as_ref().ok_or("no client")?.close().is_ok()),
            _ => return Err("action".into()),
        };
        o["handoffs"] = json!(services.0.lock().map_err(|_| "poison")?["handoffs"]
            .as_u64()
            .unwrap_or(0));
        writeln!(out, "{o}")?;
        out.flush()?;
    }
    if let Some(c) = client {
        let _ = c.close();
    } else {
        return Err("no client".into());
    };
    Ok(())
}
fn main() {
    if run().is_err() {
        std::process::exit(2)
    }
}
