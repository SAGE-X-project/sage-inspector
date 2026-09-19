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

use sage_crypto_core::registry010 as r;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};
#[derive(Clone)]
struct Controls(Arc<Mutex<State>>);
struct State {
    snapshot: r::Snapshot,
    mono: i64,
    delay: i64,
    reads: usize,
    fail: bool,
    clock_fail: bool,
    checks: usize,
    effects: usize,
}
impl r::Clock for Controls {
    fn now(&mut self) -> sage_crypto_core::error::Result<r::Stamp> {
        let c = self.0.lock().unwrap();
        if c.clock_fail {
            return Err(sage_crypto_core::error::Error::ValidationError(
                "fixture unavailable".into(),
            ));
        }
        Ok(r::Stamp {
            mono_ms: c.mono,
            unix: 1700000000,
        })
    }
}
impl r::Source for Controls {
    fn read(&mut self, _: &str) -> sage_crypto_core::error::Result<r::Snapshot> {
        let mut c = self.0.lock().unwrap();
        c.reads += 1;
        if c.fail {
            return Err(sage_crypto_core::error::Error::ValidationError(
                "fixture unavailable".into(),
            ));
        }
        let mut s = c.snapshot.clone();
        s.acquired_ms = c.mono;
        Ok(s)
    }
}
impl r::Store for Controls {
    fn advance(
        &mut self,
        _: r::Scope,
        _: u64,
        _: String,
        _: bool,
    ) -> sage_crypto_core::error::Result<()> {
        let mut c = self.0.lock().unwrap();
        c.mono += c.delay;
        Ok(())
    }
}
struct Sink {
    control: Controls,
    mode: String,
}
impl g::Component for Sink {
    fn check(&mut self, _: &str, _: &str) -> g::Result<()> {
        let mut c = self.control.0.lock().unwrap();
        c.checks += 1;
        if c.checks == 2 {
            match self.mode.as_str() {
                "revoked" => c.snapshot.keys[0].state = "revoked".into(),
                "unready" => c.snapshot.ready = false,
                "source" => c.fail = true,
                "clock" => c.clock_fail = true,
                "stale" => c.delay = 5001,
                "boundary" => c.delay = 5000,
                "rollback" => c.mono = 0,
                _ => (),
            }
        }
        Ok(())
    }
    fn commit(&mut self, i: &g::Invocation) -> g::Result<()> {
        if i.arguments() != br#"{"path":"public.txt"}"# {
            return Err(g::Invalid);
        }
        self.control.0.lock().unwrap().effects += 1;
        Ok(())
    }
}

fn main() {
    if run().is_err() {
        std::process::exit(2)
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("path")?;
    let mut raw = Vec::new();
    io::stdin().take(1048577).read_to_end(&mut raw)?;
    if raw.len() > 1048576 {
        return Err("size".into());
    }
    let q: Value = serde_json::from_slice(&raw)?;
    let mode = q["mode"].as_str().ok_or("mode")?;
    if ![
        "valid", "boundary", "revoked", "unready", "source", "clock", "stale", "rollback",
    ]
    .contains(&mode)
    {
        return Err("mode".into());
    }
    let f = q["input"].clone();
    let env = hex::decode(s(&f, "envelope_hex"))?;
    let e: Value = serde_json::from_slice(&env)?;
    let issuer = s(&e["intent"], "issuer");
    let kid = s(&e["intent"], "keyid");
    let registry = issuer
        .strip_prefix("did:sage:")
        .ok_or("did")?
        .rsplit_once(':')
        .ok_or("did")?
        .0;
    let c = Controls(Arc::new(Mutex::new(State {
        snapshot: r::Snapshot {
            source: "fixture".into(),
            registry: registry.into(),
            network: "fixture".into(),
            did: issuer.into(),
            version: "1".into(),
            state: "active".into(),
            digest: "a".repeat(64),
            ready: true,
            validated: true,
            finalized: true,
            conflicting: false,
            acquired_ms: 0,
            block_hash: String::new(),
            keys_block_hash: String::new(),
            keys: vec![r::Key {
                name: kid.split_once('#').ok_or("kid")?.1.into(),
                alg: "ed25519".into(),
                material: s(&f, "public_key_hex").into(),
                state: "accepted".into(),
                expires: None,
            }],
        },
        mono: 100,
        delay: 0,
        reads: 0,
        fail: false,
        clock_fail: false,
        checks: 0,
        effects: 0,
    })));
    let registry = r::SendGate::new_send(
        r::Config {
            source: "fixture".into(),
            registry: registry.into(),
            network: "fixture".into(),
            blockchain: false,
        },
        Box::new(c.clone()),
        Box::new(c.clone()),
        Box::new(c.clone()),
    )?;
    let authority = g::RegistryAuthority::new(registry, issuer, kid)?;
    let gate = g::DispatchGate::open(
        std::path::Path::new(&path),
        true,
        s(&f, "expected_recipient"),
        Box::new(authority),
        Box::new(Fixture(f.clone())),
        Box::new(Sink {
            control: c.clone(),
            mode: mode.into(),
        }),
    )?;
    let result = gate.dispatch(&env);
    gate.close()?;
    let c = c.0.lock().unwrap();
    println!(
        "{}",
        json!({"ok":result.is_ok(),"committed":result.as_ref().is_ok_and(|r|r.committed()),"effects":c.effects,"arguments":if c.effects==1 {r#"{"path":"public.txt"}"#}else{""},"reads":c.reads})
    );
    Ok(())
}
