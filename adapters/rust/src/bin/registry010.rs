//! Bounded local test binding. Synthetic Source/Clock inputs are not peer evidence.
use sage_crypto_core::{
    error::{Error, Result},
    registry010::*,
};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    io::{self, BufRead, Write},
    path::Path,
    rc::Rc,
    sync::{Arc, Mutex},
};
const REGISTRY: &str = "eip155:1:0xabababababababababababababababababababab";
fn bad() -> Error {
    Error::ValidationError("invalid test control".into())
}
fn cfg() -> Config {
    Config {
        source: "fixture-authority".into(),
        registry: REGISTRY.into(),
        network: "1".into(),
        blockchain: true,
    }
}
#[derive(Clone)]
struct Controls(Rc<RefCell<(Value, usize)>>);
impl Clock for Controls {
    fn now(&mut self) -> Result<Stamp> {
        let mut c = self.0.borrow_mut();
        if c.0["clock_ok"] != true {
            return Err(bad());
        };
        let t = &c.0["times"][c.1.min(2)];
        let s = Stamp {
            mono_ms: t["mono_ms"].as_i64().ok_or_else(bad)?,
            unix: t["unix"].as_i64().ok_or_else(bad)?,
        };
        c.1 += 1;
        Ok(s)
    }
}
impl Source for Controls {
    fn read(&mut self, _: &str) -> Result<Snapshot> {
        let c = self.0.borrow();
        if c.0["source_ok"] != true {
            return Err(bad());
        };
        serde_json::from_value(c.0["snapshot"].clone()).map_err(|_| bad())
    }
}
fn decode(bytes: &[u8]) -> Result<Value> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| bad())?;
    let m = v.as_object().ok_or_else(bad)?;
    if m.len() != 2
        || !m.contains_key("id")
        || !m.contains_key("request")
        || v["id"]
            .as_str()
            .is_none_or(|s| s.is_empty() || s.len() > 128)
    {
        return Err(bad());
    }
    let q = v["request"].as_object().ok_or_else(bad)?;
    let action = q.get("action").and_then(Value::as_str).ok_or_else(bad)?;
    let mut required = vec!["action"];
    match action {
        "observe" | "select" | "check" => {
            required.extend(["did", "snapshot", "times", "clock_ok", "source_ok"]);
            if !v["request"]["clock_ok"].is_boolean() || !v["request"]["source_ok"].is_boolean() {
                return Err(bad());
            }
            let times = v["request"]["times"].as_array().ok_or_else(bad)?;
            if times.len() != 3 {
                return Err(bad());
            }
            for t in times {
                if t.as_object().is_none_or(|o| o.len() != 2)
                    || t["mono_ms"].as_i64().is_none()
                    || t["unix"].as_i64().is_none()
                {
                    return Err(bad());
                }
            }
            let _: Snapshot =
                serde_json::from_value(v["request"]["snapshot"].clone()).map_err(|_| bad())?;
        }
        "inspect" => required.push("did"),
        "restart" | "mutate" => {}
        _ => return Err(bad()),
    }
    if action == "select" {
        required.extend(["signing_url", "require_kem"]);
        if !v["request"]["signing_url"].is_string() || !v["request"]["require_kem"].is_boolean() {
            return Err(bad());
        }
    }
    if required.contains(&"did") && !v["request"]["did"].is_string() {
        return Err(bad());
    }
    if q.len() != required.len()
        || required
            .iter()
            .any(|k| q.get(*k).is_none_or(Value::is_null))
    {
        return Err(bad());
    }
    Ok(v)
}
fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !["create", "reopen"].contains(&args[2].as_str()) {
        return Err("expected journal path and create or reopen".into());
    }
    let path = Path::new(&args[1]);
    let mut journal = Arc::new(Mutex::new(Journal::open(path, args[2] == "create")?));
    let control = Controls(Rc::new(RefCell::new((Value::Null, 0))));
    let make = |j: Arc<Mutex<Journal>>| {
        Gate::new(
            cfg(),
            Box::new(control.clone()),
            Box::new(control.clone()),
            Box::new(j),
        )
    };
    let mut gate = make(journal.clone())?;
    let mut pin: Option<Pinned> = None;
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut count = 0;
    loop {
        let mut line = Vec::new();
        let mut limited = std::io::Read::take(&mut reader, 1024 * 1024 + 1);
        if limited.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        count += 1;
        if line.len() > 1024 * 1024 || count > 128 {
            return Err("input limit".into());
        }
        let envelope = decode(&line)?;
        let q = &envelope["request"];
        *control.0.borrow_mut() = (q.clone(), 0);
        let did = q["did"].as_str().unwrap_or("");
        let mut out = json!({});
        let mut verdict = "ACCEPT";
        let result = match q["action"].as_str().unwrap() {
            "observe" => gate.observe(did).map(|s| {
                out = json!({"state":s.state,"version":s.version});
            }),
            "select" => {
                pin = None;
                gate.select(did,q["signing_url"].as_str().unwrap(),q["require_kem"].as_bool().unwrap()).map(|p|{out=json!({"signing_keyid":format!("{}#{}",p.did(),p.signing().name),"kem_keyid":p.kem().map(|k|format!("{}#{}",p.did(),k.name)).unwrap_or_default()});pin=Some(p);})
            }
            "check" => pin
                .as_ref()
                .filter(|p| p.did() == did)
                .ok_or_else(bad)
                .and_then(|p| gate.check_pinned(p))
                .map(|()| {
                    out = json!({"valid":true});
                }),
            "inspect" => {
                let w = journal.lock().map_err(|_| bad())?.get(&Scope {
                    registry: REGISTRY.into(),
                    did: did.into(),
                });
                out = json!({"highest_finalized_version":w.as_ref().map(|w|w.version.to_string()).unwrap_or_else(||"0".into()),"tombstone":w.is_some_and(|w|w.terminal)});
                Ok(())
            }
            "restart" => {
                journal.lock().map_err(|_| bad())?.close()?;
                journal = Arc::new(Mutex::new(Journal::open(path, false)?));
                gate = make(journal.clone())?;
                pin = None;
                Ok(())
            }
            "mutate" => {
                verdict = "UNSUPPORTED";
                Ok(())
            }
            _ => return Err(bad().into()),
        };
        if result.is_err() {
            verdict = "REJECT";
            out = json!({});
        }
        println!(
            "{}",
            json!({"id":envelope["id"],"verdict":verdict,"output":out})
        );
        io::stdout().flush()?;
    }
    journal.lock().map_err(|_| bad())?.close()?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(2)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn controls() {
        for s in [
            r#"{"id":"x","request":{"action":"restart"}}"#,
            r#"{"id":"x","request":{"action":"mutate"}}"#,
        ] {
            assert!(decode(s.as_bytes()).is_ok())
        }
        for s in [
            r#"{}"#,
            r#"{"id":"x","request":{"action":"observe"}}"#,
            r#"{"id":"x","request":{"action":"restart","expected":{}}}"#,
            r#"{"id":"x","request":{"action":"restart"}} {}"#,
        ] {
            assert!(decode(s.as_bytes()).is_err())
        }
    }
}
