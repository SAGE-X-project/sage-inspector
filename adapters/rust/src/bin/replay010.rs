//! Bounded local controls for the real persistent replay API, never a service.
use sage_crypto_core::{
    error::{Error, Result},
    hpke::completion010::{Replay010, ReplayJournal010, ReplayStore010},
    registry010::{Clock, Stamp},
};
use serde::Deserialize;
use std::{
    cell::RefCell,
    io::{Read, Write},
    path::Path,
    rc::Rc,
};
#[derive(Clone)]
struct Time(Rc<RefCell<Stamp>>);
impl Clock for Time {
    fn now(&mut self) -> Result<Stamp> {
        Ok(*self.0.borrow())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    action: String,
    unix: i64,
    mono_ms: i64,
    #[serde(default)]
    create: bool,
    #[serde(default)]
    gate: bool,
    #[serde(default)]
    id: String,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    recipient: String,
    #[serde(default)]
    context: String,
    #[serde(default)]
    expires: i64,
}
fn bad() -> Error {
    Error::ValidationError("control".into())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err(bad());
    }
    let time = Time(Rc::new(RefCell::new(Stamp {
        unix: 0,
        mono_ms: 0,
    })));
    let mut store: Option<ReplayJournal010> = None;
    let mut input = String::new();
    std::io::stdin().take(1048577).read_to_string(&mut input)?;
    if input.len() > 1048576 {
        return Err(bad());
    }
    for (n, line) in input.lines().enumerate() {
        if n >= 128 || line.len() > 65536 {
            return Err(bad());
        }
        let mut q: Control = serde_json::from_str(line).map_err(|_| bad())?;
        *time.0.borrow_mut() = Stamp {
            unix: q.unix,
            mono_ms: q.mono_ms,
        };
        let mut calls = 0;
        let ok = match q.action.as_str() {
            "open" => {
                if store.is_some() {
                    return Err(bad());
                }
                let result =
                    ReplayJournal010::open(Path::new(&args[1]), q.create, Box::new(time.clone()));
                let ok = result.is_ok();
                store = result.ok();
                ok
            }
            "close" => store.take().ok_or_else(bad)?.close().is_ok(),
            "ready" => store.as_mut().ok_or_else(bad)?.ready(),
            "reserve" | "record" => {
                if q.id.is_empty() {
                    q.id = "id".into();
                }
                if q.nonce.is_empty() {
                    q.nonce = "nonce".into();
                }
                if q.recipient.is_empty() {
                    q.recipient = "bob".into();
                }
                if q.expires == 0 {
                    q.expires = 760;
                }
                let v = Replay010 {
                    sender: "alice".into(),
                    recipient: q.recipient,
                    id: q.id,
                    nonce: q.nonce,
                    context: q.context,
                    expires: q.expires,
                };
                let j = store.as_mut().ok_or_else(bad)?;
                if q.action == "record" {
                    j.reserve_record(v, &mut || {
                        calls += 1;
                        if q.gate {
                            Ok(())
                        } else {
                            Err(bad())
                        }
                    })
                    .is_ok()
                } else {
                    j.reserve(v).is_ok()
                }
            }
            "abandon" => {
                println!("{{\"ok\":true,\"calls\":0}}");
                std::io::stdout().flush()?;
                std::process::exit(0)
            }
            _ => return Err(bad()),
        };
        println!("{}", serde_json::json!({"ok":ok,"calls":calls}));
    }
    if let Some(mut j) = store {
        j.close()?;
    }
    Ok(())
}
fn main() {
    if run().is_err() {
        std::process::exit(2)
    }
}
