//! Bounded local test dependencies; no network target or production credentials.
use sage_crypto_core::guard010 as g;
use sage_crypto_core::{
    error::{Error, Result},
    hpke::completion010::*,
    registry010::{Clock, Config, Gate, Journal, Key, Snapshot, Source, Stamp},
};

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    cell::RefCell,
    collections::HashSet,
    io::{self, BufRead, Write},
    path::Path,
    rc::Rc,
};
fn bad() -> Error {
    Error::ValidationError("invalid local test control".into())
}
fn canonical(v: &impl Serialize) -> Vec<u8> {
    sage_crypto_core::jcs::canonicalize(&serde_json::to_vec(v).unwrap()).unwrap()
}
fn public(n: u8) -> String {
    match n {
        1 => "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        2 => "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
        4 => "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c",
        5 => "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
        _ => panic!("fixed fixture key"),
    }
    .into()
}
fn kem_public() -> String {
    "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22".into()
}
const ALICE: &str = "did:sage:web:agent.example:alice";
const BOB: &str = "did:sage:web:agent.example:bob";
#[derive(Default)]
struct Control {
    handshakes: u64,
    records: u64,
    expiry: i64,
    mono: i64,
    utc: i64,
    mode: String,
}
#[derive(Clone)]
struct Controls(Rc<RefCell<Control>>);
impl Clock for Controls {
    fn now(&mut self) -> Result<Stamp> {
        let c = self.0.borrow();
        if c.mode == "clock-error" {
            return Err(bad());
        }
        Ok(Stamp {
            mono_ms: c.mono,
            unix: c.utc,
        })
    }
}
impl Source for Controls {
    fn read(&mut self, did: &str) -> Result<Snapshot> {
        let c = self.0.borrow();
        if c.mode == "source-error" {
            return Err(bad());
        }
        let n = if did == BOB { 2 } else { 1 };
        let mut k = Key {
            name: "signing-1".into(),
            alg: "ed25519".into(),
            material: public(n),
            state: "accepted".into(),
            expires: None,
        };
        let mut keys = Vec::new();
        if did == BOB {
            keys.push(Key {
                name: "kem-1".into(),
                alg: "x25519".into(),
                material: kem_public(),
                state: if c.mode == "revoke-kem" {
                    "revoked"
                } else {
                    "accepted"
                }
                .into(),
                expires: None,
            });
        }
        if (c.mode == "revoke-init" && did == ALICE) || (c.mode == "revoke-resp" && did == BOB) {
            k.state = "revoked".into()
        }
        if c.mode == "changed-material" && did == BOB {
            k.material = public(4)
        }
        keys.push(k.clone());
        let version = if c.mode.starts_with("revoke")
            || ["changed-material", "unrelated"].contains(&c.mode.as_str())
        {
            "3"
        } else {
            "2"
        };
        if c.mode == "unrelated" {
            k.name = "z-extra".into();
            k.material = public(5);
            keys.push(k)
        }
        if c.expiry != 0 {
            for k in &mut keys {
                k.expires = Some(c.expiry);
            }
        }
        let digest = hex::encode(sage_crypto_core::hpke::sha256_hash(&canonical(&keys)));
        Ok(Snapshot {
            source: "fixture-authority".into(),
            registry: "web:agent.example".into(),
            network: "local".into(),
            did: did.into(),
            version: version.into(),
            state: "active".into(),
            digest,
            ready: true,
            validated: true,
            finalized: true,
            conflicting: false,
            acquired_ms: c.mono,
            block_hash: String::new(),
            keys_block_hash: String::new(),
            keys,
        })
    }
}
struct Replay {
    control: Controls,
    seen: HashSet<String>,
}
impl ReplayStore010 for Replay {
    fn reserve_record(
        &mut self,
        r: Replay010,
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let prefix = format!("{}|{}", r.sender, r.recipient);
        let ids = [
            format!("{prefix}|id|{}", r.id),
            format!("{prefix}|nonce|{}", r.nonce),
        ];
        if self.control.0.borrow().mode == "transport-id" {
            self.seen.insert(ids[0].clone());
        }
        if self.control.0.borrow().mode == "transport-nonce" {
            self.seen.insert(ids[1].clone());
        }
        if ids.iter().any(|id| self.seen.contains(id)) {
            return Err(bad());
        }
        {
            let mut c = self.control.0.borrow_mut();
            if c.mode == "store-error" {
                return Err(bad());
            }
            if c.mode == "utc-delay" {
                c.utc += 1;
                c.mono += 1000
            }
            if c.mode == "store-delay" {
                c.mono += 5001
            }
        }
        validate()?;
        self.seen.extend(ids);
        self.control.0.borrow_mut().records += 1;
        Ok(())
    }

    fn reserve(&mut self, r: Replay010) -> Result<()> {
        let mut c = self.control.0.borrow_mut();
        if c.mode == "store-error" {
            return Err(bad());
        }
        let prefix = format!("{}|{}", r.sender, r.recipient);
        let mut ids = vec![
            format!("{prefix}|id|{}", r.id),
            format!("{prefix}|nonce|{}", r.nonce),
        ];
        if !r.context.is_empty() {
            ids.push(format!("{}|ctx|{}", r.sender, r.context))
        }
        if ids.iter().any(|id| self.seen.contains(id)) {
            return Err(bad());
        }
        self.seen.extend(ids);
        if c.mode == "utc-delay" {
            c.utc += 1;
            c.mono += 1000;
        }
        if c.mode == "store-delay" {
            c.mono += 5001
        }
        c.handshakes += 1;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    target: String,
    #[serde(default)]
    status: u16,
    message_id: Option<String>,
    success: Option<bool>,
    error: Option<String>,
    #[serde(default)]
    key_expires: i64,
    id: String,
    action: String,
    wire_hex: Option<String>,
    #[serde(default)]
    mode: String,
    mono_ms: i64,
    unix: i64,
    ttl: Option<i64>,
}
fn decode(bytes: &[u8]) -> Result<(Request, Vec<u8>)> {
    let q: Request = serde_json::from_slice(bytes).map_err(|_| bad())?;
    if q.id.is_empty()
        || q.id.len() > 128
        || ![
            "",
            "utc-delay",
            "source-error",
            "clock-error",
            "store-error",
            "store-delay",
            "revoke-init",
            "revoke-resp",
            "revoke-kem",
            "changed-material",
            "unrelated",
            "transport-id",
            "transport-nonce",
        ]
        .contains(&q.mode.as_str())
    {
        return Err(bad());
    }
    let wire = match q.action.as_str() {
        "mcp-seal" | "mcp-open" | "mcp-reply" | "mcp-open-reply" => {
            let v = q.wire_hex.as_ref().ok_or_else(bad)?;
            if v.len() > 65536 {
                return Err(bad());
            }
            hex::decode(v).map_err(|_| bad())?
        }
        "respond"
        | "complete"
        | "record-seal"
        | "record-open"
        | "response-seal"
        | "response-open"
        | "http-request-seal"
        | "http-request-open"
        | "http-response-seal"
        | "http-response-open"
        | "http-respond-raw"
        | "http-complete-raw"
        | "http-record-seal-raw"
        | "http-record-open-raw"
        | "http-response-seal-raw"
        | "http-response-open-raw" => {
            let s = q.wire_hex.as_ref().ok_or_else(bad)?;
            let limit = if matches!(
                q.action.as_str(),
                "http-request-open"
                    | "http-response-open"
                    | "http-respond-raw"
                    | "http-complete-raw"
                    | "http-record-open-raw"
                    | "http-response-open-raw"
            ) {
                196608
            } else {
                65536
            };
            if s.len() > limit {
                return Err(bad());
            }
            hex::decode(s).map_err(|_| bad())?
        }
        "start" | "inspect" | "check" | "close" | "endpoint-close" | "pending-close"
        | "dispatch" | "record-inspect" | "http-bind" | "http-endpoint-bind" | "http-start"
        | "http-inspect" => {
            if q.wire_hex.is_some() {
                return Err(bad());
            }
            Vec::new()
        }
        _ => return Err(bad()),
    };
    Ok((q, wire))
}
fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !["alice", "bob"].contains(&args[1].as_str()) {
        return Err("expected role and local journal path".into());
    }
    let (did, n) = if args[1] == "alice" {
        (ALICE, 1)
    } else {
        (BOB, 2)
    };
    let controls = Controls(Rc::new(RefCell::new(Control {
        utc: 100,
        ..Default::default()
    })));
    let gate = Gate::new(
        Config {
            source: "fixture-authority".into(),
            registry: "web:agent.example".into(),
            network: "local".into(),
            blockchain: false,
        },
        Box::new(controls.clone()),
        Box::new(controls.clone()),
        Box::new(Journal::open(Path::new(&args[2]), true)?),
    )?;
    let mut e = CompletionEndpoint010::new(
        did,
        &format!("{did}#signing-1"),
        &[n; 32],
        if n == 2 { &[3; 32] } else { &[] },
        gate,
        Box::new(controls.clone()),
        Box::new(Replay {
            control: controls.clone(),
            seen: HashSet::new(),
        }),
    )?;
    let mut target = "https://agent.example/messages".to_owned();
    let mut p: Option<PendingCompletion010> = None;
    let mut result: Option<AuthenticatedCompletion010> = None;
    let mut mcp_calls = std::collections::BTreeMap::<String, g::MCPSessionCall>::new();
    let mut seen = HashSet::new();
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut count = 0;
    loop {
        let mut line = Vec::new();
        let mut limited = std::io::Read::take(&mut reader, 256 * 1024 + 1);
        if limited.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        count += 1;
        if count > 128 || line.len() > 256 * 1024 {
            return Err("input limit".into());
        };
        let (q, wire) = decode(&line)?;
        if !seen.insert(q.id.clone()) {
            return Err(bad().into());
        }
        {
            let mut c = controls.0.borrow_mut();
            c.expiry = q.key_expires;
            c.mode = q.mode;
            c.mono = q.mono_ms;
            c.utc = q.unix;
        }
        let mut out = json!({});
        let mut verdict = "ACCEPT";
        let outcome = match q.action.as_str() {
            "mcp-seal" => result.as_mut().ok_or_else(bad).and_then(|s| {
                let id=q.message_id.as_deref().ok_or_else(bad)?;
                if mcp_calls.contains_key(id){return Err(bad())}
                let(w,call)=g::seal_mcp_session_request(s,&mut e,&q.target,id,&wire,q.ttl.unwrap_or(300)).map_err(|_|bad())?;
                mcp_calls.insert(id.into(),call);out=json!({"wire_hex":hex::encode(w)});Ok(())
            }),
            "mcp-open" => result.as_mut().ok_or_else(bad).and_then(|s| {
                let call=g::open_mcp_session_request(s,&mut e,&q.target,&wire).map_err(|_|bad())?;
                if mcp_calls.contains_key(call.id()){return Err(bad())}
                out=json!({"rpc_id":call.id(),"rpc_hex":hex::encode(call.request())});mcp_calls.insert(call.id().into(),call);Ok(())
            }),
            "mcp-reply" | "mcp-open-reply" => result.as_mut().ok_or_else(bad).and_then(|s| {
                let call=mcp_calls.get_mut(q.message_id.as_deref().ok_or_else(bad)?).ok_or_else(bad)?;
                let w=if q.action=="mcp-reply"{call.seal_reply(s,&mut e,&wire,q.ttl.unwrap_or(300))}else{call.open_reply(s,&mut e,&wire)}.map_err(|_|bad())?;
                out=json!({"wire_hex":hex::encode(w)});Ok(())
            }),

            "start" => {
                if p.is_some() {
                    Err(bad())
                } else {
                    e.start(BOB, &format!("{BOB}#signing-1"), q.ttl.unwrap_or(300))
                        .map(|(pending, wire)| {
                            out = json!({"state":pending.state(),"wire_hex":hex::encode(wire)});
                            p = Some(pending);
                        })
                }
            }
            "respond" => e.respond(&wire, q.ttl.unwrap_or(300)).map(|(next, wire)| {
                out =
                    json!({"state":next.state(),"tuple":next.tuple(),"wire_hex":hex::encode(wire)});
                result = Some(next);
            }),
            "complete" => p
                .as_mut()
                .ok_or_else(bad)
                .and_then(|pending| pending.complete(&mut e, &wire))
                .map(|next| {
                    out = json!({"state":next.state(),"tuple":next.tuple()});
                    result = Some(next);
                }),




            "http-endpoint-bind" => e.bind_http(&q.target).map(|()|target=q.target.clone()),
            "http-inspect" => {let c=controls.0.borrow();out=json!({"handshakes":c.handshakes,"records":c.records,"pending":p.as_ref().map(|p|p.state()).unwrap_or("NONE"),"session":result.as_ref().map(|s|s.state()).unwrap_or("NONE")});Ok(())},
            "http-start" => {
                if p.is_some() {Err(bad())} else {e.start_http(BOB,&format!("{BOB}#signing-1"),q.ttl.unwrap_or(300)).and_then(|(pending,m)|{let wire=encode_http_010(&m,&target)?;p=Some(pending);out=json!({"wire_hex":hex::encode(wire)});Ok(())})}
            },
            "http-respond-raw" => parse_http_010(&wire,&target,false).and_then(|m|e.respond_http(&m,q.ttl.unwrap_or(300))).and_then(|(mut next,m)|{
                let raw=match encode_http_010(&m,&target){Ok(v)=>v,Err(e)=>{next.close();return Err(e)}};
                if let Some(s)=result.as_mut(){s.close();}result=Some(next);out=json!({"wire_hex":hex::encode(raw)});Ok(())
            }),
            "http-complete-raw" => p.as_mut().ok_or_else(bad).and_then(|p|{
                let m=match parse_http_010(&wire,&target,true){Ok(m)=>m,Err(e)=>{p.close();return Err(e)}};
                let next=p.complete_http(&mut e,&m)?;out=json!({"state":next.state(),"tuple":next.tuple()});if let Some(s)=result.as_mut(){s.close();}result=Some(next);Ok(())
            }),
            "http-record-seal-raw" | "http-response-seal-raw" => result.as_mut().ok_or_else(bad).and_then(|s|{
                let m=if q.action=="http-record-seal-raw"{s.seal_http_request(&mut e,&wire,q.ttl.unwrap_or(300))?}else{let success=q.success.ok_or_else(bad)?;if success && q.error.as_deref().is_some_and(|s|!s.is_empty()){return Err(bad());}s.seal_http_response(&mut e,q.message_id.as_deref().ok_or_else(bad)?,&wire,if success{None}else{Some(q.error.as_deref().ok_or_else(bad)?)},q.ttl.unwrap_or(300),200)?};out=json!({"wire_hex":hex::encode(encode_http_010(&m,&target)?)});Ok(())
            }),
            "http-record-open-raw" | "http-response-open-raw" => result.as_mut().ok_or_else(bad).and_then(|s|{
                let m=parse_http_010(&wire,&target,q.action=="http-response-open-raw")?;
                if q.action=="http-record-open-raw"{out=json!({"plaintext_hex":hex::encode(s.open_http_request(&mut e,&m)?)});}else{let v=s.open_http_response(&mut e,&m)?;out=json!({"message_id":v.message_id,"success":v.success,"error":v.error,"plaintext_hex":hex::encode(v.data)});}Ok(())
            }),
            "http-bind" => result.as_mut().ok_or_else(bad).and_then(|s| s.bind_http("https://agent.example/messages")),
            "http-request-seal" | "http-response-seal" => result.as_mut().ok_or_else(bad).and_then(|s| {
                let m=if q.action=="http-request-seal" { s.seal_http_request(&mut e,&wire,q.ttl.unwrap_or(300))? } else {
                    let success=q.success.ok_or_else(bad)?;
                    if success && q.error.as_deref().is_some_and(|s| !s.is_empty()) {return Err(bad());}
                    s.seal_http_response(&mut e,q.message_id.as_deref().ok_or_else(bad)?,&wire,if success {None} else {Some(q.error.as_deref().ok_or_else(bad)?)},q.ttl.unwrap_or(300),if q.status==0 {200} else {q.status})?
                };
                out=json!({"wire_hex":hex::encode(serde_json::to_vec(&m).map_err(|_|bad())?)});Ok(())
            }),
            "http-request-open" | "http-response-open" => result.as_mut().ok_or_else(bad).and_then(|s| {
                let m:HTTPMessage010=serde_json::from_slice(&wire).map_err(|_|bad())?;
                if q.action=="http-request-open" {let v=s.open_http_request(&mut e,&m)?;out=json!({"plaintext_hex":hex::encode(v)});} else {let v=s.open_http_response(&mut e,&m)?;out=json!({"message_id":v.message_id,"success":v.success,"error":v.error,"plaintext_hex":hex::encode(v.data)});}
                Ok(())
            }),
            "response-seal" => result.as_mut().ok_or_else(bad).and_then(|s| {
                let success=q.success.ok_or_else(bad)?;
                let code=q.error.as_deref().unwrap_or("");
                if success && !code.is_empty(){return Err(bad())}
                s.seal_response(&mut e,q.message_id.as_deref().ok_or_else(bad)?,&wire,if success{None}else{Some(code)},q.ttl.unwrap_or(300)).map(|wire|{out=json!({"wire_hex":hex::encode(wire)})})
            }),
            "response-open" => result.as_mut().ok_or_else(bad).and_then(|s|s.open_response(&mut e,&wire).map(|r|{out=json!({"message_id":r.message_id,"success":r.success,"error":r.error,"plaintext_hex":hex::encode(r.data)})})),
            "record-seal" => result.as_mut().ok_or_else(bad).and_then(|s| {
                s.seal_request(&mut e, &wire, q.ttl.unwrap_or(300))
                    .map(|wire| {
                        out = json!({"wire_hex":hex::encode(wire),"state":s.state()});
                    })
            }),
            "record-open" => result.as_mut().ok_or_else(bad).and_then(|s| {
                s.open_request(&mut e, &wire).map(|plain| {
                    out = json!({"plaintext_hex":hex::encode(plain),"state":s.state()});
                })
            }),
            "record-inspect" => {
                out = json!({"state":result.as_ref().map(|s|s.state()).unwrap_or("NONE"),"reservations":controls.0.borrow().records});
                Ok(())
            }
            "check" => result.as_mut().ok_or_else(bad).and_then(|s| {
                s.check(&mut e).map(|()| {
                    out = json!({"state":s.state()});
                })
            }),
            "close" => {
                if let Some(s) = result.as_mut() {
                    s.close()
                }
                if let Some(p) = p.as_mut() {
                    p.close()
                }
                Ok(())
            }
            "pending-close" => {
                if let Some(p) = p.as_mut() {
                    p.close()
                }
                Ok(())
            }
            "endpoint-close" => {
                e.close();
                Ok(())
            }
            "inspect" => {
                out = json!({"pending_state":p.as_ref().map(|p|p.state()).unwrap_or("NONE"),"result_state":result.as_ref().map(|s|s.state()).unwrap_or("NONE")});
                Ok(())
            }
            "dispatch" => {
                verdict = "UNSUPPORTED";
                Ok(())
            }
            _ => Err(bad()),
        };
        if outcome.is_err() {
            verdict = "REJECT";
            out = json!({})
        }
        println!("{}", json!({"id":q.id,"verdict":verdict,"output":out}));
        io::stdout().flush()?;
    }
    e.close();
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
            r#"{}"#,
            r#"{"id":"x","action":"start","mono_ms":0,"unix":100,"unexpected":true}"#,
            r#"{"id":"x","action":"complete","mono_ms":0,"unix":100}"#,
            r#"{"id":"x","action":"start","mono_ms":0,"unix":100,"mode":"arbitrary"}"#,
        ] {
            assert!(decode(s.as_bytes()).is_err())
        }
        assert!(decode(br#"{"id":"x","action":"start","mono_ms":0,"unix":100}"#).is_ok())
    }
    #[test]
    fn http_controls() {
        for action in [
            "http-request-open",
            "http-response-open",
            "http-respond-raw",
            "http-complete-raw",
            "http-record-open-raw",
            "http-response-open-raw",
        ] {
            for n in [65538, 196608, 196610] {
                let q = json!({"id":"http","action":action,"mono_ms":0,"unix":100,"wire_hex":"0".repeat(n)});
                assert_eq!(
                    decode(&serde_json::to_vec(&q).unwrap()).is_ok(),
                    n <= 196608
                );
            }
        }
        for mut q in [
            json!({"action":"http-request-open"}),
            json!({"action":"http-bind","wire_hex":""}),
            json!({"action":"record-open","wire_hex":"0".repeat(65538)}),
        ] {
            q["id"] = json!("http");
            q["mono_ms"] = json!(0);
            q["unix"] = json!(100);
            assert!(decode(&serde_json::to_vec(&q).unwrap()).is_err());
        }
    }
}
