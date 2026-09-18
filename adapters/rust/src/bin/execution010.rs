//! Owned local ledger controls, not an authenticated execution endpoint.
use sage_crypto_core::execution010::{Entry, Ledger};
use serde::Deserialize;
use std::io::{self, BufRead, Write};
use std::path::Path;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    entry: Option<Entry>,
    issuer: Option<String>,
    call_id: Option<String>,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !matches!(args[2].as_str(), "create" | "reopen") {
        return Err("arguments".into());
    }
    let path = Path::new(&args[1]);
    let mut ledger = Ledger::open(path, args[2] == "create")?;
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    let mut count = 0;
    loop {
        let mut line = Vec::new();
        let read =
            std::io::Read::take(&mut input, 5 * 1024 * 1024 + 1).read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        count += 1;
        if read > 5 * 1024 * 1024 || count > 128 {
            return Err("input bound".into());
        }
        let q: Request = serde_json::from_slice(&line)?;
        let mut changed = false;
        let mut entry = None;
        if q.action == "abandon" {
            writeln!(
                out,
                "{}",
                serde_json::json!({"ok":true,"changed":false,"entry":null})
            )?;
            out.flush()?;
            std::process::exit(0);
        }
        let result = match q.action.as_str() {
            "commit" => ledger.commit(q.entry.ok_or("entry")?).map(|v| changed = v),
            "lookup" => ledger
                .lookup(&q.issuer.ok_or("issuer")?, &q.call_id.ok_or("call")?)
                .map(|v| entry = v),
            "reopen" => ledger
                .close()
                .and_then(|_| Ledger::open(path, false))
                .map(|v| ledger = v),
            _ => return Err("action".into()),
        };
        writeln!(
            out,
            "{}",
            serde_json::json!({"ok":result.is_ok(),"changed":changed,"entry":entry})
        )?;
        out.flush()?;
    }
    ledger.close()?;
    Ok(())
}
fn main() {
    if run().is_err() {
        std::process::exit(2);
    }
}
