use sage_crypto_core::session::SecureSession;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Barrier,
};
use std::time::Instant;

// Scoped workers borrow one core. The gate never wraps the core call in a lock.
pub fn open(
    core: &SecureSession,
    input: &Value,
    aad: &[u8],
) -> Result<Value, Box<dyn std::error::Error>> {
    let values = input.as_array().ok_or("missing parallel records")?;
    if values.len() < 2 || values.len() > 16 {
        return Err("parallel worker count must be 2..16".into());
    }
    let mut records = Vec::new();
    for value in values {
        let wire = hex::decode(value.as_str().ok_or("invalid parallel record")?)?;
        if wire.len() > 2048 {
            return Err("invalid parallel record size".into());
        }
        records.push(wire);
    }
    let gate = Barrier::new(records.len() + 1);
    let ready = AtomicUsize::new(0);
    let origin = Instant::now();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (index, wire) in records.iter().enumerate() {
            let gate = &gate;
            let ready = &ready;
            handles.push(scope.spawn(move || {
                ready.fetch_add(1, Ordering::SeqCst);
                gate.wait();
                let began = origin.elapsed().as_nanos();
                let result = core.decrypt_with_aad_inbound(wire, aad);
                let ended = origin.elapsed().as_nanos();
                match result {
                    Ok(plain) => json!({"index":index,"started_ns":began,"finished_ns":ended,"verdict":"ACCEPT","output":{"plaintext_hex":hex::encode(plain)}}),
                    Err(_) => json!({"index":index,"started_ns":began,"finished_ns":ended,"verdict":"REJECT","output":{}}),
                }
            }));
        }
        gate.wait();
        let mut workers = Vec::new();
        for handle in handles {
            workers.push(handle.join().map_err(|_| "parallel core worker panicked")?);
        }
        Ok(
            json!({"verdict":"ACCEPT","output":{"start_gate":"all-ready","workers_ready":ready.load(Ordering::SeqCst),"workers":workers}}),
        )
    })
}
