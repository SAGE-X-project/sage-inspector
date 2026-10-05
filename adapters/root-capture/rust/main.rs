use sage_crypto_core::guard010::{original_commitment, RootCapture};

fn decode_hex(raw: &str) -> Option<Vec<u8>> {
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    raw.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)? as u8;
            let low = (pair[1] as char).to_digit(16)? as u8;
            Some((high << 4) | low)
        })
        .collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(request_id) = args.next() else {
        println!("REJECT");
        return;
    };
    let mut items = Vec::new();
    for encoded in args {
        if items.len() >= 1024 {
            println!("REJECT");
            return;
        }
        let Some(item) = decode_hex(&encoded) else {
            println!("REJECT");
            return;
        };
        items.push(item);
    }
    if RootCapture::new(&items, &request_id).is_err() {
        println!("REJECT");
        return;
    }
    match original_commitment(&items) {
        Ok(digest) => println!("ACCEPT:{digest}"),
        Err(_) => println!("REJECT"),
    }
}
