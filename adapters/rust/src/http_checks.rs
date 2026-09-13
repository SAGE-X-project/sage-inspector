use http::{Request, Response};
use sage_crypto_core::crypto::{KeyType, PublicKey};
use sage_crypto_core::rfc9421::{
    canonicalize, dictionary,
    verifier::{HttpVerifier, VerifyOptions},
    SignatureComponent,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    request_hex: String,
    response_hex: String,
    public_key_hex: String,
    body_repeat: usize,
}
type Error = Box<dyn std::error::Error>;
fn request(raw: &[u8]) -> Result<Request<Vec<u8>>, Error> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Request::new(&mut headers);
    let n = match parsed.parse(raw)? {
        httparse::Status::Complete(n) => n,
        _ => return Err("incomplete request".into()),
    };
    let mut b = Request::builder()
        .method(parsed.method.ok_or("missing method")?)
        .uri(parsed.path.ok_or("missing target")?);
    for h in parsed.headers {
        b = b.header(h.name, h.value);
    }
    Ok(b.body(raw[n..].to_vec())?)
}
fn response(raw: &[u8]) -> Result<Response<Vec<u8>>, Error> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Response::new(&mut headers);
    let n = match parsed.parse(raw)? {
        httparse::Status::Complete(n) => n,
        _ => return Err("incomplete response".into()),
    };
    let mut b = Response::builder().status(parsed.code.ok_or("missing status")?);
    for h in parsed.headers {
        b = b.header(h.name, h.value);
    }
    Ok(b.body(raw[n..].to_vec())?)
}
pub fn observe(op: &str, input: Value) -> Result<(&'static str, Value), Error> {
    // Neither fixed-clock injection nor a complete SAGE HTTP boundary is exposed.
    if op == "sage.http.verify" {
        return Ok(("UNSUPPORTED", json!({})));
    }
    let i: Input = serde_json::from_value(input)?;
    let mut raw = hex::decode(i.request_hex)?;
    let raw_response = hex::decode(i.response_hex)?;
    if i.body_repeat < 1 || i.body_repeat > (16 << 20) + 1 {
        return Err("invalid repeat control".into());
    }
    if i.body_repeat > 1 {
        let at = raw
            .windows(4)
            .position(|s| s == b"\r\n\r\n")
            .ok_or("missing boundary")?
            + 4;
        if raw.len() != at + 1 {
            return Err("repeat needs one body byte".into());
        }
        let byte = raw[at];
        raw.resize(at + i.body_repeat, byte);
    }
    let req = if raw.is_empty() {
        None
    } else {
        match request(&raw) {
            Ok(r) => Some(r),
            Err(_) => return Ok(("REJECT", json!({}))),
        }
    };
    let resp = if raw_response.is_empty() {
        None
    } else {
        match response(&raw_response) {
            Ok(r) => Some(r),
            Err(_) => return Ok(("REJECT", json!({}))),
        }
    };
    let h = if let Some(r) = &resp {
        r.headers()
    } else {
        req.as_ref().ok_or("missing message")?.headers()
    };
    let result = (|| -> Result<Value, Error> {
        match op {
            "rfc9421.base" => {
                let fields = dictionary::parse_signature_input(
                    h.get("signature-input").ok_or("missing input")?.to_str()?,
                )?;
                let member = fields.get("sig1").ok_or("missing sig1")?;
                let values = if let Some(r) = &resp {
                    canonicalize::canonicalize_response(r, req.as_ref(), &member.components)?
                } else {
                    canonicalize::canonicalize_request(
                        req.as_ref().ok_or("missing request")?,
                        &member.components,
                    )?
                };
                Ok(
                    json!({"base_hex":hex::encode(canonicalize::build_signature_base(&values,&member.raw))}),
                )
            }
            "sage.content-digest" => {
                let body = if let Some(r) = &resp {
                    r.body()
                } else {
                    req.as_ref().ok_or("missing request")?.body()
                };
                canonicalize::verify_content_digest(
                    h.get("content-digest").ok_or("missing digest")?.to_str()?,
                    body,
                )?;
                Ok(json!({"valid":true}))
            }
            "rfc9421.archived.verify" => {
                let key =
                    PublicKey::from_bytes(KeyType::Ed25519, &hex::decode(&i.public_key_hex)?)?;
                let v = HttpVerifier::new(key);
                let mut options = if resp.is_some() {
                    VerifyOptions::strict_response()
                } else {
                    VerifyOptions::strict_request()
                };
                options.max_age = None;
                options.label = Some("sig1".into());
                let coverage = if resp.is_some() {
                    vec![
                        "@status",
                        "\"@method\";req",
                        "\"@target-uri\";req",
                        "\"@authority\";req",
                        "\"content-digest\";req",
                        "\"signature\";req",
                        "\"x-sage-version\";req",
                        "content-type",
                        "content-digest",
                        "x-sage-did",
                        "x-sage-version",
                    ]
                } else {
                    vec![
                        "@method",
                        "@target-uri",
                        "@authority",
                        "content-type",
                        "content-digest",
                        "x-sage-did",
                        "x-sage-version",
                    ]
                };
                options.required_components = coverage
                    .iter()
                    .map(|s| SignatureComponent::parse(s))
                    .collect::<sage_crypto_core::error::Result<_>>()?;
                if let Some(r) = &resp {
                    v.verify_response(
                        r,
                        req.as_ref().ok_or("missing request context")?,
                        Some(r.body()),
                        &options,
                    )?
                } else {
                    options.expected_authorities = vec!["agent.example".into()];
                    let r = req.as_ref().ok_or("missing request")?;
                    v.verify_request_with(r, Some(r.body()), &options)?;
                }
                Ok(json!({"valid":true}))
            }
            _ => Err("unsupported operation".into()),
        }
    })();
    Ok(match result {
        Ok(o) => ("ACCEPT", o),
        Err(_) => ("REJECT", json!({})),
    })
}
