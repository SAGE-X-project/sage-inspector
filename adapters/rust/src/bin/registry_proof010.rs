use sage_crypto_core::registry010::pop_challenge010;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    case_id: String,
    registry_id: String,
    agent_id: String,
    name: String,
    alg: String,
    public_key_hex: String,
}

#[derive(Serialize)]
struct Response {
    case_id: String,
    verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_sha256: Option<String>,
}

fn evaluate(q: Request) -> Response {
    let mut response = Response {
        case_id: q.case_id,
        verdict: "REJECT",
        challenge_hex: None,
        challenge_sha256: None,
    };
    let Ok(key) = hex::decode(&q.public_key_hex) else {
        return response;
    };
    if hex::encode(&key) != q.public_key_hex {
        return response;
    }
    let Ok(challenge) = pop_challenge010(&q.registry_id, &q.agent_id, &q.name, &q.alg, &key) else {
        return response;
    };
    response.verdict = "ACCEPT";
    response.challenge_hex = Some(hex::encode(&challenge));
    response.challenge_sha256 = Some(hex::encode(Sha256::digest(&challenge)));
    response
}

fn main() {
    let mut raw = Vec::new();
    if io::stdin().take(4097).read_to_end(&mut raw).is_err() || raw.len() > 4096 {
        std::process::exit(2);
    }
    let Ok(request) = serde_json::from_slice::<Request>(&raw) else {
        std::process::exit(2);
    };
    let response = evaluate(request);
    if serde_json::to_writer(io::stdout(), &response).is_err() {
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_ascii_and_bad_hex() {
        let mut q = Request {
            case_id: "local".into(),
            registry_id: "web:agents.example.com".into(),
            agent_id: "billing-bot".into(),
            name: "sign-1".into(),
            alg: "ed25519".into(),
            public_key_hex: "01".into(),
        };
        assert_eq!(evaluate(q.clone()).verdict, "ACCEPT");
        q.agent_id = "agént".into();
        assert_eq!(evaluate(q.clone()).verdict, "REJECT");
        q.agent_id = "billing-bot".into();
        q.public_key_hex = "0G".into();
        assert_eq!(evaluate(q).verdict, "REJECT");
    }
}
