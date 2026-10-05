// External, loopback-only, inert fixture. No deployed registry or general tool.
use ed25519_dalek::{Signer, SigningKey};
use sage_crypto_core::hpke::completion010::{CompletionEndpoint010, ReplayJournal010};
use sage_crypto_core::{guard010 as g, registry010 as r};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
const ALICE: &str = "did:sage:web:agent.example:alice";
const BOB: &str = "did:sage:web:agent.example:bob";
const REQUEST: &str = "00000000-0000-4000-8000-000000000002";
const INSTANCE: &[u8] = b"inert-exact-read-v1";
fn need(value: bool) -> g::Result<()> {
    if value {
        Ok(())
    } else {
        Err(g::Invalid)
    }
}
fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[derive(Clone)]
struct Clock(Arc<AtomicI64>);
impl r::Clock for Clock {
    fn now(&mut self) -> sage_crypto_core::error::Result<r::Stamp> {
        let m = self.0.load(Ordering::SeqCst);
        Ok(r::Stamp {
            mono_ms: m,
            unix: 100 + m / 1000,
        })
    }
}
impl g::ClientClock for Clock {
    fn sample(&mut self) -> g::Result<(i64, i64)> {
        let m = self.0.load(Ordering::SeqCst);
        Ok((100000 + m, m))
    }
}
struct Source(Clock);
impl r::Source for Source {
    fn read(&mut self, did: &str) -> sage_crypto_core::error::Result<r::Snapshot> {
        if did != ALICE && did != BOB {
            return Err(sage_crypto_core::error::Error::InvalidInput(
                "fixture identity".into(),
            ));
        }
        let n = if did == BOB { 2 } else { 1 };
        let mut keys = vec![r::Key {
            name: "signing-1".into(),
            alg: "ed25519".into(),
            material: hex::encode(SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes()),
            state: "accepted".into(),
            expires: None,
        }];
        if did == BOB {
            keys.insert(
                0,
                r::Key {
                    name: "kem-1".into(),
                    alg: "x25519".into(),
                    material: hex::encode(x25519_dalek::x25519(
                        [3; 32],
                        x25519_dalek::X25519_BASEPOINT_BYTES,
                    )),
                    state: "accepted".into(),
                    expires: None,
                },
            );
        }
        Ok(r::Snapshot {
            source: "external-fixture".into(),
            registry: "web:agent.example".into(),
            network: "local".into(),
            did: did.into(),
            version: "1".into(),
            state: "active".into(),
            digest: "a".repeat(64),
            ready: true,
            validated: true,
            finalized: true,
            conflicting: false,
            acquired_ms: self.0 .0.load(Ordering::SeqCst),
            block_hash: String::new(),
            keys_block_hash: String::new(),
            keys,
        })
    }
}
fn config() -> r::Config {
    r::Config {
        source: "external-fixture".into(),
        registry: "web:agent.example".into(),
        network: "local".into(),
        blockchain: false,
    }
}
fn authority(root: &Path, mode: &str, name: &str, did: &str, c: &Clock) -> g::RegistryAuthority {
    let gate = r::SendGate::new_send(
        config(),
        Box::new(Source(c.clone())),
        Box::new(c.clone()),
        Box::new(r::Journal::open(&root.join(format!("{mode}-{name}")), true).unwrap()),
    )
    .unwrap();
    g::RegistryAuthority::new(gate, did, &format!("{did}#signing-1")).unwrap()
}
fn manifest() -> Vec<u8> {
    bytes(&json!({"version":"0.10.0","files":[{"path":"component.bin","sha256":hash(INSTANCE)}]}))
}
fn policy() -> Vec<u8> {
    bytes(
        &json!({"version":"0.10.0","issuer":ALICE,"epoch":"00000000-0000-4000-8000-000000000001","engine":"external-consumer-fixture/1","artifacts":serde_json::from_slice::<Value>(&manifest()).unwrap()}),
    )
}
struct Policy;
impl g::IntentPolicy for Policy {
    fn bindings(&mut self, i: &str, id: &str) -> g::Result<g::Bindings> {
        need(i == ALICE && id == REQUEST)?;
        Ok(g::Bindings {
            original: g::original_commitment(&[b"trusted root input".to_vec()])?,
            policy: policy(),
            manifest: manifest(),
        })
    }
    fn authorize(&mut self, i: &str, tool: &str, args: &[u8]) -> g::Result<()> {
        need(i == ALICE && tool == "read" && args == br#"{"path":"public.txt"}"#)
    }
}
impl g::IssuancePolicy for Policy {
    fn approve_intent(&mut self, raw: &[u8]) -> g::Result<()> {
        let i: Value = serde_json::from_slice(raw).map_err(|_| g::Invalid)?;
        need(
            i["issuer"] == ALICE
                && i["recipient"] == BOB
                && i["request_id"] == REQUEST
                && i["tool"] == "read"
                && i["arguments"] == json!({"path":"public.txt"}),
        )
    }
}
struct Loaded {
    material: Vec<u8>,
    effects: AtomicI64,
}
impl Loaded {
    fn check(&self, m: &str, t: &str) -> g::Result<()> {
        need(t == "read" && m == g::manifest_commitment(&manifest())? && self.material == INSTANCE)
    }
}
struct Measurement(Arc<Loaded>);
impl g::IntentMeasurement for Measurement {
    fn check(&mut self, m: &str, t: &str) -> g::Result<()> {
        self.0.check(m, t)
    }
}
impl g::MCPExecutor for Loaded {
    fn check(&self, m: &str, t: &str) -> g::Result<()> {
        self.check(m, t)
    }
    fn run(&self, i: &g::Invocation, c: &g::MCPCancellation) -> g::Result<Vec<u8>> {
        need(!c.cancelled() && i.arguments() == br#"{"path":"public.txt"}"#)?;
        self.check(i.manifest_digest(), "read")?;
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(br#"{"ok":true}"#.to_vec())
    }
}
struct NoSend;
impl g::ClientSender for NoSend {
    fn commit(&mut self, _: &str, _: &[u8]) -> g::Result<()> {
        Err(g::Invalid)
    }
}
struct IntentSigner {
    root: PathBuf,
    calls: Arc<AtomicI64>,
    body: Arc<Mutex<Vec<u8>>>,
    fail: bool,
}
impl g::IntentSigner for IntentSigner {
    fn sign(&mut self, key: &str, msg: &[u8]) -> g::Result<Vec<u8>> {
        let domain = b"sage-execution-intent|0.10.0\0";
        need(key == format!("{ALICE}#signing-1") && msg.starts_with(domain))?;
        let marker = fs::read(self.root.join("client-journal.issuance")).map_err(|_| g::Invalid)?;
        need(
            marker
                == format!(
                    "sage-intent-issuance|0.10.0\n{}\n",
                    hash(&msg[domain.len()..])
                )
                .as_bytes(),
        )?;
        *self.body.lock().map_err(|_| g::Invalid)? = msg[domain.len()..].to_vec();
        self.calls.fetch_add(1, Ordering::SeqCst);
        need(!self.fail)?;
        Ok(SigningKey::from_bytes(&[1; 32])
            .sign(msg)
            .to_bytes()
            .to_vec())
    }
}
struct ResultSigner(Clock);
impl g::Authority for ResultSigner {
    fn now(&mut self) -> g::Result<i64> {
        Ok(100 + self.0 .0.load(Ordering::SeqCst) / 1000)
    }
    fn active_key(&mut self, i: &str, k: &str) -> g::Result<[u8; 32]> {
        need(i == BOB && k == format!("{BOB}#signing-1"))?;
        Ok(SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes())
    }
}
impl g::ResultSigner for ResultSigner {
    fn key_id(&mut self) -> g::Result<String> {
        Ok(format!("{BOB}#signing-1"))
    }
    fn sign(&mut self, k: &str, b: &[u8]) -> g::Result<Vec<u8>> {
        need(k == format!("{BOB}#signing-1"))?;
        Ok(SigningKey::from_bytes(&[2; 32]).sign(b).to_bytes().to_vec())
    }
}
struct Handler {
    root: PathBuf,
    mode: String,
    scenario: String,
    c: Clock,
    loaded: Arc<Loaded>,
    signs: Arc<AtomicI64>,
    body: Arc<Mutex<Vec<u8>>>,
    completed: bool,
    before: Vec<u8>,
    stage: String,
    owned_capture: String,
    prepare_denied: Arc<Mutex<bool>>,
}
impl g::MCPConnectionHandler for Handler {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        let registry = r::Gate::new(
            config(),
            Box::new(Source(self.c.clone())),
            Box::new(self.c.clone()),
            Box::new(
                r::Journal::open(
                    &self.root.join(format!("{}-endpoint-registry", self.mode)),
                    true,
                )
                .map_err(|_| g::Invalid)?,
            ),
        )
        .map_err(|_| g::Invalid)?;
        let replay = ReplayJournal010::open(
            &self.root.join(format!("{}-endpoint-replay", self.mode)),
            true,
            Box::new(self.c.clone()),
        )
        .map_err(|_| g::Invalid)?;
        let client = self.mode == "client";
        let did = if client { ALICE } else { BOB };
        let kem = if client { vec![] } else { vec![3; 32] };
        let endpoint = CompletionEndpoint010::new(
            did,
            &format!("{did}#signing-1"),
            &[if client { 1 } else { 2 }; 32],
            &kem,
            registry,
            Box::new(self.c.clone()),
            Box::new(replay),
        )
        .map_err(|_| g::Invalid)?;
        self.c.0.store(360000, Ordering::SeqCst);
        Ok(endpoint)
    }
    fn prepare(&mut self) -> g::Result<()> {
        if self.mode == "server" && self.scenario == "readiness-denied" {
            *self.prepare_denied.lock().map_err(|_| g::Invalid)? = true;
            return Err(g::Invalid);
        };
        Ok(())
    }
    fn handle(&mut self, connection: &mut g::MCPConnection<'_>) -> g::Result<()> {
        if self.mode == "server" {
            while connection
                .serve_one(&mut ResultSigner(self.c.clone()))
                .is_ok()
            {}
            return Ok(());
        }
        self.stage = "capture".into();
        let capture = g::RootCapture::new(&[b"trusted root input".to_vec()], REQUEST)?;
        let loaded = if self.scenario == "measurement-denied" {
            Arc::new(Loaded {
                material: b"changed fixture".to_vec(),
                effects: AtomicI64::new(0),
            })
        } else {
            self.loaded.clone()
        };
        let services = g::IssuerServices {
            client: g::ClientServices {
                intent_authority: Box::new(authority(
                    &self.root,
                    &self.mode,
                    "issuer-intent",
                    ALICE,
                    &self.c,
                )),
                result_authority: Box::new(authority(
                    &self.root,
                    &self.mode,
                    "issuer-result",
                    BOB,
                    &self.c,
                )),
                policy: Box::new(Policy),
                clock: Box::new(self.c.clone()),
                sender: Box::new(NoSend),
                expected_issuer: ALICE.into(),
                expected_recipient: BOB.into(),
            },
            policy: Box::new(Policy),
            signer: Box::new(IntentSigner {
                root: self.root.clone(),
                calls: self.signs.clone(),
                body: self.body.clone(),
                fail: self.scenario == "signing-denied",
            }),
            measurement: Box::new(Measurement(loaded)),
            key_id: format!("{ALICE}#signing-1"),
        };
        let mut issuer = g::IntentIssuer::new(capture, services)?;
        let args = if self.scenario == "policy-denied" {
            br#"{"path":"other.txt"}"#.to_vec()
        } else {
            br#"{"path":"public.txt"}"#.to_vec()
        };
        self.stage = "authorizing".into();
        let mut token = issuer.authorize(g::IntentProposal {
            tool: "read".into(),
            arguments: args,
            lifetime_seconds: 300,
        })?;
        let path = self.root.join("client-journal");
        self.stage = "issuing".into();
        let durable = issuer.issue(&path, &mut token)?;
        let raw = durable.journaled_intent()?;
        durable.close()?;
        issuer.retire()?;
        self.before = fs::read(&path).map_err(|_| g::Invalid)?;
        let capture = g::RootCapture::new(
            &[if self.scenario == "capture-denied" {
                b"changed root".to_vec()
            } else {
                b"trusted root input".to_vec()
            }],
            REQUEST,
        )?;
        self.owned_capture = g::original_commitment(&[if self.scenario == "capture-denied" {
            b"changed root".to_vec()
        } else {
            b"trusted root input".to_vec()
        }])?;
        self.stage = "opening".into();
        connection.open_root_client(
            &path,
            false,
            &raw,
            g::MCPClientServices {
                intent_authority: authority(&self.root, &self.mode, "owned-intent", ALICE, &self.c),
                result_authority: authority(&self.root, &self.mode, "owned-result", BOB, &self.c),
                policy: Box::new(Policy),
                clock: Box::new(self.c.clone()),
            },
            capture,
        )?;
        self.stage = "exchanging".into();
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(20));
            self.c.0.fetch_add(1000, Ordering::SeqCst);
            let d = connection.exchange()?;
            if d.status() == "completed" {
                need(d.first_terminal() && d.output() == br#"{"ok":true}"#)?;
                self.stage = "completed".into();
                self.completed = true;
                return Ok(());
            }
        }
        Err(g::Invalid)
    }
}
fn read(path: &Path) -> String {
    if !path.exists() {
        String::new()
    } else {
        hex::encode(fs::read(path).unwrap())
    }
}
fn main() {
    let root = PathBuf::from(std::env::var("SAGE_CONSUMER_ROOT").unwrap());
    let mode = std::env::var("SAGE_CONSUMER_MODE").unwrap();
    let scenario = std::env::var("SAGE_CONSUMER_SCENARIO").unwrap();
    assert!(["client", "server"].contains(&mode.as_str()));
    assert!([
        "allowed",
        "policy-denied",
        "measurement-denied",
        "capture-denied",
        "readiness-denied",
        "signing-denied"
    ]
    .contains(&scenario.as_str()));
    let c = Clock(Arc::new(AtomicI64::new(0)));
    let loaded = Arc::new(Loaded {
        material: INSTANCE.to_vec(),
        effects: AtomicI64::new(0),
    });
    let signs = Arc::new(AtomicI64::new(0));
    let body = Arc::new(Mutex::new(Vec::new()));
    let prepare_denied = Arc::new(Mutex::new(false));
    let ledger = root.join(format!("{mode}-gate"));
    let host = g::MCPHost::open(
        &ledger,
        true,
        BOB,
        g::MCPHostServices {
            intent_authority: authority(&root, &mode, "host-intent", ALICE, &c),
            result_authority: authority(&root, &mode, "host-result", BOB, &c),
            policy: Box::new(Policy),
            executor: loaded.clone(),
            signers: vec![Box::new(ResultSigner(c.clone()))],
            clock: Box::new(c.clone()),
        },
        g::MCPHostBounds {
            capacity: 2,
            preparations: 2,
            clients: 2,
            owners: 4,
            workers: 1,
            request: Duration::from_secs(20),
            claim: Duration::from_secs(10),
            worker: Duration::from_secs(1),
            client: Duration::from_secs(20),
            tick: Duration::from_millis(1),
        },
    )
    .unwrap();
    let mut handler = Handler {
        root: root.clone(),
        mode: mode.clone(),
        scenario: scenario.clone(),
        c: c.clone(),
        loaded: loaded.clone(),
        signs: signs.clone(),
        body: body.clone(),
        completed: false,
        before: vec![],
        stage: String::new(),
        owned_capture: String::new(),
        prepare_denied: prepare_denied.clone(),
    };
    let cfg = g::MCPConnectionConfig {
        role: if mode == "client" {
            g::MCPRole::Initiator {
                recipient: BOB.into(),
                key: format!("{BOB}#signing-1"),
            }
        } else {
            g::MCPRole::Responder
        },
        name: "external fixture".into(),
        version: "1".into(),
        ttl_seconds: 300,
        timeout: Duration::from_secs(3),
    };
    let mut status = "completed";
    if mode == "server" {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        fs::write(root.join("address"), tcp.local_addr().unwrap().to_string()).unwrap();
        let listener = host.serve(tcp, cfg, vec![Box::new(handler)]).unwrap();
        let end = Instant::now() + Duration::from_secs(15);
        while !root.join("finished").exists() {
            assert!(Instant::now() < end);
            thread::sleep(Duration::from_millis(10))
        }
        assert!(listener.close(Duration::from_secs(3)).unwrap());
        handler = Handler {
            root: root.clone(),
            mode: mode.clone(),
            scenario,
            c,
            loaded: loaded.clone(),
            signs: signs.clone(),
            body: body.clone(),
            completed: false,
            before: vec![],
            stage: String::new(),
            owned_capture: String::new(),
            prepare_denied: prepare_denied.clone(),
        };
    } else {
        let address: std::net::SocketAddr = fs::read_to_string(root.join("address"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            address.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_ne!(address.port(), 0);
        let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
        let outcome = host.connect(tcp, &cfg, &mut handler);
        if scenario == "allowed" {
            outcome.unwrap();
            assert!(handler.completed)
        } else {
            assert!(outcome.is_err() && !handler.completed);
            status = "denied"
        };
        fs::write(root.join("finished"), b"done").unwrap()
    }
    assert!(host.close(Duration::from_secs(3)).unwrap());
    let mut record = json!({"mode":mode,"status":status,"effects":loaded.effects.load(Ordering::SeqCst),"ledger_hex":read(&ledger),"prepare_denied":*prepare_denied.lock().unwrap()});
    if mode == "client" {
        record["journal_hex"] = json!(read(&root.join("client-journal")));
        record["fence_hex"] = json!(read(&root.join("client-journal.issuance")));
        record["before_transfer_hex"] = json!(hex::encode(&handler.before));
        record["stage"] = json!(handler.stage);
        record["owned_capture_digest"] = json!(handler.owned_capture);
        record["sign_calls"] = json!(signs.load(Ordering::SeqCst));
        record["issuance_body_hex"] = json!(hex::encode(&*body.lock().unwrap()))
    };
    fs::write(root.join(format!("{mode}.json")), bytes(&record)).unwrap();
    println!("EXTERNAL_MCP_CONSUMER")
}
