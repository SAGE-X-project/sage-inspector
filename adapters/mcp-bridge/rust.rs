use super::*;

struct BridgeClock;
impl r::Clock for BridgeClock {
    fn now(&mut self) -> Result<Stamp> {
        let mono = std::env::var("SAGE_BRIDGE_DIR")
            .ok()
            .and_then(|d| std::fs::read_to_string(std::path::Path::new(&d).join("clock")).ok())
            .map(|s| s.parse::<i64>().unwrap())
            .unwrap_or(360000);
        Ok(Stamp {
            mono_ms: mono,
            unix: 100 + mono / 1000,
        })
    }
}
struct BridgeHandler {
    initiator: bool,
    dir: std::path::PathBuf,
    ready: bool,
    sink: Arc<Sink>,
}
impl Handler for BridgeHandler {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        let (a, b, controls, dir) = pair();
        controls.0.borrow_mut().utc = 460;
        controls.0.borrow_mut().mono = 360000;
        let mut endpoint = if self.initiator { a } else { b };
        endpoint.clock = Box::new(BridgeEndpointClock(controls));
        endpoint.replay = Box::new(KeepReplay {
            inner: endpoint.replay,
            _dir: dir,
        });
        Ok(endpoint)
    }
    fn handle(&mut self, connection: &mut Connection) -> g::Result<()> {
        if connection.closer()?.closed() {
            return Err(g::Invalid);
        }
        // Connection::establish invokes handlers only after real setup READY.
        let role = if self.initiator { "client" } else { "server" };
        if std::env::var("SAGE_BRIDGE_PROTECTED").as_deref() == Ok("1") {
            let observation = if self.initiator {
                let intent = std::fs::read(self.dir.join("intent.json")).unwrap();
                connection.open_client(
                    &self.dir.join("client.journal"),
                    true,
                    &intent,
                    OwnedServices {
                        intent_authority: bridge_authority(ALICE),
                        result_authority: bridge_authority(BOB),
                        policy: Box::new(Policy),
                        clock: Box::new(BridgeClientClock),
                    },
                )?;
                let mut terminal = None;
                let mut attempts = 0;
                for _ in 0..4 {
                    if attempts > 0 {
                        bridge_write(
                            self.dir.join("clock"),
                            (360000 + attempts * 1000).to_string(),
                        )
                        .unwrap();
                    }
                    attempts += 1;
                    let delivery = connection.exchange()?;
                    if delivery.status() == "completed" {
                        terminal = Some(delivery);
                        break;
                    }
                    if delivery.status() != "pending" {
                        return Err(g::Invalid);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let delivery = terminal.ok_or(g::Invalid)?;
                if !delivery.first_terminal()
                    || delivery.output() != br#"{"text":"inert public fixture"}"#
                {
                    return Err(g::Invalid);
                }
                if connection.exchange().is_ok() {
                    return Err(g::Invalid);
                }
                json!({"role":role,"state":"READY","status":"completed","first_terminal":true,
                    "output_hex":hex::encode(delivery.output()),"attempts":attempts,"repeat_denied":true})
            } else {
                while connection.serve_one(&mut BridgeSigner).is_ok() {}
                if self.sink.effects.load(Ordering::SeqCst) != 1 {
                    return Err(g::Invalid);
                }
                json!({"role":role,"state":"READY","effects":1})
            };
            bridge_write(
                self.dir.join(format!("{role}.json")),
                serde_json::to_vec(&observation).unwrap(),
            )
            .unwrap();
            self.ready = true;
            return Ok(());
        }
        bridge_write(
            self.dir.join(format!("{role}.json")),
            serde_json::to_vec(&json!({"role":role,"state":"READY","protected":"NOT_RUN"}))
                .unwrap(),
        )
        .unwrap();
        self.ready = true;
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if self.dir.join("release").exists() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Err(g::Invalid)
    }
}
#[test]
fn inspector_mcp_bridge() {
    let dir = std::path::PathBuf::from(std::env::var("SAGE_BRIDGE_DIR").unwrap());
    let role = std::env::var("SAGE_BRIDGE_ROLE").unwrap();
    assert!(["client", "server"].contains(&role.as_str()));
    let initiator = role == "client";
    let tmp = tempfile::tempdir().unwrap();
    let sink = Arc::new(Sink::default());
    let gate = Arc::new(
        MCPGate::open(
            &tmp.path().join("execution"),
            true,
            BOB,
            bridge_authority(ALICE),
            bridge_authority(BOB),
            Box::new(Policy),
            sink.clone(),
            Box::new(BridgeClock),
            1,
            30000,
            1000,
        )
        .unwrap(),
    );
    let clients = Arc::new(ClientPool::new(1, 30000).unwrap());
    let owners = OwnerMonitor::start(2, Duration::from_millis(1), Box::new(BridgeClock)).unwrap();
    gate.attach_owners(owners.registry()).unwrap();
    clients.attach_owners(owners.registry()).unwrap();
    let workers = Workers::start(
        gate.clone(),
        vec![Box::new(BridgeSigner)],
        Duration::from_millis(1),
        30000,
    )
    .unwrap();
    let host = Host::start(
        gate.clone(),
        clients,
        owners,
        workers,
        1,
        Box::new(BridgeClock),
    )
    .unwrap();
    let tcp = if initiator {
        let addr: std::net::SocketAddr =
            std::env::var("SAGE_BRIDGE_PEER").unwrap().parse().unwrap();
        assert_eq!(
            addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        TcpStream::connect_timeout(&addr, Duration::from_secs(3)).unwrap()
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        bridge_write(
            dir.join("address"),
            listener.local_addr().unwrap().to_string(),
        )
        .unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < end);
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("{e}"),
            }
        }
    };
    let mut handler = BridgeHandler {
        initiator,
        dir: dir.clone(),
        ready: false,
        sink,
    };
    let result = host.connection(
        tcp,
        &config(initiator, Duration::from_secs(10)),
        &mut handler,
    );
    assert!(handler.ready, "setup did not reach READY: {result:?}");
    let protected = std::env::var("SAGE_BRIDGE_PROTECTED").as_deref() == Ok("1");
    assert!(protected || dir.join("release").exists());
    assert!(host.stop(Duration::from_secs(3)).unwrap());
    gate.close().unwrap();
    if protected && !initiator {
        bridge_write(
            dir.join("server.journal"),
            std::fs::read(tmp.path().join("execution")).unwrap(),
        )
        .unwrap();
    }
}

fn bridge_write(path: std::path::PathBuf, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

fn bridge_authority(did: &str) -> g::RegistryAuthority {
    let registry = r::SendGate::new_send(
        r::Config {
            source: "admission-fixture".into(),
            registry: "web:agent.example".into(),
            network: "local".into(),
            blockchain: false,
        },
        Box::new(BridgeSource),
        Box::new(BridgeClock),
        Box::new(Store),
    )
    .unwrap();
    g::RegistryAuthority::new(registry, did, &format!("{did}#signing-1")).unwrap()
}

struct BridgeSigner;
impl g::Authority for BridgeSigner {
    fn now(&mut self) -> g::Result<i64> {
        Ok(BridgeClock.now().unwrap().unix)
    }
    fn active_key(&mut self, issuer: &str, kid: &str) -> g::Result<[u8; 32]> {
        Signer.active_key(issuer, kid)
    }
}
impl g::ResultSigner for BridgeSigner {
    fn key_id(&mut self) -> g::Result<String> {
        Signer.key_id()
    }
    fn sign(&mut self, kid: &str, msg: &[u8]) -> g::Result<Vec<u8>> {
        Signer.sign(kid, msg)
    }
}
struct BridgeClientClock;
impl g::ClientClock for BridgeClientClock {
    fn sample(&mut self) -> g::Result<(i64, i64)> {
        let now = BridgeClock.now().unwrap();
        Ok((now.unix * 1000, now.mono_ms))
    }
}

struct BridgeEndpointClock(Controls);
impl r::Clock for BridgeEndpointClock {
    fn now(&mut self) -> Result<Stamp> {
        let now = BridgeClock.now()?;
        self.0 .0.borrow_mut().utc = now.unix;
        self.0 .0.borrow_mut().mono = now.mono_ms;
        Ok(now)
    }
}

struct BridgeSource;
impl r::Source for BridgeSource {
    fn read(&mut self, did: &str) -> Result<r::Snapshot> {
        Source(Local(Arc::new(AtomicI64::new(BridgeClock.now()?.mono_ms)))).read(did)
    }
}
