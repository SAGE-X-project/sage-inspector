use super::*;

struct BridgeClock;
impl r::Clock for BridgeClock {
    fn now(&mut self) -> Result<Stamp> {
        Ok(Stamp {
            mono_ms: 360000,
            unix: 460,
        })
    }
}
struct BridgeHandler {
    initiator: bool,
    dir: std::path::PathBuf,
    ready: bool,
}
impl Handler for BridgeHandler {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        let (a, b, controls, dir) = pair();
        controls.0.borrow_mut().utc = 460;
        controls.0.borrow_mut().mono = 360000;
        let mut endpoint = if self.initiator { a } else { b };
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
    let authority = |did: &str| {
        let registry = r::SendGate::new_send(
            r::Config {
                source: "admission-fixture".into(),
                registry: "web:agent.example".into(),
                network: "local".into(),
                blockchain: false,
            },
            Box::new(Source(Local(Arc::new(AtomicI64::new(360000))))),
            Box::new(BridgeClock),
            Box::new(Store),
        )
        .unwrap();
        g::RegistryAuthority::new(registry, did, &format!("{did}#signing-1")).unwrap()
    };
    let gate = Arc::new(
        MCPGate::open(
            &tmp.path().join("execution"),
            true,
            BOB,
            authority(ALICE),
            authority(BOB),
            Box::new(Policy),
            Arc::new(Sink::default()),
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
        vec![Box::new(Signer)],
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
    };
    let result = host.connection(
        tcp,
        &config(initiator, Duration::from_secs(10)),
        &mut handler,
    );
    assert!(handler.ready, "setup did not reach READY: {result:?}");
    assert!(dir.join("release").exists());
    assert!(host.stop(Duration::from_secs(3)).unwrap());
    gate.close().unwrap();
}

fn bridge_write(path: std::path::PathBuf, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}
