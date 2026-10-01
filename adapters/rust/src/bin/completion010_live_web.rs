//! Explicit local Registry service source for bounded Inspector observations.

use super::{alice, bob, registry};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sage_crypto_core::{
    error::{Error, Result},
    registry010::{
        check_web_registry_history_continuity_010, fetch_web_registry_record_010, Key, Snapshot,
        Stamp, WebRegistryHistoryEntry010,
    },
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ORIGIN: &str = "https://agent.example";
const ADMIN_HOST: &str = "admin.example.com";
const MAX_INSPECTION: usize = 1_048_576;

fn rejected() -> Error {
    Error::ValidationError("record.rejected".into())
}
fn stale() -> Error {
    Error::ValidationError("record.stale".into())
}
fn unreachable() -> Error {
    Error::ValidationError("record.unreachable".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination {
    public: String,
    admin: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    origin: String,
    admin_host: String,
    root_der: String,
    inspector_cert: PathBuf,
    inspector_key: PathBuf,
    agents: BTreeMap<String, Destination>,
}

fn destinations(
    agents: &BTreeMap<String, Destination>,
) -> Result<BTreeMap<String, (SocketAddr, SocketAddr)>> {
    if agents.len() != 2 || !agents.contains_key(alice()) || !agents.contains_key(bob()) {
        return Err(rejected());
    }
    agents
        .iter()
        .map(|(did, target)| {
            let public: SocketAddr = target.public.parse().map_err(|_| rejected())?;
            let admin: SocketAddr = target.admin.parse().map_err(|_| rejected())?;
            if !public.ip().is_loopback()
                || !admin.ip().is_loopback()
                || public.port() == 0
                || admin.port() == 0
            {
                return Err(rejected());
            }
            Ok((did.clone(), (public, admin)))
        })
        .collect()
}

fn pem_file(path: &Path, tag: &str) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(rejected());
    }
    let raw = std::fs::read(path).map_err(|_| rejected())?;
    if raw.is_empty() || raw.len() > 16_384 {
        return Err(rejected());
    }
    let block = pem::parse(&raw).map_err(|_| rejected())?;
    if block.tag() != tag {
        return Err(rejected());
    }
    Ok(block.into_contents())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspection {
    registry: String,
    did: String,
    version: String,
    grants: Vec<Value>,
    history: Vec<History>,
    tombstoned: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    envelope: String,
    at: i64,
    operation: String,
    #[serde(default)]
    actor: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    scope: String,
}

pub(super) struct LiveWeb {
    root: Vec<u8>,
    cert: Vec<u8>,
    key: Vec<u8>,
    agents: BTreeMap<String, (SocketAddr, SocketAddr)>,
    start: Instant,
}

impl LiveWeb {
    pub(super) fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(rejected());
        }
        let raw = std::fs::read(path).map_err(|_| rejected())?;
        if raw.is_empty() || raw.len() > 65_536 {
            return Err(rejected());
        }
        let config: Configuration = serde_json::from_slice(&raw).map_err(|_| rejected())?;
        if config.origin != ORIGIN || config.admin_host != ADMIN_HOST {
            return Err(rejected());
        }
        let root = URL_SAFE_NO_PAD
            .decode(&config.root_der)
            .map_err(|_| rejected())?;
        if URL_SAFE_NO_PAD.encode(&root) != config.root_der {
            return Err(rejected());
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(root.clone()))
            .map_err(|_| rejected())?;
        let cert = pem_file(&config.inspector_cert, "CERTIFICATE")?;
        let key = pem_file(&config.inspector_key, "PRIVATE KEY")?;
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from(cert.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())),
            )
            .map_err(|_| rejected())?;
        Ok(Self {
            root,
            cert,
            key,
            agents: destinations(&config.agents)?,
            start: Instant::now(),
        })
    }

    pub(super) fn now(&self) -> Result<Stamp> {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| unreachable())?
            .as_secs()
            .try_into()
            .map_err(|_| unreachable())?;
        let mono_ms = self
            .start
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(|_| unreachable())?;
        Ok(Stamp { mono_ms, unix })
    }

    fn inspection(&self, destination: SocketAddr) -> Result<Inspection> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.root.clone()))
            .map_err(|_| unreachable())?;
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from(self.cert.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone())),
            )
            .map_err(|_| unreachable())?;
        let timeout = Duration::from_secs(5);
        let socket =
            TcpStream::connect_timeout(&destination, timeout).map_err(|_| unreachable())?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|_| unreachable())?;
        socket
            .set_write_timeout(Some(timeout))
            .map_err(|_| unreachable())?;
        let server_name = ServerName::try_from(ADMIN_HOST.to_owned()).map_err(|_| unreachable())?;
        let connection =
            ClientConnection::new(Arc::new(config), server_name).map_err(|_| unreachable())?;
        let mut stream = StreamOwned::new(connection, socket);
        stream.write_all(b"GET /admin/registry/inspection HTTP/1.1\r\nHost: admin.example.com\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
            .map_err(|_| unreachable())?;
        let raw = read_inspection_http(&mut stream)?;
        let state: Inspection = serde_json::from_slice(&raw).map_err(|_| rejected())?;
        if state.history.is_empty() || state.history.len() > 256 || state.grants.len() > 128 {
            return Err(rejected());
        }
        Ok(state)
    }

    pub(super) fn read(&self, did: &str) -> Result<Snapshot> {
        let (public_addr, admin_addr) = *self.agents.get(did).ok_or_else(rejected)?;
        let mut public = None;
        let mut last_error = unreachable();
        for _ in 0..2 {
            let started = self.now()?.unix;
            match fetch_web_registry_record_010(
                did,
                &[ORIGIN],
                public_addr,
                &[public_addr],
                &self.root,
                started,
            ) {
                Ok(value) => {
                    public = Some(value);
                    break;
                }
                Err(error) => {
                    last_error = error;
                }
            }
            if self.now()?.unix == started {
                break;
            }
        }
        let public = public.ok_or(last_error)?;
        let inspection = self.inspection(admin_addr)?;
        if inspection.registry != ORIGIN || inspection.did != did {
            return Err(stale());
        }
        let mut envelopes = Vec::with_capacity(inspection.history.len());
        for entry in &inspection.history {
            if [&entry.actor, &entry.target, &entry.scope]
                .iter()
                .any(|value| value.len() > 256 || !value.is_ascii())
            {
                return Err(rejected());
            }
            let envelope = STANDARD.decode(&entry.envelope).map_err(|_| rejected())?;
            if envelope.is_empty() || envelope.len() > 69_632 {
                return Err(rejected());
            }
            envelopes.push(envelope);
        }
        let history: Vec<_> = inspection
            .history
            .iter()
            .zip(&envelopes)
            .map(|(entry, envelope)| WebRegistryHistoryEntry010 {
                envelope,
                at: entry.at,
                operation: &entry.operation,
            })
            .collect();
        check_web_registry_history_continuity_010(&history, &public, did, self.now()?.unix)
            .map_err(|_| stale())?;
        let envelope: Value = serde_json::from_slice(&public).map_err(|_| rejected())?;
        let record = envelope.get("record").ok_or_else(rejected)?;
        let field = |name| {
            record
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(rejected)
        };
        let version = field("version")?.to_owned();
        let number: usize = version.parse().map_err(|_| rejected())?;
        if number == 0
            || number > 256
            || number.to_string() != version
            || inspection.history.len() != number
            || inspection.version != version
            || inspection.tombstoned != (field("state")? == "deactivated")
            || field("id")? != did
        {
            return Err(stale());
        }
        let mut keys = Vec::new();
        for item in record
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(rejected)?
        {
            let item_field = |name| item.get(name).and_then(Value::as_str).ok_or_else(rejected);
            let material = item_field("key")?;
            let bytes = URL_SAFE_NO_PAD.decode(material).map_err(|_| rejected())?;
            if URL_SAFE_NO_PAD.encode(&bytes) != material {
                return Err(rejected());
            }
            let expires = match item.get("expires") {
                None => None,
                Some(value) => Some(value.as_i64().ok_or_else(rejected)?),
            };
            keys.push(Key {
                name: item_field("name")?.into(),
                alg: item_field("alg")?.into(),
                material: hex::encode(bytes),
                state: item_field("state")?.into(),
                expires,
            });
        }
        let canonical = sage_crypto_core::jcs::canonicalize(
            &serde_json::to_vec(record).map_err(|_| rejected())?,
        )
        .map_err(|_| rejected())?;
        let digest = hex::encode(sage_crypto_core::hpke::sha256_hash(&canonical));
        Ok(Snapshot {
            source: ORIGIN.into(),
            registry: registry().into(),
            network: "local".into(),
            did: did.into(),
            version,
            state: field("state")?.into(),
            digest,
            ready: true,
            validated: true,
            finalized: true,
            conflicting: false,
            acquired_ms: self.now()?.mono_ms,
            block_hash: String::new(),
            keys_block_hash: String::new(),
            keys,
        })
    }
}

fn read_inspection_http<R: Read>(stream: &mut R) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    let mut remaining = 16_384_usize;
    let mut line = || -> Result<String> {
        let mut raw = Vec::new();
        let amount = reader
            .by_ref()
            .take((remaining + 1) as u64)
            .read_until(b'\n', &mut raw)
            .map_err(|_| unreachable())?;
        if amount == 0 || amount > remaining || !raw.ends_with(b"\r\n") {
            return Err(rejected());
        }
        remaining -= amount;
        String::from_utf8(raw[..raw.len() - 2].to_vec()).map_err(|_| rejected())
    };
    let status = line()?;
    if !status.starts_with("HTTP/1.1 200 ") {
        return Err(rejected());
    }
    let mut content_type = None;
    let mut length = None;
    let mut ended = false;
    for _ in 0..64 {
        let header = line()?;
        if header.is_empty() {
            ended = true;
            break;
        }
        let (name, value) = header.split_once(':').ok_or_else(rejected)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
        {
            return Err(rejected());
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.replace(value.to_owned()).is_some() {
                return Err(rejected());
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if length
                .replace(value.parse::<usize>().map_err(|_| rejected())?)
                .is_some()
                || value.is_empty()
                || !value.bytes().all(|c| c.is_ascii_digit())
            {
                return Err(rejected());
            }
        } else if name.eq_ignore_ascii_case("content-encoding")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("trailer")
        {
            return Err(rejected());
        }
    }
    if !ended || content_type.as_deref() != Some("application/json") {
        return Err(rejected());
    }
    let amount = length.ok_or_else(rejected)?;
    if amount == 0 || amount > MAX_INSPECTION {
        return Err(rejected());
    }
    let mut body = vec![0; amount];
    reader.read_exact(&mut body).map_err(|_| unreachable())?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets() -> BTreeMap<String, Destination> {
        BTreeMap::from([
            (
                alice().into(),
                Destination {
                    public: "127.0.0.1:9001".into(),
                    admin: "127.0.0.1:9002".into(),
                },
            ),
            (
                bob().into(),
                Destination {
                    public: "127.0.0.1:9003".into(),
                    admin: "127.0.0.1:9004".into(),
                },
            ),
        ])
    }

    #[test]
    fn restricts_live_source_to_exact_local_participants() {
        assert_eq!(destinations(&targets()).unwrap().len(), 2);
        let mut wrong = targets();
        wrong.get_mut(alice()).unwrap().public = "192.0.2.1:443".into();
        assert!(destinations(&wrong).is_err());
        let mut wrong = targets();
        wrong.remove(bob());
        wrong.insert(
            "did:sage:web:agent.example:other".into(),
            Destination {
                public: "127.0.0.1:9003".into(),
                admin: "127.0.0.1:9004".into(),
            },
        );
        assert!(destinations(&wrong).is_err());
        let mut wrong = targets();
        wrong.get_mut(bob()).unwrap().admin = "127.0.0.1:0".into();
        assert!(destinations(&wrong).is_err());
    }

    #[test]
    fn requires_one_bounded_unambiguous_inspection_response() {
        use std::io::Cursor;
        let valid =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            read_inspection_http(&mut Cursor::new(valid)).unwrap(),
            b"{}"
        );
        for invalid in [
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            assert!(read_inspection_http(&mut Cursor::new(invalid)).is_err());
        }
    }
}
