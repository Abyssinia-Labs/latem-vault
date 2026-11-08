//! Joining a vault (join.md): the PAKE, the request, and handing over the log and grants, on one
//! stream of a connection with ALPN `openvault/join/1`.
//!
//! The admin connects to the joiner and opens the stream. Either side's code can be wrong, so
//! each side checks the other's confirmation before going on, and the admin sends its own only
//! after checking the joiner's.

use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointId};
use openvault_core::VaultId;
use openvault_core::grant::Grant;
use openvault_core::join::JoinRequest;
use openvault_core::membership::{DeviceName, LogEntry};
use openvault_crypto::VerifyingKey;
use openvault_crypto::hash::Hash;
use openvault_crypto::pake::{self, JoinKeys, Pake, Side};
use tokio::time::{Instant, timeout, timeout_at};

use crate::EndpointKey;
use crate::frame::{self, FrameError, Reason};

pub const ALPN: &[u8] = b"openvault/join/1";

const PAKE: u8 = 0x20;
const CONFIRM: u8 = 0x21;
const REQUEST: u8 = 0x22;
const ACCEPTED: u8 = 0x23;
const JOINED: u8 = 0x24;
const LOG_REQUEST: u8 = 0x02;
const LOG_ENTRIES: u8 = 0x03;
const ITEMS: u8 = 0x07;

/// The grants set's id (sync.md, sets).
const GRANTS_SET: [u8; 17] = {
    let mut id = [0; 17];
    id[0] = 0x02;
    id
};
/// Log entries per request, and in one session (sync.md, log exchange).
const LOG_BATCH: u16 = 64;
const MAX_LOG: usize = 4096;
/// How long a step may take when nobody has to do anything.
const STEP: Duration = Duration::from_secs(30);

/// The prefix of a joining device's mDNS announcement: `join:<platform>:<name>`.
const ANNOUNCEMENT: &str = "join:";

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("wrong code")]
    WrongCode,
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("the other device took too long")]
    Timeout,
    #[error("can't connect: {0}")]
    Connect(String),
    #[error(transparent)]
    Core(#[from] openvault_core::Error),
}

/// What a joining device announces on mDNS (join.md, finding the device). Nothing in it is
/// trusted; it only helps the admin pick the device.
pub fn announcement(name: &DeviceName) -> String {
    format!("{ANNOUNCEMENT}{}:{}", name.platform, name.name)
}

/// The platform and name in a joining device's announcement, or `None` for any other.
pub fn parse_announcement(announcement: &str) -> Option<(String, String)> {
    let (platform, name) = announcement.strip_prefix(ANNOUNCEMENT)?.split_once(':')?;
    // Control characters would let a device on the network rewrite the admin's terminal.
    let clean = |text: &str| text.chars().filter(|c| !c.is_control()).collect::<String>();
    Some((clean(platform), clean(name)))
}

/// The transport key an endpoint id stands for, as a crypto.md verifying key.
pub fn transport_key(id: &EndpointKey) -> VerifyingKey {
    VerifyingKey::from_bytes(&[&[0x01][..], id].concat()).expect("an endpoint id is an Ed25519 key")
}

/// The admin's side of a join, after the joiner has proved it knows the code and sent its
/// request.
pub struct AdminSession {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    request: JoinRequest,
}

impl AdminSession {
    /// Connects to the joiner and runs the PAKE with `code`, then reads and checks its request.
    pub async fn start(
        endpoint: &Endpoint,
        joiner: EndpointKey,
        code: &str,
    ) -> Result<Self, JoinError> {
        let id = EndpointId::from_bytes(&joiner).map_err(|e| JoinError::Connect(e.to_string()))?;
        let connection = timeout(STEP, endpoint.connect(id, ALPN))
            .await
            .map_err(|_| JoinError::Timeout)?
            .map_err(|e| JoinError::Connect(e.to_string()))?;
        let admin_transport = transport_key(endpoint.id().as_bytes());
        let joiner_transport = transport_key(&joiner);
        let (pake, message) = Pake::start(Side::Admin, code, &admin_transport, &joiner_transport)
            .map_err(openvault_core::Error::from)?;
        let (mut send, mut recv) = timeout(STEP, connection.open_bi())
            .await
            .map_err(|_| JoinError::Timeout)?
            .map_err(|e| JoinError::Connect(e.to_string()))?;
        frame::write(&mut send, PAKE, &message).await?;
        let keys = finish_pake(pake, &mut recv).await?;

        let (kind, joiner_confirm) = step(&mut recv).await?;
        expect(kind, CONFIRM)?;
        if !pake::confirmation_matches(&keys.joiner_confirm, &joiner_confirm) {
            frame::send_error(&mut send, Reason::WrongCode, "").await;
            connection.close(0u32.into(), b"wrong code");
            return Err(JoinError::WrongCode);
        }
        frame::write(&mut send, CONFIRM, &keys.admin_confirm[..]).await?;

        let (kind, body) = step(&mut recv).await?;
        expect(kind, REQUEST)?;
        let request = JoinRequest::from_bytes(&body)?;
        request.verify(&keys.session_id)?;
        if request.transport_key != joiner_transport {
            frame::send_error(&mut send, Reason::BadMessage, "transport key").await;
            return Err(
                FrameError::Bad("the request's transport key isn't the connection's").into(),
            );
        }
        Ok(Self {
            connection,
            send,
            recv,
            request,
        })
    }

    pub fn request(&self) -> &JoinRequest {
        &self.request
    }

    /// Ends the session with "join refused".
    pub async fn refuse(mut self, detail: &str) {
        frame::send_error(&mut self.send, Reason::JoinRefused, detail).await;
        self.connection.close(0u32.into(), b"refused");
    }

    /// Sends the vault's head, answers the joiner's log requests, sends its grants once it has
    /// the whole log, and waits for joined.
    pub async fn finish(
        mut self,
        vault: VaultId,
        log: &[LogEntry],
        grants: &[Grant],
    ) -> Result<(), JoinError> {
        let last = log.last().expect("an approved vault has a log");
        let mut accepted = vault.as_bytes().to_vec();
        accepted.extend_from_slice(&last.seq().to_be_bytes());
        accepted.extend_from_slice(&last.hash());
        frame::write(&mut self.send, ACCEPTED, &accepted).await?;

        let mut grants_sent = false;
        loop {
            let (kind, body) = step(&mut self.recv).await?;
            match kind {
                LOG_REQUEST => {
                    let (from, max) = parse_log_request(&body)?;
                    let start = usize::try_from(from).unwrap_or(usize::MAX).min(log.len());
                    let end = (start + usize::from(max.min(LOG_BATCH))).min(log.len());
                    let mut entries = (end - start).to_be_bytes()[6..].to_vec();
                    for entry in &log[start..end] {
                        let bytes = entry.to_bytes();
                        entries.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                        entries.extend_from_slice(&bytes);
                    }
                    frame::write(&mut self.send, LOG_ENTRIES, &entries).await?;
                    if end == log.len() && !grants_sent {
                        frame::write(&mut self.send, ITEMS, &encode_grants(grants)).await?;
                        grants_sent = true;
                    }
                }
                JOINED if grants_sent => break,
                _ => {
                    frame::send_error(&mut self.send, Reason::BadMessage, "").await;
                    return Err(FrameError::Bad("unexpected message").into());
                }
            }
        }
        let _ = self.send.finish();
        self.connection.close(0u32.into(), b"joined");
        Ok(())
    }
}

/// The vault and head the admin sent once it approved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub vault: VaultId,
    pub head: (u64, Hash),
}

/// The joiner's side of a join, after both sides have checked each other's confirmation.
pub struct JoinerSession {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    keys: JoinKeys,
}

impl JoinerSession {
    /// Answers the admin's PAKE on an incoming connection with `code`.
    pub async fn accept(
        connection: Connection,
        joiner: EndpointKey,
        code: &str,
    ) -> Result<Self, JoinError> {
        let admin_transport = transport_key(connection.remote_id().as_bytes());
        let joiner_transport = transport_key(&joiner);
        let (mut send, mut recv) = timeout(STEP, connection.accept_bi())
            .await
            .map_err(|_| JoinError::Timeout)?
            .map_err(|e| JoinError::Connect(e.to_string()))?;
        let (pake, message) = Pake::start(Side::Joiner, code, &admin_transport, &joiner_transport)
            .map_err(openvault_core::Error::from)?;
        frame::write(&mut send, PAKE, &message).await?;
        let keys = finish_pake(pake, &mut recv).await?;
        frame::write(&mut send, CONFIRM, &keys.joiner_confirm[..]).await?;
        let (kind, admin_confirm) = match step(&mut recv).await {
            Err(JoinError::Frame(FrameError::Peer {
                reason: Reason::WrongCode,
                ..
            })) => return Err(JoinError::WrongCode),
            other => other?,
        };
        expect(kind, CONFIRM)?;
        if !pake::confirmation_matches(&keys.admin_confirm, &admin_confirm) {
            frame::send_error(&mut send, Reason::WrongCode, "").await;
            return Err(JoinError::WrongCode);
        }
        Ok(Self {
            connection,
            send,
            recv,
            keys,
        })
    }

    /// The session id the request must be signed over.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.keys.session_id
    }

    /// Sends the request and waits, until `deadline`, for the admin to approve it.
    pub async fn request(
        &mut self,
        request: &JoinRequest,
        deadline: Instant,
    ) -> Result<Accepted, JoinError> {
        frame::write(&mut self.send, REQUEST, &request.to_bytes()).await?;
        let (kind, body) = timeout_at(deadline, frame::read(&mut self.recv))
            .await
            .map_err(|_| JoinError::Timeout)??;
        expect(kind, ACCEPTED)?;
        let (vault, rest) = body
            .split_first_chunk::<16>()
            .ok_or(FrameError::Bad("accepted"))?;
        let (seq, hash) = rest
            .split_first_chunk::<8>()
            .ok_or(FrameError::Bad("accepted"))?;
        let hash: Hash = hash.try_into().map_err(|_| FrameError::Bad("accepted"))?;
        Ok(Accepted {
            vault: VaultId::from_bytes(*vault),
            head: (u64::from_be_bytes(*seq), hash),
        })
    }

    /// Requests the log up to `head`, then reads the grants that follow it. Nothing is checked
    /// here beyond the encoding: the store checks the log and grants before it keeps them.
    pub async fn receive(
        &mut self,
        head: (u64, Hash),
    ) -> Result<(Vec<LogEntry>, Vec<Grant>), JoinError> {
        let total = usize::try_from(head.0)
            .ok()
            .and_then(|seq| seq.checked_add(1))
            .filter(|&total| total <= MAX_LOG)
            .ok_or(FrameError::Bad("the log is too long"))?;
        let mut log: Vec<LogEntry> = Vec::with_capacity(total);
        while log.len() < total {
            let max = LOG_BATCH.min(u16::try_from(total - log.len()).unwrap_or(LOG_BATCH));
            let mut request = (log.len() as u64).to_be_bytes().to_vec();
            request.extend_from_slice(&max.to_be_bytes());
            frame::write(&mut self.send, LOG_REQUEST, &request).await?;
            let (kind, body) = step(&mut self.recv).await?;
            expect(kind, LOG_ENTRIES)?;
            let entries = parse_entries(&body)?;
            if entries.is_empty() || entries.len() > usize::from(max) {
                return Err(FrameError::Bad("log entries").into());
            }
            for entry in entries {
                if entry.seq() != log.len() as u64 {
                    return Err(FrameError::Bad("log entries out of order").into());
                }
                log.push(entry);
            }
        }
        let (kind, body) = step(&mut self.recv).await?;
        expect(kind, ITEMS)?;
        Ok((log, parse_grants(&body)?))
    }

    /// Tells the admin the join is complete.
    pub async fn joined(mut self) -> Result<(), JoinError> {
        frame::write(&mut self.send, JOINED, &[]).await?;
        let _ = self.send.finish();
        // Waits for the admin to close, so joined isn't lost with the connection.
        let _ = timeout(STEP, self.connection.closed()).await;
        Ok(())
    }

    /// Ends the session because what the admin sent didn't check out.
    pub async fn fail(mut self, detail: &str) {
        frame::send_error(&mut self.send, Reason::BadMessage, detail).await;
        self.connection.close(0u32.into(), b"failed");
    }
}

async fn finish_pake(pake: Pake, recv: &mut RecvStream) -> Result<JoinKeys, JoinError> {
    let (kind, message) = step(recv).await?;
    expect(kind, PAKE)?;
    Ok(pake.finish(&message).map_err(openvault_core::Error::from)?)
}

/// Reads the next message, within [`STEP`].
async fn step(recv: &mut RecvStream) -> Result<(u8, Vec<u8>), JoinError> {
    timeout(STEP, frame::read(recv))
        .await
        .map_err(|_| JoinError::Timeout)?
        .map_err(JoinError::from)
}

fn expect(kind: u8, expected: u8) -> Result<(), JoinError> {
    if kind == expected {
        Ok(())
    } else {
        Err(FrameError::Bad("unexpected message").into())
    }
}

fn parse_log_request(body: &[u8]) -> Result<(u64, u16), JoinError> {
    let bytes: [u8; 10] = body
        .try_into()
        .map_err(|_| FrameError::Bad("log request"))?;
    Ok((
        u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes")),
        u16::from_be_bytes(bytes[8..].try_into().expect("2 bytes")),
    ))
}

/// `count (u16) ‖ entries, each u32 length ‖ entry`.
fn parse_entries(body: &[u8]) -> Result<Vec<LogEntry>, JoinError> {
    let mut rest = body;
    let count = take_u16(&mut rest)?;
    let mut entries = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        entries.push(LogEntry::from_bytes(take_item(&mut rest)?)?);
    }
    if !rest.is_empty() {
        return Err(FrameError::Bad("trailing bytes").into());
    }
    Ok(entries)
}

/// `set id (17) ‖ count (u16) ‖ items, each u32 length ‖ item` (sync.md, range reconciliation).
fn encode_grants(grants: &[Grant]) -> Vec<u8> {
    let mut out = GRANTS_SET.to_vec();
    out.extend_from_slice(&(grants.len() as u16).to_be_bytes());
    for grant in grants {
        let bytes = grant.to_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

fn parse_grants(body: &[u8]) -> Result<Vec<Grant>, JoinError> {
    let (set, mut rest) = body
        .split_first_chunk::<17>()
        .ok_or(FrameError::Bad("items"))?;
    if *set != GRANTS_SET {
        return Err(FrameError::Bad("items from another set").into());
    }
    let count = take_u16(&mut rest)?;
    let mut grants = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        grants.push(Grant::from_bytes(take_item(&mut rest)?)?);
    }
    if !rest.is_empty() {
        return Err(FrameError::Bad("trailing bytes").into());
    }
    Ok(grants)
}

fn take_u16(rest: &mut &[u8]) -> Result<u16, JoinError> {
    let (count, after) = rest
        .split_first_chunk::<2>()
        .ok_or(FrameError::Bad("count"))?;
    *rest = after;
    Ok(u16::from_be_bytes(*count))
}

fn take_item<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], JoinError> {
    let (len, after) = rest
        .split_first_chunk::<4>()
        .ok_or(FrameError::Bad("item length"))?;
    let (item, after) = after
        .split_at_checked(u32::from_be_bytes(*len) as usize)
        .ok_or(FrameError::Bad("item"))?;
    *rest = after;
    Ok(item)
}

#[cfg(test)]
mod tests {
    use openvault_core::membership::Scope;
    use openvault_core::{DeviceId, Kind, SoftwareKeys, Vault, transport_seed};
    use openvault_crypto::RecoveryKey;

    use super::*;
    use crate::{Node, Options};

    fn desktop() -> DeviceName {
        DeviceName {
            platform: "linux".into(),
            name: "Desktop".into(),
        }
    }

    async fn joiner_node(keys: &SoftwareKeys) -> Node {
        let options = Options {
            alpns: vec![ALPN.to_vec()],
            announcement: Some(announcement(&desktop())),
            ..Options::default()
        };
        Node::start(&transport_seed(keys), options).await.unwrap().0
    }

    async fn admin_node(seed: &[u8; 32]) -> Node {
        let options = Options {
            advertise: false,
            ..Options::default()
        };
        Node::start(seed, options).await.unwrap().0
    }

    #[test]
    fn announcements_round_trip_without_control_characters() {
        assert_eq!(
            parse_announcement(&announcement(&desktop())),
            Some(("linux".into(), "Desktop".into()))
        );
        assert_eq!(
            parse_announcement("join:linux:Desk\u{1b}[2Jtop: 2"),
            Some(("linux".into(), "Desk[2Jtop: 2".into()))
        );
        assert_eq!(parse_announcement("member"), None);
    }

    /// A device joins over a real connection, found with mDNS.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_joins() {
        let dir = tempfile::tempdir().unwrap();
        let recovery = RecoveryKey::generate();
        let admin_keys = SoftwareKeys::generate();
        let admin_seed = transport_seed(&admin_keys);
        let mut admin_vault = Vault::create(
            &dir.path().join("admin.db"),
            admin_keys,
            &recovery,
            "MacBook",
            None,
        )
        .unwrap();
        let latem = admin_vault
            .create_collection("latem", &recovery.admin_signing_key())
            .unwrap();
        admin_vault
            .set(latem, "prod/SENTRY_DSN", Kind::Secret, b"https://sentry")
            .unwrap();

        let joiner_keys = SoftwareKeys::generate();
        let joiner_device = DeviceId::random();
        let joiner = joiner_node(&joiner_keys).await;
        let admin = admin_node(&admin_seed).await;
        let joiner_id = joiner.id();
        let code = pake::new_code();

        let joined_path = dir.path().join("joiner.db");
        let joiner_code = code.clone();
        let joining = tokio::spawn(async move {
            let incoming = joiner.endpoint().accept().await.unwrap();
            let connection = incoming.await.unwrap();
            assert_eq!(connection.alpn(), ALPN);
            let mut session = JoinerSession::accept(connection, joiner.id(), &joiner_code)
                .await
                .unwrap();
            let request =
                JoinRequest::sign(session.session_id(), joiner_device, &joiner_keys, desktop())
                    .unwrap();
            let accepted = session
                .request(&request, Instant::now() + Duration::from_secs(60))
                .await
                .unwrap();
            let (log, grants) = session.receive(accepted.head).await.unwrap();
            let vault = Vault::join(
                &joined_path,
                joiner_keys,
                joiner_device,
                &desktop(),
                accepted.head,
                &log,
                &grants,
            )
            .unwrap();
            session.joined().await.unwrap();
            joiner.close().await;
            (accepted, vault.membership().unwrap().head(), grants.len())
        });

        let session = AdminSession::start(admin.endpoint(), joiner_id, &code)
            .await
            .unwrap();
        assert_eq!(session.request().name, desktop());
        assert_eq!(session.request().device, joiner_device);
        let approval = admin_vault
            .approve_join(
                session.request(),
                &[(latem, Scope::Read)],
                &recovery.admin_signing_key(),
            )
            .unwrap();
        session
            .finish(admin_vault.vault_id(), &approval.log, &approval.grants)
            .await
            .unwrap();
        let (accepted, joined_head, grants) = joining.await.unwrap();
        assert_eq!(accepted.vault, admin_vault.vault_id());
        assert_eq!(joined_head, admin_vault.membership().unwrap().head());
        assert_eq!(grants, 1);
        assert_eq!(
            admin_vault
                .membership()
                .unwrap()
                .scope(joiner_device, latem),
            Scope::Read
        );
        admin.close().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_wrong_code_fails_on_both_sides() {
        let joiner_keys = SoftwareKeys::generate();
        let admin_seed = transport_seed(&SoftwareKeys::generate());
        let joiner = joiner_node(&joiner_keys).await;
        let admin = admin_node(&admin_seed).await;
        let joiner_id = joiner.id();

        let joining = tokio::spawn(async move {
            let connection = joiner.endpoint().accept().await.unwrap().await.unwrap();
            let result = JoinerSession::accept(connection, joiner.id(), "111111").await;
            joiner.close().await;
            result.err()
        });
        let result = AdminSession::start(admin.endpoint(), joiner_id, "222222").await;
        assert!(matches!(result, Err(JoinError::WrongCode)));
        assert!(matches!(joining.await.unwrap(), Some(JoinError::WrongCode)));
        admin.close().await;
    }
}
