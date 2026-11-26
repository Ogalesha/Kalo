//! Incoming-sender trust decisions and the authorization prompt plumbing.
//!
//! New senders are asked about in the desktop UI. A sender can be allowed or
//! blocked once, or remembered in the trust store. The CLI receiver is
//! deliberately non-interactive, so it rejects new senders and only accepts
//! remembered devices. Windows falls back to a display-name identity when the
//! Bluetooth address cannot be resolved; those identities are never stored.

// macOS has no OPP receiver, so the trust and authorization plumbing is unused.
#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::events::{Event, EventSink};
use crate::paths;

/// How long an incoming push waits for a decision in the UI before it is
/// rejected. obexd itself has a finite authorization timeout, so this must
/// stay comfortably below it.
pub const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(45);

/// What to do with a sender that has no remembered decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncomingPolicy {
    /// Ask in the desktop UI; the CLI rejects because it has no prompt.
    #[default]
    Ask,
    /// Reject every sender that is not remembered as allowed.
    TrustedOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustDecision {
    Allow,
    Block,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEntry {
    pub name: String,
    pub decision: TrustDecision,
    /// Ed25519 public key pinned during Kalo pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_key: Option<String>,
    /// Outgoing ratchet: next chain key and the step it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_chain: Option<String>,
    #[serde(default)]
    pub send_step: u64,
    /// Incoming ratchet, independent from the outgoing one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_chain: Option<String>,
    #[serde(default)]
    pub recv_step: u64,
}

impl std::fmt::Debug for TrustEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustEntry")
            .field("name", &self.name)
            .field("decision", &self.decision)
            .field(
                "peer_key",
                &self
                    .peer_key
                    .as_ref()
                    .map(|_| "<pinned>")
                    .unwrap_or("<none>"),
            )
            .field("send_chain", &self.send_chain.as_ref().map(|_| "<set>"))
            .field("send_step", &self.send_step)
            .field("recv_chain", &self.recv_chain.as_ref().map(|_| "<set>"))
            .field("recv_step", &self.recv_step)
            .finish()
    }
}

/// One direction of a paired device's ratchet.
#[derive(Clone, PartialEq, Eq)]
pub struct ChainState {
    pub key: [u8; 32],
    pub step: u64,
}

impl std::fmt::Debug for ChainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainState")
            .field("key", &"<set>")
            .field("step", &self.step)
            .finish()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct TrustData {
    policy: IncomingPolicy,
    devices: BTreeMap<String, TrustEntry>,
}

#[derive(Debug)]
struct TrustInner {
    /// `None` for the demo/in-memory store; decisions still work but are not
    /// written anywhere.
    path: Option<PathBuf>,
    data: Mutex<TrustData>,
}

/// Persistent per-device decisions, shared by the UI and the receiver.
#[derive(Debug, Clone)]
pub struct TrustStore {
    inner: Arc<TrustInner>,
}

impl TrustStore {
    pub fn load() -> (Self, Option<String>) {
        Self::load_from(paths::trust_file())
    }

    pub fn load_from(path: PathBuf) -> (Self, Option<String>) {
        match std::fs::read_to_string(&path) {
            Ok(raw) => match serde_json::from_str::<TrustData>(&raw) {
                Ok(data) => (
                    Self {
                        inner: Arc::new(TrustInner {
                            path: Some(path),
                            data: Mutex::new(data),
                        }),
                    },
                    None,
                ),
                Err(error) => (
                    Self::with_path(path.clone()),
                    Some(format!(
                        "trust store at {} is invalid ({error}); starting empty",
                        path.display()
                    )),
                ),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (Self::with_path(path), None)
            }
            Err(error) => (
                Self::with_path(path.clone()),
                Some(format!(
                    "cannot read trust store at {} ({error}); starting empty",
                    path.display()
                )),
            ),
        }
    }

    fn with_path(path: PathBuf) -> Self {
        Self {
            inner: Arc::new(TrustInner {
                path: Some(path),
                data: Mutex::new(TrustData::default()),
            }),
        }
    }

    /// A store that works for this process only.
    pub fn in_memory() -> Self {
        Self {
            inner: Arc::new(TrustInner {
                path: None,
                data: Mutex::new(TrustData::default()),
            }),
        }
    }

    /// Fictional entries for README screenshots. Never loads the user's file.
    pub fn demo() -> Self {
        let store = Self::in_memory();
        {
            let mut data = store.inner.data.lock().expect("trust lock");
            data.devices.insert(
                "AA:BB:CC:11:22:33".into(),
                TrustEntry {
                    name: "Pixel 8".into(),
                    decision: TrustDecision::Allow,
                    peer_key: None,
                    send_chain: None,
                    send_step: 0,
                    recv_chain: None,
                    recv_step: 0,
                },
            );
            data.devices.insert(
                "AA:BB:CC:44:55:66".into(),
                TrustEntry {
                    name: "Studio laptop".into(),
                    decision: TrustDecision::Allow,
                    peer_key: None,
                    send_chain: None,
                    send_step: 0,
                    recv_chain: None,
                    recv_step: 0,
                },
            );
        }
        store
    }

    pub fn policy(&self) -> IncomingPolicy {
        self.inner.data.lock().expect("trust lock").policy
    }

    pub fn set_policy(&self, policy: IncomingPolicy) -> Result<()> {
        {
            let mut data = self.inner.data.lock().expect("trust lock");
            if data.policy == policy {
                return Ok(());
            }
            data.policy = policy;
        }
        self.persist()
    }

    /// All remembered devices, sorted by address.
    pub fn entries(&self) -> Vec<(String, TrustEntry)> {
        self.inner
            .data
            .lock()
            .expect("trust lock")
            .devices
            .iter()
            .map(|(address, entry)| (address.clone(), entry.clone()))
            .collect()
    }

    pub fn decision(&self, address: &str) -> Option<TrustDecision> {
        let key = normalize_key(address);
        self.inner
            .data
            .lock()
            .expect("trust lock")
            .devices
            .get(&key)
            .map(|entry| entry.decision)
    }

    pub fn remember(&self, address: &str, name: &str, decision: TrustDecision) -> Result<()> {
        let key = normalize_key(address);
        {
            let mut data = self.inner.data.lock().expect("trust lock");
            let entry = data.devices.entry(key).or_insert_with(|| TrustEntry {
                name: name.to_string(),
                decision,
                peer_key: None,
                send_chain: None,
                send_step: 0,
                recv_chain: None,
                recv_step: 0,
            });
            entry.name = name.to_string();
            entry.decision = decision;
        }
        self.persist()
    }

    pub fn remove(&self, address: &str) -> Result<()> {
        let key = normalize_key(address);
        {
            let mut data = self.inner.data.lock().expect("trust lock");
            if data.devices.remove(&key).is_none() {
                return Ok(());
            }
        }
        self.persist()
    }

    /// The full entry for a sender, including pinned keys. Callers must not
    /// log the secret chain fields.
    pub fn entry(&self, address: &str) -> Option<TrustEntry> {
        let key = normalize_key(address);
        self.inner
            .data
            .lock()
            .expect("trust lock")
            .devices
            .get(&key)
            .cloned()
    }

    /// A paired device has a pinned identity and both ratchet directions.
    pub fn is_paired(&self, address: &str) -> bool {
        self.entry(address).is_some_and(|entry| {
            entry.decision == TrustDecision::Allow
                && entry.peer_key.is_some()
                && entry.send_chain.is_some()
                && entry.recv_chain.is_some()
        })
    }

    /// True when the device has a pinned identity, even if one of its ratchet
    /// directions is missing or corrupt. Receivers use this to fail closed:
    /// a partially damaged pairing entry must never turn into permission for
    /// plaintext or shared-passphrase downgrade.
    pub fn is_pinned(&self, address: &str) -> bool {
        self.entry(address)
            .is_some_and(|entry| entry.decision == TrustDecision::Allow && entry.peer_key.is_some())
    }

    pub fn peer_public(&self, address: &str) -> Option<[u8; 32]> {
        parse_key32(self.entry(address)?.peer_key.as_deref()?)
    }

    /// Outgoing chain state, or `None` when this is not a paired sender.
    pub fn outgoing_chain(&self, address: &str) -> Option<ChainState> {
        let entry = self.entry(address)?;
        if entry.decision != TrustDecision::Allow {
            return None;
        }
        Some(ChainState {
            key: parse_key32(entry.send_chain.as_deref()?)?,
            step: entry.send_step,
        })
    }

    /// Incoming chain state, or `None` when this sender is not paired.
    pub fn incoming_chain(&self, address: &str) -> Option<ChainState> {
        let entry = self.entry(address)?;
        if entry.decision != TrustDecision::Allow {
            return None;
        }
        Some(ChainState {
            key: parse_key32(entry.recv_chain.as_deref()?)?,
            step: entry.recv_step,
        })
    }

    /// Persist a newly completed pairing. The device is trusted in both
    /// directions: the pairing itself proved possession of the passphrase and
    /// of the advertised identity key, so no extra prompt is needed.
    pub fn pin_peer(
        &self,
        address: &str,
        name: &str,
        peer_key: [u8; 32],
        send_chain: [u8; 32],
        recv_chain: [u8; 32],
    ) -> Result<()> {
        let key = normalize_key(address);
        {
            let mut data = self.inner.data.lock().expect("trust lock");
            let entry = data.devices.entry(key).or_insert_with(|| TrustEntry {
                name: name.to_string(),
                decision: TrustDecision::Allow,
                peer_key: None,
                send_chain: None,
                send_step: 0,
                recv_chain: None,
                recv_step: 0,
            });
            entry.name = name.to_string();
            entry.decision = TrustDecision::Allow;
            entry.peer_key = Some(hex::encode(peer_key));
            entry.send_chain = Some(hex::encode(send_chain));
            entry.send_step = 0;
            entry.recv_chain = Some(hex::encode(recv_chain));
            entry.recv_step = 0;
        }
        self.persist()
    }

    /// Advance the outgoing ratchet after one attempted send. `expected_step`
    /// must still be current, so a concurrent or stale send cannot rewind the
    /// chain.
    pub fn commit_outgoing(&self, address: &str, expected_step: u64, next: [u8; 32]) -> Result<()> {
        let key = normalize_key(address);
        {
            let mut data = self.inner.data.lock().expect("trust lock");
            let entry = data
                .devices
                .get_mut(&key)
                .context("the sender is no longer paired")?;
            if entry.send_step != expected_step || entry.send_chain.is_none() {
                anyhow::bail!("the outgoing key chain advanced concurrently; retry the send");
            }
            entry.send_chain = Some(hex::encode(next));
            entry.send_step = expected_step + 1;
        }
        self.persist()
    }

    /// Advance the incoming ratchet after a container authenticated at
    /// `next_step`. `from_step` must still be current, so a replay or a stale
    /// completion cannot rewind the chain. A container can skip ahead when
    /// earlier sends were lost or cancelled.
    pub fn commit_incoming(
        &self,
        address: &str,
        from_step: u64,
        next_step: u64,
        next: [u8; 32],
    ) -> Result<()> {
        if next_step <= from_step {
            anyhow::bail!("the incoming key chain must advance");
        }
        // `next_step` is one past the authenticated container step, so a
        // container exactly MAX_CHAIN_SKIP steps ahead advances the stored
        // chain by MAX_CHAIN_SKIP + 1. Keep this bound in sync with
        // `PeerDecryptor`, which accepts that same boundary.
        if next_step - from_step > crate::crypto::MAX_CHAIN_SKIP.saturating_add(1) {
            anyhow::bail!("the incoming key chain skipped too far ahead");
        }
        let key = normalize_key(address);
        {
            let mut data = self.inner.data.lock().expect("trust lock");
            let entry = data
                .devices
                .get_mut(&key)
                .context("the sender is no longer paired")?;
            if entry.recv_step != from_step || entry.recv_chain.is_none() {
                anyhow::bail!("the incoming key chain advanced concurrently; retry the receive");
            }
            entry.recv_chain = Some(hex::encode(next));
            entry.recv_step = next_step;
        }
        self.persist()
    }

    /// Find a paired device by the 8-byte key identifier carried in a peer
    /// container. Recovery uses this when the Bluetooth address is unknown.
    pub fn peer_by_key_id(&self, key_id: &[u8; 8]) -> Option<(String, TrustEntry)> {
        self.entries().into_iter().find(|(_, entry)| {
            entry.decision == TrustDecision::Allow
                && entry
                    .peer_key
                    .as_deref()
                    .and_then(parse_key32)
                    .is_some_and(|key| crate::crypto::key_id(&key) == *key_id)
        })
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = self.inner.path.as_deref() else {
            return Ok(());
        };
        // Keep the lock held while serializing and writing. Cloning the state
        // first would let a slower writer replace the file with an older
        // snapshot, potentially restoring a ratchet step that was already
        // consumed.
        let data = self.inner.data.lock().expect("trust lock");
        crate::settings::write_json(path, &*data).context("save trust store")
    }
}

/// Bluetooth addresses are case-insensitive; normalize them so a device
/// cannot appear twice with different casing.
pub fn normalize_key(address: &str) -> String {
    address.trim().to_ascii_uppercase()
}

/// Decode a 32-byte key from its lowercase/uppercase hex form.
fn parse_key32(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

/// Display-name identities are weaker than a Bluetooth address. They are
/// accepted for one transfer but never remembered.
pub fn is_stable_key(address: &str) -> bool {
    !address.trim().to_ascii_lowercase().starts_with("name:")
}

/// The answer supplied by the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationResponse {
    Allow { remember: bool },
    Deny { remember: bool },
}

#[derive(Debug)]
enum Responder {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Async(oneshot::Sender<AuthorizationResponse>),
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    Blocking(std::sync::mpsc::Sender<AuthorizationResponse>),
}

#[derive(Debug)]
struct Pending {
    address: String,
    name: String,
    responder: Responder,
}

#[derive(Debug)]
struct AuthorizerInner {
    trust: TrustStore,
    events: EventSink,
    /// The desktop UI can answer prompts; the CLI cannot.
    interactive: bool,
    pending: Mutex<HashMap<String, Pending>>,
}

/// Decides whether an incoming push may proceed. The same object serves the
/// UI (async responses), Linux D-Bus calls (async wait) and Windows' blocking
/// RFCOMM workers.
#[derive(Debug, Clone)]
pub struct Authorizer {
    inner: Arc<AuthorizerInner>,
}

impl Authorizer {
    pub fn new(trust: TrustStore, events: EventSink, interactive: bool) -> Self {
        Self {
            inner: Arc::new(AuthorizerInner {
                trust,
                events,
                interactive,
                pending: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Check a decision that needs no prompt. `None` means "ask the user".
    fn remembered(&self, address: &str) -> Option<Result<(), String>> {
        if !is_stable_key(address) {
            return match self.inner.trust.policy() {
                IncomingPolicy::TrustedOnly => Some(Err(
                    "the sender's Bluetooth address could not be resolved, so it cannot be \
                     verified against your trusted senders"
                        .into(),
                )),
                IncomingPolicy::Ask => None,
            };
        }
        match self.inner.trust.decision(address) {
            Some(TrustDecision::Allow) => Some(Ok(())),
            Some(TrustDecision::Block) => {
                Some(Err("the sender is blocked in your trust settings".into()))
            }
            None => match self.inner.trust.policy() {
                IncomingPolicy::Ask => None,
                IncomingPolicy::TrustedOnly => {
                    Some(Err("the sender is not in your trusted senders".into()))
                }
            },
        }
    }

    fn non_interactive_error(&self) -> String {
        "new sender; run the Kalo window to approve this transfer".to_string()
    }

    /// Async authorization used by the Linux OBEX agent.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub async fn authorize(
        &self,
        id: &str,
        address: &str,
        name: &str,
        file_name: &str,
        size: Option<u64>,
    ) -> Result<(), String> {
        if let Some(decision) = self.remembered(address) {
            return decision;
        }
        if !self.inner.interactive {
            return Err(self.non_interactive_error());
        }

        let (tx, rx) = oneshot::channel();
        self.register(id, address, name, Responder::Async(tx));
        self.publish_request(id, address, name, file_name, size);

        match tokio::time::timeout(AUTHORIZATION_TIMEOUT, rx).await {
            Ok(Ok(AuthorizationResponse::Allow { remember })) => {
                self.apply_remember(id, address, name, true, remember);
                Ok(())
            }
            Ok(Ok(AuthorizationResponse::Deny { remember })) => {
                self.apply_remember(id, address, name, false, remember);
                Err("declined in the Kalo window".into())
            }
            Ok(Err(_)) => Err("the authorization request was canceled".into()),
            Err(_) => {
                self.inner
                    .pending
                    .lock()
                    .expect("authorization lock")
                    .remove(id);
                Err(format!(
                    "no approval was given within {}s",
                    AUTHORIZATION_TIMEOUT.as_secs()
                ))
            }
        }
    }

    /// Blocking authorization used by the Windows RFCOMM worker threads.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub fn authorize_blocking(
        &self,
        id: &str,
        address: &str,
        name: &str,
        file_name: &str,
        size: Option<u64>,
    ) -> Result<(), String> {
        if let Some(decision) = self.remembered(address) {
            return decision;
        }
        if !self.inner.interactive {
            return Err(self.non_interactive_error());
        }

        let (tx, rx) = std::sync::mpsc::channel();
        self.register(id, address, name, Responder::Blocking(tx));
        self.publish_request(id, address, name, file_name, size);

        match rx.recv_timeout(AUTHORIZATION_TIMEOUT) {
            Ok(AuthorizationResponse::Allow { remember }) => {
                self.apply_remember(id, address, name, true, remember);
                Ok(())
            }
            Ok(AuthorizationResponse::Deny { remember }) => {
                self.apply_remember(id, address, name, false, remember);
                Err("declined in the Kalo window".into())
            }
            Err(_) => {
                self.inner
                    .pending
                    .lock()
                    .expect("authorization lock")
                    .remove(id);
                Err(format!(
                    "no approval was given within {}s",
                    AUTHORIZATION_TIMEOUT.as_secs()
                ))
            }
        }
    }

    fn register(&self, id: &str, address: &str, name: &str, responder: Responder) {
        self.inner
            .pending
            .lock()
            .expect("authorization lock")
            .insert(
                id.to_string(),
                Pending {
                    address: address.to_string(),
                    name: name.to_string(),
                    responder,
                },
            );
    }

    fn publish_request(
        &self,
        id: &str,
        address: &str,
        name: &str,
        file_name: &str,
        size: Option<u64>,
    ) {
        self.inner.events.send(Event::IncomingAuthorization {
            id: id.to_string(),
            sender: name.to_string(),
            address: address.to_string(),
            name: file_name.to_string(),
            size,
            stable: is_stable_key(address),
        });
    }

    /// Answer a pending prompt. Returns false when the transfer already ended
    /// (timeout, disconnect or a second click).
    pub fn respond(&self, id: &str, allow: bool, remember: bool) -> bool {
        let pending = self
            .inner
            .pending
            .lock()
            .expect("authorization lock")
            .remove(id);
        let Some(pending) = pending else {
            return false;
        };
        self.apply_remember(id, &pending.address, &pending.name, allow, remember);
        let response = if allow {
            AuthorizationResponse::Allow { remember }
        } else {
            AuthorizationResponse::Deny { remember }
        };
        match pending.responder {
            Responder::Async(tx) => tx.send(response).is_ok(),
            Responder::Blocking(tx) => tx.send(response).is_ok(),
        }
    }

    fn apply_remember(&self, id: &str, address: &str, name: &str, allow: bool, remember: bool) {
        if !remember {
            return;
        }
        if !is_stable_key(address) {
            self.inner.events.send(Event::Log(format!(
                "{name}: Bluetooth address unknown, so this decision applies to this transfer only"
            )));
            return;
        }
        let decision = if allow {
            TrustDecision::Allow
        } else {
            TrustDecision::Block
        };
        if let Err(error) = self.inner.trust.remember(address, name, decision) {
            self.inner.events.send(Event::Log(format!(
                "could not save the trust decision for {name}: {error:#}"
            )));
        } else {
            self.inner.events.send(Event::Log(format!(
                "{name} was saved as {} (transfer {id})",
                if allow { "trusted" } else { "blocked" }
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_store() -> (TrustStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("kalo-test-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trust.json");
        (TrustStore::load_from(path.clone()).0, path)
    }

    #[test]
    fn missing_trust_store_starts_empty_with_ask_policy() {
        let store = TrustStore::in_memory();
        assert_eq!(store.policy(), IncomingPolicy::Ask);
        assert!(store.entries().is_empty());
    }

    #[test]
    fn decisions_are_normalized_and_persisted() {
        let (store, path) = temp_store();
        store
            .remember("aa:bb:cc:dd:ee:ff", "Phone", TrustDecision::Allow)
            .unwrap();
        assert_eq!(
            store.decision("AA:BB:CC:DD:EE:FF"),
            Some(TrustDecision::Allow)
        );

        let (reloaded, warning) = TrustStore::load_from(path.clone());
        assert!(warning.is_none());
        assert_eq!(
            reloaded.decision("aa:bb:cc:dd:ee:ff"),
            Some(TrustDecision::Allow)
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn pinned_identity_is_visible_without_ratchet_chains() {
        let dir = std::env::temp_dir().join(format!("kalo-test-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trust.json");
        let peer_key = hex::encode([1u8; 32]);
        std::fs::write(
            &path,
            format!(
                r#"{{"devices":{{"AA:BB":{{"name":"Phone","decision":"allow","peer_key":"{peer_key}"}}}}}}"#
            ),
        )
        .unwrap();

        let (store, warning) = TrustStore::load_from(path.clone());
        assert!(warning.is_none());
        // A damaged entry keeps its pinned identity visible, so receivers
        // reject downgrades even though full pairing state is incomplete.
        assert!(store.is_pinned("AA:BB"));
        assert!(!store.is_paired("AA:BB"));
        assert!(store.outgoing_chain("AA:BB").is_none());
        assert!(store.incoming_chain("AA:BB").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn incoming_ratchet_accepts_forward_skips_and_rejects_rewinds() {
        let (store, path) = temp_store();
        store
            .pin_peer("AA:BB", "Phone", [1u8; 32], [2u8; 32], [3u8; 32])
            .unwrap();
        assert_eq!(store.incoming_chain("AA:BB").unwrap().step, 0);

        // The sender burned steps 0 and 1, so this container authenticates
        // at step 2. Committing it must move the receiver to step 3.
        store.commit_incoming("AA:BB", 0, 3, [9u8; 32]).unwrap();
        assert_eq!(store.incoming_chain("AA:BB").unwrap().step, 3);

        // A delayed container from an older step can no longer rewind or
        // reuse the chain, and a stale completion is refused.
        assert!(store.commit_incoming("AA:BB", 0, 1, [8u8; 32]).is_err());
        assert!(store.commit_incoming("AA:BB", 2, 3, [8u8; 32]).is_err());
        assert!(store.commit_incoming("AA:BB", 3, 3, [8u8; 32]).is_err());
        assert_eq!(store.incoming_chain("AA:BB").unwrap().step, 3);

        // A container authenticated at exactly the maximum skip must be
        // committable; the decryptor accepts that boundary too. Advancing any
        // further is refused.
        store
            .commit_incoming("AA:BB", 3, 3 + crate::crypto::MAX_CHAIN_SKIP + 1, [7u8; 32])
            .unwrap();
        assert_eq!(
            store.incoming_chain("AA:BB").unwrap().step,
            3 + crate::crypto::MAX_CHAIN_SKIP + 1
        );
        let current = 3 + crate::crypto::MAX_CHAIN_SKIP + 1;
        assert!(
            store
                .commit_incoming(
                    "AA:BB",
                    current,
                    current + crate::crypto::MAX_CHAIN_SKIP + 2,
                    [6u8; 32],
                )
                .is_err()
        );
        assert_eq!(store.incoming_chain("AA:BB").unwrap().step, current);

        // The advanced state is durable.
        let (reloaded, warning) = TrustStore::load_from(path.clone());
        assert!(warning.is_none());
        assert_eq!(reloaded.incoming_chain("AA:BB").unwrap().step, current);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn concurrent_trust_writes_do_not_lose_entries() {
        let (store, path) = temp_store();
        let workers = 8;
        let per_worker = 20;
        let handles = (0..workers)
            .map(|worker| {
                let store = store.clone();
                std::thread::spawn(move || {
                    for index in 0..per_worker {
                        store
                            .remember(
                                &format!("AA:BB:{worker:02X}:{index:02X}"),
                                "Phone",
                                TrustDecision::Allow,
                            )
                            .unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }

        let (reloaded, warning) = TrustStore::load_from(path.clone());
        assert!(warning.is_none());
        assert_eq!(reloaded.entries().len(), workers * per_worker);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn policy_and_removal_persist() {
        let (store, path) = temp_store();
        store
            .remember("AA:BB", "Phone", TrustDecision::Allow)
            .unwrap();
        store.set_policy(IncomingPolicy::TrustedOnly).unwrap();
        store.remove("aa:bb").unwrap();
        assert!(store.entries().is_empty());

        let (reloaded, _) = TrustStore::load_from(path.clone());
        assert_eq!(reloaded.policy(), IncomingPolicy::TrustedOnly);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn trusted_only_rejects_unknown_without_prompting() {
        let store = TrustStore::in_memory();
        store.set_policy(IncomingPolicy::TrustedOnly).unwrap();
        let sink = EventSink::new(16);
        let authorizer = Authorizer::new(store, sink, true);
        let error = authorizer
            .authorize_blocking("id", "AA:BB", "Phone", "photo.jpg", None)
            .unwrap_err();
        assert!(error.contains("not in your trusted senders"));
    }

    #[test]
    fn name_based_identity_is_never_remembered() {
        let store = TrustStore::in_memory();
        let sink = EventSink::new(16);
        let authorizer = Authorizer::new(store.clone(), sink, true);
        assert!(!is_stable_key("name:Pixel 8"));
        assert!(authorizer.remembered("name:Pixel 8").is_none());

        authorizer.apply_remember("id", "name:Pixel 8", "Pixel 8", true, true);
        assert!(store.entries().is_empty());
    }

    #[test]
    fn blocking_prompt_can_be_answered_and_remembered() {
        let (store, path) = temp_store();
        let sink = EventSink::new(16);
        let mut events = sink.subscribe();
        let authorizer = Authorizer::new(store.clone(), sink, true);
        let worker = authorizer.clone();
        let handle = std::thread::spawn(move || {
            worker.authorize_blocking("id-1", "AA:BB:CC:DD:EE:FF", "Phone", "photo.jpg", Some(5))
        });

        let mut event = None;
        for _ in 0..200 {
            match events.try_recv() {
                Ok(received) => {
                    event = Some(received);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        let event = event.expect("authorization request");
        assert!(matches!(
            event,
            Event::IncomingAuthorization { ref id, stable: true, .. } if id == "id-1"
        ));
        assert!(authorizer.respond("id-1", true, true));
        assert!(handle.join().unwrap().is_ok());
        assert_eq!(
            store.decision("AA:BB:CC:DD:EE:FF"),
            Some(TrustDecision::Allow)
        );
        assert!(!authorizer.respond("id-1", true, false));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn blocked_sender_is_rejected_without_a_prompt() {
        let (store, path) = temp_store();
        store
            .remember("AA:BB", "Phone", TrustDecision::Block)
            .unwrap();
        let sink = EventSink::new(16);
        let authorizer = Authorizer::new(store, sink, true);
        assert!(
            authorizer
                .authorize_blocking("id", "aa:bb", "Phone", "photo.jpg", None)
                .unwrap_err()
                .contains("blocked")
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
