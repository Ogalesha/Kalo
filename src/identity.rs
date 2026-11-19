//! Device identity and authenticated pairing.
//!
//! Kalo keeps one Ed25519 identity per installation. Pairing two devices uses
//! SPAKE2 over the shared encryption passphrase, so an eavesdropper who sees
//! the pairing objects cannot mount an offline guess or impersonate either
//! side. The three pairing objects are ordinary OPP pushes:
//!
//! 1. initiator → responder: `request` (SPAKE2 share + identity key)
//! 2. responder → initiator: `response` (SPAKE2 share + proof + identity key)
//! 3. initiator → responder: `confirm` (proof that both derived the same key)
//!
//! Both sides pin the other identity key and derive two independent
//! hash-ratchet chains. Paired transfers then use [`crate::crypto`]'s
//! KALOENC2 containers instead of the shared passphrase container.
//!
//! Pairing files are never saved as received files: the receiver recognizes
//! the `kalo-pair-*.kalopair` name, processes the object, and deletes it.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::MIN_PASSPHRASE_CHARS;
use crate::events::{Event, EventSink};
use crate::paths;
use crate::security;
use crate::settings;
use crate::trust::{TrustStore, normalize_key};

/// Magic inside every pairing object.
const PAIR_MAGIC: &str = "KALOPAIR1";
/// Pairing objects are small JSON documents; anything larger is hostile.
pub(crate) const MAX_PAIR_BYTES: u64 = 64 * 1024;
/// A pending pairing is abandoned after this long. The two OPP transfers that
/// carry the request and the response each have their own deadlines.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const MAX_NAME_BYTES: usize = 200;

/// Identify the pairing exchange without relying on a Bluetooth address: the
/// initiator's random nonce, the role, and the object kind are enough for
/// SPAKE2 to bind the transcript.
fn role_id(role: u8, nonce: &[u8; 16]) -> Vec<u8> {
    let mut id = Vec::with_capacity(20);
    id.extend_from_slice(b"KaloPair");
    id.push(role);
    id.extend_from_slice(nonce);
    id
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u32).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hkdf.expand(info, &mut out)
        .expect("32 bytes is a valid HKDF output length");
    out
}

fn hmac32(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(&(part.len() as u32).to_le_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// A cleaned display name for the peer. Path separators are removed here and
/// again when the receiver chooses a folder; this copy is only for the UI and
/// trust store.
fn clean_name(name: &str) -> String {
    let name: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .collect();
    let mut name = name.trim().to_string();
    if name.len() > MAX_NAME_BYTES {
        let mut end = 0;
        for (index, character) in name.char_indices() {
            if index + character.len_utf8() > MAX_NAME_BYTES {
                break;
            }
            end = index + character.len_utf8();
        }
        name.truncate(end);
    }
    if name.is_empty() {
        "Kalo device".to_string()
    } else {
        name
    }
}

/// This installation's long-term pairing identity.
pub struct DeviceIdentity {
    signing: SigningKey,
    public: [u8; 32],
    name: String,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("name", &self.name)
            .field("public_key", &hex::encode(self.public))
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentity {
    secret: String,
    public: String,
}

impl DeviceIdentity {
    /// Load the identity, creating it on first use. A corrupt identity is an
    /// error: silently replacing it would break every existing pairing.
    pub fn load_or_create() -> Result<Self> {
        Self::load_from(&paths::identity_file())
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(raw) => {
                let stored: StoredIdentity =
                    serde_json::from_str(&raw).context("parse the device identity")?;
                let secret = decode_key32(&stored.secret).context("invalid identity secret")?;
                let expected = decode_key32(&stored.public).context("invalid identity key")?;
                let signing = SigningKey::from_bytes(&secret);
                let public = signing.verifying_key().to_bytes();
                ensure!(
                    public == expected,
                    "the stored identity public key does not match its secret"
                );
                Ok(Self {
                    signing,
                    public,
                    name: clean_name(&paths::device_name()),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let secret = random_key32()?;
                let signing = SigningKey::from_bytes(&secret);
                let public = signing.verifying_key().to_bytes();
                let stored = StoredIdentity {
                    secret: hex::encode(secret),
                    public: hex::encode(public),
                };
                settings::write_json(path, &stored).context("save the device identity")?;
                Ok(Self {
                    signing,
                    public,
                    name: clean_name(&paths::device_name()),
                })
            }
            Err(error) => Err(error).context("read the device identity"),
        }
    }

    /// Public key bytes, safe to share.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Clone of the signing key for the sender-side container encryptor.
    pub fn signing_key(&self) -> SigningKey {
        self.signing.clone()
    }

    fn sign(&self, bytes: &[u8]) -> [u8; 64] {
        self.signing.sign(bytes).to_bytes()
    }

    fn verify(public: &[u8; 32], bytes: &[u8], signature: &[u8; 64]) -> Result<()> {
        let key = VerifyingKey::from_bytes(public).context("invalid peer identity key")?;
        key.verify_strict(bytes, &Signature::from_bytes(signature))
            .map_err(|_| anyhow!("the pairing object signature is invalid"))
    }
}

fn decode_key32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("key is not hexadecimal")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("key must be exactly 32 bytes"))
}

fn random_key32() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|error| anyhow!("generate a random key: {error}"))?;
    Ok(key)
}

fn random_nonce() -> Result<[u8; 16]> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| anyhow!("generate a random nonce: {error}"))?;
    Ok(nonce)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairWire {
    magic: String,
    kind: String,
    pake: String,
    identity: String,
    name: String,
    nonce: String,
    transcript: String,
    proof: String,
    sig: String,
}

/// The canonical bytes covered by a pairing signature. Length prefixes keep a
/// peer from moving bytes between fields.
fn signed_bytes(wire: &PairWire) -> Vec<u8> {
    let mut out = b"KaloPair signature v1".to_vec();
    for field in [
        wire.kind.as_bytes(),
        wire.pake.as_bytes(),
        wire.identity.as_bytes(),
        wire.name.as_bytes(),
        wire.nonce.as_bytes(),
        wire.transcript.as_bytes(),
        wire.proof.as_bytes(),
    ] {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

struct ParsedPair {
    wire: PairWire,
    pake: Vec<u8>,
    public: [u8; 32],
    nonce: [u8; 16],
    transcript: Option<[u8; 32]>,
    proof: Option<[u8; 32]>,
}

fn parse_pair(bytes: &[u8]) -> Result<ParsedPair> {
    ensure!(
        bytes.len() as u64 <= MAX_PAIR_BYTES,
        "the pairing object is too large"
    );
    let wire: PairWire = serde_json::from_slice(bytes).context("parse the pairing object")?;
    ensure!(wire.magic == PAIR_MAGIC, "not a Kalo pairing object");
    ensure!(
        matches!(wire.kind.as_str(), "request" | "response" | "confirm"),
        "unknown pairing object kind"
    );
    let pake = hex::decode(&wire.pake).context("invalid pairing exchange value")?;
    ensure!(
        (1..=256).contains(&pake.len()),
        "invalid pairing exchange length"
    );
    let public = decode_key32(&wire.identity)?;
    let nonce: [u8; 16] = hex::decode(&wire.nonce)
        .context("invalid pairing nonce")?
        .try_into()
        .map_err(|_| anyhow!("invalid pairing nonce length"))?;
    let signature: [u8; 64] = hex::decode(&wire.sig)
        .context("invalid pairing signature")?
        .try_into()
        .map_err(|_| anyhow!("invalid pairing signature length"))?;
    let transcript = if wire.transcript.is_empty() {
        None
    } else {
        Some(
            hex::decode(&wire.transcript)
                .context("invalid pairing transcript")?
                .try_into()
                .map_err(|_| anyhow!("invalid pairing transcript length"))?,
        )
    };
    let proof = if wire.proof.is_empty() {
        None
    } else {
        Some(
            hex::decode(&wire.proof)
                .context("invalid pairing proof")?
                .try_into()
                .map_err(|_| anyhow!("invalid pairing proof length"))?,
        )
    };
    if wire.kind == "request" {
        ensure!(
            transcript.is_none() && proof.is_none(),
            "a pairing request cannot carry a transcript or proof"
        );
    } else {
        ensure!(
            transcript.is_some() && proof.is_some(),
            "the pairing response is missing its proof"
        );
    }
    DeviceIdentity::verify(&public, &signed_bytes(&wire), &signature)?;
    Ok(ParsedPair {
        wire,
        pake,
        public,
        nonce,
        transcript,
        proof,
    })
}

fn serialize_wire(wire: &PairWire) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(wire).context("serialize the pairing object")?;
    ensure!(
        bytes.len() as u64 <= MAX_PAIR_BYTES,
        "the pairing object is too large"
    );
    Ok(bytes)
}

/// Chains and identity pinned after a successful pairing.
pub struct PairedPeer {
    pub public: [u8; 32],
    pub name: String,
    pub send_chain: [u8; 32],
    pub recv_chain: [u8; 32],
}

impl std::fmt::Debug for PairedPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairedPeer")
            .field("public", &hex::encode(self.public))
            .field("name", &self.name)
            .field("chains", &"<redacted>")
            .finish()
    }
}

/// Initiator half of an in-flight pairing.
pub struct InitiatorState {
    spake: Option<Spake2<Ed25519Group>>,
    request: Vec<u8>,
    request_hash: [u8; 32],
    nonce: [u8; 16],
}

/// Responder half of an in-flight pairing.
pub struct ResponderState {
    transcript_hash: [u8; 32],
    peer_public: [u8; 32],
    peer_name: String,
    session: Zeroizing<[u8; 32]>,
}

/// Build the first pairing object and keep the SPAKE2 state.
pub fn start_pairing(
    identity: &DeviceIdentity,
    passphrase: &str,
) -> Result<(Vec<u8>, InitiatorState)> {
    ensure!(
        passphrase.chars().count() >= MIN_PASSPHRASE_CHARS,
        "set a shared passphrase of at least {MIN_PASSPHRASE_CHARS} characters before pairing"
    );
    let nonce = random_nonce()?;
    let (spake, share) = Spake2::<Ed25519Group>::start_a(
        &Password::new(passphrase.as_bytes()),
        &Identity::new(&role_id(b'A', &nonce)),
        &Identity::new(&role_id(b'B', &nonce)),
    );
    let request = PairWire {
        magic: PAIR_MAGIC.into(),
        kind: "request".into(),
        pake: hex::encode(&share),
        identity: identity.public_hex(),
        name: identity.name().to_string(),
        nonce: hex::encode(nonce),
        transcript: String::new(),
        proof: String::new(),
        sig: String::new(),
    };
    let signature = identity.sign(&signed_bytes(&request));
    let request = PairWire {
        sig: hex::encode(signature),
        ..request
    };
    let bytes = serialize_wire(&request)?;
    let request_hash = hash_parts(&[&bytes]);
    Ok((
        bytes.clone(),
        InitiatorState {
            spake: Some(spake),
            request: bytes,
            request_hash,
            nonce,
        },
    ))
}

/// Process a request, produce the response object and keep the responder
/// state until the initiator's confirmation arrives.
pub fn accept_request(
    identity: &DeviceIdentity,
    passphrase: &str,
    request: &[u8],
) -> Result<(Vec<u8>, ResponderState)> {
    ensure!(
        passphrase.chars().count() >= MIN_PASSPHRASE_CHARS,
        "set a shared passphrase of at least {MIN_PASSPHRASE_CHARS} characters before pairing"
    );
    let parsed = parse_pair(request)?;
    ensure!(parsed.wire.kind == "request", "expected a pairing request");
    ensure!(
        parsed.public != identity.public(),
        "a device cannot pair with itself"
    );
    let (spake, share) = Spake2::<Ed25519Group>::start_b(
        &Password::new(passphrase.as_bytes()),
        &Identity::new(&role_id(b'A', &parsed.nonce)),
        &Identity::new(&role_id(b'B', &parsed.nonce)),
    );
    let shared = spake
        .finish(&parsed.pake)
        .map_err(|_| anyhow!("pairing failed: the shared passphrase does not match"))?;
    let request_hash = hash_parts(&[request]);
    let response_key = hkdf32(&shared, &request_hash, b"Kalo pairing response proof v1");
    let proof = hmac32(
        &response_key,
        &[
            b"responder",
            &share,
            &identity.public(),
            identity.name().as_bytes(),
            &parsed.nonce,
        ],
    );
    let response = PairWire {
        magic: PAIR_MAGIC.into(),
        kind: "response".into(),
        pake: hex::encode(&share),
        identity: identity.public_hex(),
        name: identity.name().to_string(),
        nonce: hex::encode(parsed.nonce),
        transcript: hex::encode(request_hash),
        proof: hex::encode(proof),
        sig: String::new(),
    };
    let signature = identity.sign(&signed_bytes(&response));
    let response = PairWire {
        sig: hex::encode(signature),
        ..response
    };
    let response_bytes = serialize_wire(&response)?;
    let transcript_hash = hash_parts(&[request, &response_bytes]);
    let session = Zeroizing::new(hkdf32(
        &shared,
        &transcript_hash,
        b"Kalo pairing session v1",
    ));
    Ok((
        response_bytes.clone(),
        ResponderState {
            transcript_hash,
            peer_public: parsed.public,
            peer_name: clean_name(&parsed.wire.name),
            session,
        },
    ))
}

impl ResponderState {
    /// Verify the initiator's confirmation. Only a peer that derived the same
    /// SPAKE2 session can produce it.
    pub fn finish(self, confirm: &[u8]) -> Result<PairedPeer> {
        let parsed = parse_pair(confirm)?;
        ensure!(
            parsed.wire.kind == "confirm",
            "expected a pairing confirmation"
        );
        ensure!(
            parsed.transcript == Some(self.transcript_hash),
            "the pairing confirmation has the wrong transcript"
        );
        ensure!(
            parsed.public == self.peer_public,
            "the pairing confirmation comes from a different identity"
        );
        ensure!(
            parsed.wire.transcript == hex::encode(self.transcript_hash),
            "the pairing confirmation transcript is malformed"
        );
        let confirm_key = hkdf32(
            &self.session[..],
            &self.transcript_hash,
            b"Kalo pairing confirm v1",
        );
        let expected = hmac32(&confirm_key, &[b"initiator", &self.transcript_hash]);
        ensure!(
            parsed
                .proof
                .as_ref()
                .is_some_and(|proof| constant_time_eq(proof, &expected)),
            "the pairing confirmation proof is invalid"
        );
        let (a2b, b2a) = derive_chains(&self.session[..], &self.transcript_hash);
        Ok(PairedPeer {
            public: self.peer_public,
            name: self.peer_name,
            send_chain: b2a,
            recv_chain: a2b,
        })
    }
}

fn derive_chains(session: &[u8], transcript_hash: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (
        hkdf32(session, transcript_hash, b"Kalo chain A to B v1"),
        hkdf32(session, transcript_hash, b"Kalo chain B to A v1"),
    )
}

/// One pending pairing, with the moment it was created.
struct Pending<T> {
    state: T,
    started: Instant,
}

#[derive(Default)]
struct PendingSet {
    outgoing: HashMap<String, Pending<InitiatorState>>,
    incoming: HashMap<String, Pending<ResponderState>>,
}

/// What the receiver should do after processing a pairing object.
pub struct ControlOutcome {
    /// Response or confirmation object to send back, if any.
    pub reply: Option<Vec<u8>>,
    pub message: String,
}

/// Shared pairing state used by the UI and both receivers. It owns the
/// pending handshakes and writes completed pairings into the trust store.
#[derive(Clone)]
pub struct PairingManager {
    identity: Arc<DeviceIdentity>,
    trust: TrustStore,
    events: EventSink,
    pending: Arc<Mutex<PendingSet>>,
}

impl std::fmt::Debug for PairingManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingManager")
            .field("identity", &self.identity)
            .field("pending", &"<redacted>")
            .finish()
    }
}

impl PairingManager {
    pub fn new(identity: DeviceIdentity, trust: TrustStore, events: EventSink) -> Self {
        Self {
            identity: Arc::new(identity),
            trust,
            events,
            pending: Arc::new(Mutex::new(PendingSet::default())),
        }
    }

    pub fn trust(&self) -> &TrustStore {
        &self.trust
    }

    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// Start an outgoing pairing and return the request object bytes.
    pub fn begin(&self, peer: &str, passphrase: &str) -> Result<Vec<u8>> {
        let key = normalize_key(peer);
        if !crate::trust::is_stable_key(&key) {
            bail!("this device has no stable Bluetooth address, so it cannot be paired");
        }
        if self.trust.is_paired(&key) {
            bail!("this device is already paired; remove it from the trust list first");
        }
        let (request, state) = start_pairing(&self.identity, passphrase)?;
        let mut pending = self.pending.lock().expect("pairing lock");
        pending.cleanup();
        if pending.incoming.contains_key(&key) {
            bail!("the other device already started pairing; finish or cancel that first");
        }
        pending.outgoing.insert(
            key,
            Pending {
                state,
                started: Instant::now(),
            },
        );
        Ok(request)
    }

    /// Forget an in-flight pairing for `peer`.
    pub fn cancel(&self, peer: &str) {
        let key = normalize_key(peer);
        let mut pending = self.pending.lock().expect("pairing lock");
        pending.outgoing.remove(&key);
        pending.incoming.remove(&key);
    }

    /// Process one pairing object. The caller must delete the file even when
    /// this returns an error: control objects are never user files.
    pub fn handle_file(&self, peer: &str, path: &Path, passphrase: &str) -> Result<ControlOutcome> {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("inspect pairing object {}", path.display()))?;
        ensure!(
            metadata.is_file() && metadata.len() <= MAX_PAIR_BYTES,
            "the pairing object is not a small regular file"
        );
        let bytes = std::fs::read(path)
            .with_context(|| format!("read pairing object {}", path.display()))?;
        self.handle_bytes(peer, &bytes, passphrase)
    }

    pub fn handle_bytes(
        &self,
        peer: &str,
        bytes: &[u8],
        passphrase: &str,
    ) -> Result<ControlOutcome> {
        let key = normalize_key(peer);
        if self.trust.is_paired(&key) {
            bail!("this device is already paired; remove it from the trust list first");
        }
        let parsed = parse_pair(bytes)?;
        match parsed.wire.kind.as_str() {
            "request" => {
                {
                    let mut pending = self.pending.lock().expect("pairing lock");
                    pending.cleanup();
                    if pending.outgoing.contains_key(&key) {
                        bail!("both devices started pairing at the same time; try again");
                    }
                }
                let (response, state) = accept_request(&self.identity, passphrase, bytes)?;
                {
                    let mut pending = self.pending.lock().expect("pairing lock");
                    pending.incoming.insert(
                        key.clone(),
                        Pending {
                            state,
                            started: Instant::now(),
                        },
                    );
                }
                let message = format!(
                    "Pairing request received from {}; waiting for its confirmation…",
                    clean_name(&parsed.wire.name)
                );
                self.events.send(Event::Log(message.clone()));
                Ok(ControlOutcome {
                    reply: Some(response),
                    message,
                })
            }
            "response" => {
                let state = self
                    .pending
                    .lock()
                    .expect("pairing lock")
                    .outgoing
                    .remove(&key)
                    .context("no outgoing pairing is waiting for this response")?;
                let (confirm, paired) = finish_initiator(&self.identity, state.state, bytes)?;
                let name = paired.name.clone();
                self.pin(&key, &paired)?;
                let message = format!("Paired with {name}; files now use per-device encryption.");
                self.events.send(Event::Pairing {
                    address: key.clone(),
                    name: name.clone(),
                    ok: true,
                    message: message.clone(),
                });
                Ok(ControlOutcome {
                    reply: Some(confirm),
                    message,
                })
            }
            "confirm" => {
                let state = self
                    .pending
                    .lock()
                    .expect("pairing lock")
                    .incoming
                    .remove(&key)
                    .context("no incoming pairing is waiting for this confirmation")?;
                let paired = state.state.finish(bytes)?;
                let name = paired.name.clone();
                self.pin(&key, &paired)?;
                let message = format!("Paired with {name}; files now use per-device encryption.");
                self.events.send(Event::Pairing {
                    address: key.clone(),
                    name: name.clone(),
                    ok: true,
                    message: message.clone(),
                });
                Ok(ControlOutcome {
                    reply: None,
                    message,
                })
            }
            _ => bail!("unknown pairing object kind"),
        }
    }

    fn pin(&self, peer: &str, paired: &PairedPeer) -> Result<()> {
        ensure!(
            paired.public != self.identity.public(),
            "refusing a self-pairing"
        );
        ensure!(
            !self.trust.is_paired(peer),
            "the device was paired concurrently; remove it before pairing again"
        );
        self.trust.pin_peer(
            peer,
            &paired.name,
            paired.public,
            paired.send_chain,
            paired.recv_chain,
        )
    }
}

/// Sign the initiator's confirmation with the long-term identity. This is
/// separate from [`InitiatorState`] because that state deliberately does not
/// keep another copy of the signing key.
fn finish_initiator(
    identity: &DeviceIdentity,
    mut state: InitiatorState,
    response: &[u8],
) -> Result<(Vec<u8>, PairedPeer)> {
    let spake = state
        .spake
        .take()
        .context("the pairing exchange was already finished")?;
    let parsed = parse_pair(response)?;
    ensure!(
        parsed.wire.kind == "response",
        "expected a pairing response"
    );
    ensure!(
        parsed.transcript == Some(state.request_hash),
        "the pairing response does not match this request"
    );
    ensure!(
        parsed.nonce == state.nonce,
        "the pairing response has the wrong session nonce"
    );
    ensure!(
        parsed.public != identity.public(),
        "the peer echoed this device's identity"
    );
    let shared = spake
        .finish(&parsed.pake)
        .map_err(|_| anyhow!("pairing failed: the shared passphrase does not match"))?;
    let response_key = hkdf32(
        &shared,
        &state.request_hash,
        b"Kalo pairing response proof v1",
    );
    let expected = hmac32(
        &response_key,
        &[
            b"responder",
            &parsed.pake,
            &parsed.public,
            parsed.wire.name.as_bytes(),
            &parsed.nonce,
        ],
    );
    ensure!(
        parsed
            .proof
            .as_ref()
            .is_some_and(|proof| constant_time_eq(proof, &expected)),
        "the pairing response proof is invalid"
    );

    let transcript_hash = hash_parts(&[&state.request, response]);
    let session = Zeroizing::new(hkdf32(
        &shared,
        &transcript_hash,
        b"Kalo pairing session v1",
    ));
    let confirm_key = hkdf32(&session[..], &transcript_hash, b"Kalo pairing confirm v1");
    let proof = hmac32(&confirm_key, &[b"initiator", &transcript_hash]);
    let confirm = PairWire {
        magic: PAIR_MAGIC.into(),
        kind: "confirm".into(),
        pake: hex::encode(&parsed.pake),
        identity: identity.public_hex(),
        name: identity.name().to_string(),
        nonce: hex::encode(state.nonce),
        transcript: hex::encode(transcript_hash),
        proof: hex::encode(proof),
        sig: String::new(),
    };
    let signature = identity.sign(&signed_bytes(&confirm));
    let confirm = PairWire {
        sig: hex::encode(signature),
        ..confirm
    };
    let bytes = serialize_wire(&confirm)?;

    let (a2b, b2a) = derive_chains(&session[..], &transcript_hash);
    let paired = PairedPeer {
        public: parsed.public,
        name: clean_name(&parsed.wire.name),
        send_chain: a2b,
        recv_chain: b2a,
    };
    Ok((bytes, paired))
}

impl PendingSet {
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.outgoing
            .retain(|_, pending| now.duration_since(pending.started) < PAIRING_TIMEOUT);
        self.incoming
            .retain(|_, pending| now.duration_since(pending.started) < PAIRING_TIMEOUT);
    }
}

/// A private temporary file holding one pairing object. Dropping it removes
/// the object, so success and every error path clean up.
#[derive(Debug)]
pub struct PairingFile {
    path: PathBuf,
}

impl PairingFile {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_PAIR_BYTES,
            "the pairing object is too large"
        );
        let dir = std::env::temp_dir().join("kalo").join("pairing");
        security::create_private_dir(&dir)
            .with_context(|| format!("create pairing staging directory {}", dir.display()))?;
        let path = dir.join(format!("kalo-pair-{}.kalopair", Uuid::new_v4().simple()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .with_context(|| format!("create pairing object {}", path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write pairing object {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync pairing object {}", path.display()))?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PairingFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Whether an incoming object is named like a pairing protocol message. The
/// content is still parsed and signature-checked before it is trusted.
pub fn looks_like_pairing_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("kalo-pair-") && name.ends_with(".kalopair")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::TrustStore;

    const PASSPHRASE: &str = "a long shared pairing passphrase";

    fn identity(name: &str) -> DeviceIdentity {
        let secret = random_key32().unwrap();
        let signing = SigningKey::from_bytes(&secret);
        let public = signing.verifying_key().to_bytes();
        DeviceIdentity {
            signing,
            public,
            name: name.into(),
        }
    }

    fn complete_pairing(
        alice: &DeviceIdentity,
        bob: &DeviceIdentity,
        passphrase: &str,
    ) -> (PairedPeer, PairedPeer) {
        let (request, alice_state) = start_pairing(alice, passphrase).unwrap();
        let (response, bob_state) = accept_request(bob, passphrase, &request).unwrap();
        let (confirm, alice_paired) = finish_initiator(alice, alice_state, &response).unwrap();
        let bob_paired = bob_state.finish(&confirm).unwrap();
        (alice_paired, bob_paired)
    }

    #[test]
    fn pairing_derives_matching_directional_chains() {
        let alice = identity("Alice");
        let bob = identity("Bob");
        let (a, b) = complete_pairing(&alice, &bob, PASSPHRASE);
        assert_eq!(a.public, bob.public());
        assert_eq!(b.public, alice.public());
        assert_eq!(a.name, "Bob");
        assert_eq!(b.name, "Alice");
        assert_eq!(a.send_chain, b.recv_chain);
        assert_eq!(a.recv_chain, b.send_chain);
        assert_ne!(a.send_chain, a.recv_chain);
    }

    #[test]
    fn the_wrong_passphrase_never_derives_a_shared_key() {
        let alice = identity("Alice");
        let bob = identity("Bob");
        let (request, alice_state) = start_pairing(&alice, PASSPHRASE).unwrap();
        let (response, _) = accept_request(&bob, "a different long passphrase", &request).unwrap();
        let error = finish_initiator(&alice, alice_state, &response).unwrap_err();
        assert!(format!("{error:#}").contains("proof"));
    }

    #[test]
    fn tampered_objects_are_rejected() {
        let alice = identity("Alice");
        let bob = identity("Bob");
        let (request, _) = start_pairing(&alice, PASSPHRASE).unwrap();
        let mut wire: serde_json::Value = serde_json::from_slice(&request).unwrap();
        wire["name"] = "Mallory".into();
        let tampered = serde_json::to_vec(&wire).unwrap();
        assert!(accept_request(&bob, PASSPHRASE, &tampered).is_err());

        let (request, alice_state) = start_pairing(&alice, PASSPHRASE).unwrap();
        let (response, _) = accept_request(&bob, PASSPHRASE, &request).unwrap();
        let mut wire: serde_json::Value = serde_json::from_slice(&response).unwrap();
        wire["proof"] = "00".repeat(32).into();
        let tampered = serde_json::to_vec(&wire).unwrap();
        assert!(finish_initiator(&alice, alice_state, &tampered).is_err());
    }

    #[test]
    fn a_confirmation_from_another_exchange_is_rejected() {
        let alice = identity("Alice");
        let bob = identity("Bob");
        let (request, _) = start_pairing(&alice, PASSPHRASE).unwrap();
        let (_, first_bob_state) = accept_request(&bob, PASSPHRASE, &request).unwrap();

        let (other_request, other_alice) = start_pairing(&alice, PASSPHRASE).unwrap();
        let (other_response, _) = accept_request(&bob, PASSPHRASE, &other_request).unwrap();
        let (other_confirm, _) = finish_initiator(&alice, other_alice, &other_response).unwrap();
        assert!(first_bob_state.finish(&other_confirm).is_err());
    }

    #[test]
    fn manager_pins_both_directions_after_three_objects() {
        let alice = identity("Alice");
        let bob = identity("Bob");
        let alice_trust = TrustStore::in_memory();
        let bob_trust = TrustStore::in_memory();
        let sink = EventSink::new(32);
        let alice_manager = PairingManager::new(alice, alice_trust.clone(), sink.clone());
        let bob_manager = PairingManager::new(bob, bob_trust.clone(), sink);

        let request = alice_manager.begin("AA:BB", PASSPHRASE).unwrap();
        let response = bob_manager
            .handle_bytes("AA:BB", &request, PASSPHRASE)
            .unwrap()
            .reply
            .unwrap();
        let outcome = alice_manager
            .handle_bytes("AA:BB", &response, PASSPHRASE)
            .unwrap();
        let confirm = outcome.reply.unwrap();
        let final_outcome = bob_manager
            .handle_bytes("AA:BB", &confirm, PASSPHRASE)
            .unwrap();
        assert!(final_outcome.reply.is_none());
        assert!(alice_trust.is_paired("AA:BB"));
        assert!(bob_trust.is_paired("AA:BB"));
        assert_eq!(
            alice_trust.outgoing_chain("AA:BB").unwrap().key,
            bob_trust.incoming_chain("AA:BB").unwrap().key
        );
        assert_eq!(
            bob_trust.outgoing_chain("AA:BB").unwrap().key,
            alice_trust.incoming_chain("AA:BB").unwrap().key
        );
    }

    #[test]
    fn pairing_files_are_private_and_removed_on_drop() {
        let file = PairingFile::new(b"{}").unwrap();
        let path = file.path().to_path_buf();
        assert!(looks_like_pairing_name(
            path.file_name().unwrap().to_str().unwrap()
        ));
        assert!(path.exists());
        drop(file);
        assert!(!path.exists());
    }

    #[test]
    fn pairing_names_are_recognized_case_insensitively() {
        assert!(looks_like_pairing_name("kalo-pair-1.kalopair"));
        assert!(looks_like_pairing_name("KALO-PAIR-X.KALOPAIR"));
        assert!(!looks_like_pairing_name("holiday.kalopair"));
        assert!(!looks_like_pairing_name("kalo-pair-1.txt"));
    }
}
