//! Application-layer encryption for Kalo-to-Kalo transfers.
//!
//! Bluetooth link encryption only protects the radio hop and is not a
//! guarantee every OPP stack provides. Kalo therefore wraps outgoing files in
//! an authenticated container when the user enables encryption:
//!
//! - the shared passphrase is stretched with Argon2id (64 MiB, 3 passes);
//! - the original filename and plaintext size are encrypted with
//!   XChaCha20-Poly1305;
//! - content is streamed in authenticated 1 MiB chunks with a final record,
//!   so truncation, reordering and tampering are all detected;
//! - every record uses a fresh random 192-bit nonce.
//!
//! Only Kalo with the same passphrase can open the result. A stock OPP
//! receiver sees an opaque `.kalo` object; the container's outer name and
//! size remain visible to the Bluetooth peer. Encryption is optional and off
//! by default so standard OPP peers keep working.

// macOS only sends files, so the receiver-side decryption helpers compiled
// into this module are intentionally unused on that target.
#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result, anyhow, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::security;

/// First eight bytes of every Kalo encrypted container.
pub const MAGIC: &[u8; 8] = b"KALOENC1";

/// Prefix of the private temporary files used while decrypting. The receiver
/// sweep deletes leftovers instead of treating them as received files.
pub const DECRYPT_TEMP_PREFIX: &str = "kalo-dec-";

const VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const KEY_BYTES: usize = 32;
/// Fixed production KDF parameters. The values are stored in each container
/// so future versions can raise them while old files remain readable.
const M_COST: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
/// Refuse containers that ask for an implausibly cheap or abusive KDF.
const MIN_M_COST: u32 = 19 * 1024;
const MAX_M_COST: u32 = 256 * 1024;
const MIN_T_COST: u32 = 2;
const MAX_T_COST: u32 = 10;
const MAX_P_COST: u32 = 4;
const CHUNK_SIZE: u32 = 1024 * 1024;
const MIN_CHUNK_SIZE: u32 = 64 * 1024;
const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 4 * 1024;
const MAX_NAME_BYTES: usize = 1024;
const HEADER_PREFIX: usize = 72;
const RECORD_OVERHEAD: u64 = 4 + NONCE_BYTES as u64 + TAG_BYTES as u64;
const END_MARKER: u32 = u32::MAX;
const KEY_CACHE_ENTRIES: usize = 8;
/// A memorable passphrase is still stronger than a short one; Argon2id only
/// slows down guessing, it cannot make "1234" safe.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Argon2id reserves substantial memory. Serialize derivations so several
/// concurrent incoming transfers cannot multiply the header's KDF bound.
static KDF_LOCK: Mutex<()> = Mutex::new(());

/// Shared runtime encryption settings. The UI changes the passphrase and the
/// outgoing toggle through this handle; the receiver reads the same state.
#[derive(Clone)]
pub struct Encryption {
    state: Arc<RwLock<State>>,
    keys: Arc<Mutex<KeyCache>>,
}

struct State {
    enabled: bool,
    passphrase: Zeroizing<String>,
}

impl std::fmt::Debug for Encryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f.debug_struct("Encryption")
            .field("enabled", &state.enabled)
            .field("configured", &!state.passphrase.is_empty())
            .finish()
    }
}

impl Encryption {
    /// Build the shared encryption state. Outgoing encryption is only
    /// considered enabled when the saved passphrase meets the minimum length,
    /// so editing the settings file cannot leave the UI claiming encryption
    /// is on while every send fails.
    pub fn new(enabled: bool, passphrase: String) -> Self {
        let enabled = enabled && passphrase.chars().count() >= MIN_PASSPHRASE_CHARS;
        Self {
            state: Arc::new(RwLock::new(State {
                enabled,
                passphrase: Zeroizing::new(passphrase),
            })),
            keys: Arc::new(Mutex::new(KeyCache::default())),
        }
    }

    pub fn enabled(&self) -> bool {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .enabled
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .enabled = enabled;
    }

    pub fn is_configured(&self) -> bool {
        !self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .passphrase
            .is_empty()
    }

    pub fn has_strong_passphrase(&self) -> bool {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .passphrase
            .chars()
            .count()
            >= MIN_PASSPHRASE_CHARS
    }

    pub fn set_passphrase(&self, passphrase: String) {
        self.keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .clear();
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .passphrase = Zeroizing::new(passphrase);
    }

    /// Build one encryptor for an outgoing batch. Reusing the derived key and
    /// salt across the batch avoids paying Argon2id once per file; every
    /// record still uses an independent random nonce.
    pub fn encryptor(&self) -> Result<Option<Encryptor>> {
        let passphrase = {
            let state = self
                .state
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !state.enabled {
                return Ok(None);
            }
            state.passphrase.clone()
        };
        if passphrase.is_empty() {
            bail!("encryption is enabled but no passphrase is set");
        }
        Ok(Some(Encryptor::new(&passphrase)?))
    }

    /// A decryptor is available whenever a passphrase is configured, even
    /// when outgoing encryption is off: receiving encrypted files should not
    /// require re-enabling encryption for sending.
    pub fn decryptor(&self) -> Option<Decryptor> {
        let passphrase = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .passphrase
            .clone();
        if passphrase.is_empty() {
            None
        } else {
            Some(Decryptor {
                passphrase,
                keys: self.keys.clone(),
            })
        }
    }
}

/// Derives one key per batch and encrypts files into the container format.
pub struct Encryptor {
    key: Zeroizing<[u8; KEY_BYTES]>,
    salt: [u8; SALT_BYTES],
    chunk_size: u32,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Encryptor {
    fn new(passphrase: &str) -> Result<Self> {
        Self::with_params(passphrase, M_COST, T_COST, P_COST, CHUNK_SIZE)
    }

    fn with_params(
        passphrase: &str,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        chunk_size: u32,
    ) -> Result<Self> {
        if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
            bail!("the encryption passphrase must be at least {MIN_PASSPHRASE_CHARS} characters");
        }
        ensure!(
            (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size),
            "invalid encryption chunk size"
        );
        let mut salt = [0u8; SALT_BYTES];
        random_bytes(&mut salt).map_err(|error| anyhow!("generate encryption salt: {error}"))?;
        let key = derive_key(passphrase.as_bytes(), &salt, m_cost, t_cost, p_cost)?;
        Ok(Self {
            key,
            salt,
            chunk_size,
            m_cost,
            t_cost,
            p_cost,
        })
    }

    /// Exact container size for a plaintext file, including the final record.
    /// The caller uses this gate before any encryption work so a file that
    /// would exceed the OPP limit is rejected up front.
    pub fn container_len(&self, plaintext: u64, name: &str) -> Result<u64> {
        ensure!(
            plaintext <= security::MAX_FILE_BYTES,
            "the file is larger than the 4 GB OPP limit"
        );
        let name = normalized_name(name);
        let metadata_plain = 4usize
            .checked_add(name.len())
            .and_then(|len| len.checked_add(8))
            .context("encrypted filename is too long")?;
        let metadata_cipher = metadata_plain
            .checked_add(TAG_BYTES)
            .context("encrypted metadata is too long")?;
        ensure!(
            metadata_cipher <= MAX_METADATA_BYTES,
            "encrypted filename is too long"
        );
        let chunks = plaintext.div_ceil(self.chunk_size as u64);
        let total = HEADER_PREFIX as u64
            + metadata_cipher as u64
            + chunks
                .checked_mul(RECORD_OVERHEAD)
                .context("encrypted size overflow")?
            + plaintext
            + RECORD_OVERHEAD;
        ensure!(
            total <= security::MAX_FILE_BYTES,
            "adding encryption overhead would push the file over the 4 GB OPP limit"
        );
        Ok(total)
    }

    /// Encrypt `input` into `output`. The output must not exist. On failure
    /// the partial container is removed before the error is returned.
    pub fn encrypt_file(&self, input: &Path, output: &Path, name: &str) -> Result<u64> {
        let metadata = std::fs::symlink_metadata(input)
            .with_context(|| format!("inspect {}", input.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("{} is not a regular file", input.display());
        }
        let plaintext_size = metadata.len();
        let name = normalized_name(name);
        let expected = self.container_len(plaintext_size, &name)?;

        let mut source =
            BufReader::new(File::open(input).with_context(|| format!("open {}", input.display()))?);
        let mut output_file = create_private_file(output)
            .with_context(|| format!("create encrypted container {}", output.display()))?;

        let result = (|| -> Result<()> {
            let mut metadata_plain = Vec::with_capacity(12 + name.len());
            metadata_plain.extend_from_slice(&(name.len() as u32).to_le_bytes());
            metadata_plain.extend_from_slice(name.as_bytes());
            metadata_plain.extend_from_slice(&plaintext_size.to_le_bytes());

            let metadata_nonce = random_nonce()?;
            let header = header_prefix(
                self.salt,
                metadata_nonce,
                metadata_plain.len() + TAG_BYTES,
                self.chunk_size,
                self.m_cost,
                self.t_cost,
                self.p_cost,
            );
            let metadata_cipher = self
                .cipher()?
                .encrypt(
                    XNonce::from_slice(&metadata_nonce),
                    Payload {
                        msg: &metadata_plain,
                        aad: &header,
                    },
                )
                .map_err(|_| anyhow!("encrypt the file metadata"))?;

            let mut out = BufWriter::new(&mut output_file);
            out.write_all(&header).context("write encrypted header")?;
            out.write_all(&metadata_cipher)
                .context("write encrypted metadata")?;

            let mut buffer = vec![0u8; self.chunk_size as usize];
            let mut index = 0u64;
            let mut written = 0u64;
            loop {
                let mut filled = 0usize;
                while filled < buffer.len() {
                    let read = source
                        .read(&mut buffer[filled..])
                        .with_context(|| format!("read {}", input.display()))?;
                    if read == 0 {
                        break;
                    }
                    filled += read;
                }
                if filled == 0 {
                    break;
                }
                ensure!(
                    written.saturating_add(filled as u64) <= plaintext_size,
                    "the source file grew while it was being encrypted"
                );
                let length = filled as u32;
                let nonce = random_nonce()?;
                let cipher = self
                    .cipher()?
                    .encrypt(
                        XNonce::from_slice(&nonce),
                        Payload {
                            msg: &buffer[..filled],
                            aad: &chunk_aad(&header, index, length),
                        },
                    )
                    .map_err(|_| anyhow!("encrypt file content"))?;
                out.write_all(&length.to_le_bytes())
                    .context("write encrypted chunk length")?;
                out.write_all(&nonce)
                    .context("write encrypted chunk nonce")?;
                out.write_all(&cipher).context("write encrypted chunk")?;
                written += filled as u64;
                index += 1;
            }
            ensure!(
                written == plaintext_size,
                "the source file changed while it was being encrypted"
            );

            let nonce = random_nonce()?;
            let end = self
                .cipher()?
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &[],
                        aad: &end_aad(&header, index, written),
                    },
                )
                .map_err(|_| anyhow!("seal the encrypted container"))?;
            out.write_all(&END_MARKER.to_le_bytes())
                .context("write encrypted end marker")?;
            out.write_all(&nonce).context("write encrypted end nonce")?;
            out.write_all(&end).context("write encrypted end record")?;
            out.flush().context("flush encrypted container")?;
            out.get_ref()
                .sync_all()
                .context("sync encrypted container")?;
            Ok(())
        })();

        if let Err(error) = result {
            drop(output_file);
            let _ = std::fs::remove_file(output);
            return Err(error);
        }
        drop(output_file);

        let actual = std::fs::metadata(output)
            .with_context(|| format!("inspect encrypted container {}", output.display()))?
            .len();
        ensure!(
            actual == expected,
            "encrypted container size changed unexpectedly"
        );
        Ok(actual)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(&self.key[..])
            .map_err(|_| anyhow!("invalid encryption key length"))
    }
}

/// Decrypts containers using one configured passphrase. A small cache keeps a
/// multi-file batch from running Argon2id once per file.
pub struct Decryptor {
    passphrase: Zeroizing<String>,
    keys: Arc<Mutex<KeyCache>>,
}

/// A successfully decrypted plaintext file waiting to be scanned and moved.
#[derive(Debug)]
pub struct Decrypted {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
}

impl Decryptor {
    /// Decrypt `input` to a private temporary file inside `dir` without any
    /// free-space gate. Tests use this convenience form.
    #[cfg(test)]
    pub fn decrypt_to(&self, input: &Path, dir: &Path) -> Result<Decrypted> {
        self.decrypt_to_gated(input, dir, |_| Ok(()))
    }

    /// Decrypt `input` to a private temporary file inside `dir`. The caller
    /// must sanitize `name`, scan the content and move the file; the returned
    /// path is deleted automatically if decryption fails. The authenticated
    /// plaintext size is passed to `gate` before any plaintext is written, so
    /// receivers can confirm there is room for the decrypted copy instead of
    /// discovering a full disk halfway through.
    pub fn decrypt_to_gated(
        &self,
        input: &Path,
        dir: &Path,
        gate: impl FnOnce(u64) -> Result<()>,
    ) -> Result<Decrypted> {
        let file_len = std::fs::metadata(input)
            .with_context(|| format!("inspect encrypted container {}", input.display()))?
            .len();
        ensure!(
            file_len <= security::MAX_FILE_BYTES,
            "encrypted container exceeds the 4 GB OPP limit"
        );
        ensure!(
            file_len >= (HEADER_PREFIX + TAG_BYTES) as u64,
            "encrypted container is truncated"
        );

        let mut reader =
            BufReader::new(File::open(input).with_context(|| format!("open {}", input.display()))?);
        let mut header = [0u8; HEADER_PREFIX];
        reader
            .read_exact(&mut header)
            .context("read encrypted header")?;
        let parsed = parse_header(&header)?;

        let mut metadata_cipher = vec![0u8; parsed.metadata_len as usize];
        reader
            .read_exact(&mut metadata_cipher)
            .context("read encrypted metadata")?;
        let key = self.key_for(&parsed.salt, parsed.m_cost, parsed.t_cost, parsed.p_cost)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| anyhow!("invalid encryption key length"))?;
        let metadata_plain = cipher
            .decrypt(
                XNonce::from_slice(&parsed.metadata_nonce),
                Payload {
                    msg: &metadata_cipher,
                    aad: &header,
                },
            )
            .map_err(|_| anyhow!("wrong passphrase or corrupted encrypted file"))?;
        let (name, plaintext_size) = parse_metadata(&metadata_plain)?;
        gate(plaintext_size)?;

        std::fs::create_dir_all(dir)
            .with_context(|| format!("create decryption directory {}", dir.display()))?;
        security::create_private_dir(dir)
            .with_context(|| format!("secure decryption directory {}", dir.display()))?;
        let output_path = dir.join(format!(
            "{DECRYPT_TEMP_PREFIX}{}.tmp",
            Uuid::new_v4().simple()
        ));
        let output_file = create_private_file(&output_path)
            .with_context(|| format!("create decrypted file {}", output_path.display()))?;

        let result = (|| -> Result<()> {
            let mut out = BufWriter::new(output_file);
            let mut total = 0u64;
            let mut index = 0u64;
            let mut short_chunk = false;
            loop {
                let mut length_bytes = [0u8; 4];
                reader
                    .read_exact(&mut length_bytes)
                    .context("encrypted container ended before its final record")?;
                let length = u32::from_le_bytes(length_bytes);
                if length == END_MARKER {
                    let mut nonce = [0u8; NONCE_BYTES];
                    let mut tag = [0u8; TAG_BYTES];
                    reader
                        .read_exact(&mut nonce)
                        .context("read encrypted final nonce")?;
                    reader
                        .read_exact(&mut tag)
                        .context("read encrypted final tag")?;
                    ensure!(
                        total == plaintext_size,
                        "encrypted file size does not match its metadata"
                    );
                    let end = cipher
                        .decrypt(
                            XNonce::from_slice(&nonce),
                            Payload {
                                msg: &tag,
                                aad: &end_aad(&header, index, total),
                            },
                        )
                        .map_err(|_| anyhow!("encrypted container failed authentication"))?;
                    ensure!(end.is_empty(), "encrypted final record is not empty");
                    let mut trailing = [0u8; 1];
                    ensure!(
                        reader.read(&mut trailing).context("read trailing data")? == 0,
                        "encrypted container has trailing data"
                    );
                    break;
                }
                ensure!(
                    length <= parsed.chunk_size,
                    "encrypted chunk is larger than its header allows"
                );
                ensure!(
                    !short_chunk,
                    "encrypted container has data after a short chunk"
                );
                ensure!(
                    total.saturating_add(length as u64) <= plaintext_size,
                    "encrypted file is larger than its metadata says"
                );
                let mut nonce = [0u8; NONCE_BYTES];
                let mut ciphertext = vec![0u8; length as usize + TAG_BYTES];
                reader
                    .read_exact(&mut nonce)
                    .context("read encrypted chunk nonce")?;
                reader
                    .read_exact(&mut ciphertext)
                    .with_context(|| format!("read encrypted chunk {index}"))?;
                let plaintext = Zeroizing::new(
                    cipher
                        .decrypt(
                            XNonce::from_slice(&nonce),
                            Payload {
                                msg: &ciphertext,
                                aad: &chunk_aad(&header, index, length),
                            },
                        )
                        .map_err(|_| anyhow!("encrypted container failed authentication"))?,
                );
                ensure!(
                    plaintext.len() == length as usize,
                    "encrypted chunk length mismatch"
                );
                out.write_all(&plaintext)
                    .with_context(|| format!("write decrypted file {}", output_path.display()))?;
                total += length as u64;
                index += 1;
                short_chunk = length < parsed.chunk_size;
            }
            ensure!(
                total == plaintext_size,
                "encrypted file size does not match its metadata"
            );
            out.flush().context("flush decrypted file")?;
            out.get_ref().sync_all().context("sync decrypted file")?;
            Ok(())
        })();

        if let Err(error) = result {
            let _ = std::fs::remove_file(&output_path);
            return Err(error);
        }

        Ok(Decrypted {
            path: output_path,
            name,
            size: plaintext_size,
        })
    }

    fn key_for(
        &self,
        salt: &[u8; SALT_BYTES],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
        {
            let cache = self
                .keys
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(entry) = cache.entries.iter().find(|entry| {
                &entry.salt == salt
                    && entry.m_cost == m_cost
                    && entry.t_cost == t_cost
                    && entry.p_cost == p_cost
            }) {
                return Ok(entry.key.clone());
            }
        }
        let key = derive_key(self.passphrase.as_bytes(), salt, m_cost, t_cost, p_cost)?;
        let mut cache = self
            .keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.entries.len() >= KEY_CACHE_ENTRIES {
            cache.entries.remove(0);
        }
        cache.entries.push(CacheEntry {
            salt: *salt,
            m_cost,
            t_cost,
            p_cost,
            key: key.clone(),
        });
        Ok(key)
    }
}

#[derive(Default)]
struct KeyCache {
    entries: Vec<CacheEntry>,
}

struct CacheEntry {
    salt: [u8; SALT_BYTES],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    key: Zeroizing<[u8; KEY_BYTES]>,
}

struct Header {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    chunk_size: u32,
    salt: [u8; SALT_BYTES],
    metadata_nonce: [u8; NONCE_BYTES],
    metadata_len: u32,
}

fn header_prefix(
    salt: [u8; SALT_BYTES],
    metadata_nonce: [u8; NONCE_BYTES],
    metadata_len: usize,
    chunk_size: u32,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> [u8; HEADER_PREFIX] {
    let mut header = [0u8; HEADER_PREFIX];
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    header[9] = KDF_ARGON2ID;
    header[12..16].copy_from_slice(&m_cost.to_le_bytes());
    header[16..20].copy_from_slice(&t_cost.to_le_bytes());
    header[20] = p_cost as u8;
    header[24..28].copy_from_slice(&chunk_size.to_le_bytes());
    header[28..44].copy_from_slice(&salt);
    header[44..68].copy_from_slice(&metadata_nonce);
    header[68..72].copy_from_slice(&(metadata_len as u32).to_le_bytes());
    header
}

fn parse_header(header: &[u8; HEADER_PREFIX]) -> Result<Header> {
    ensure!(&header[..8] == MAGIC, "not a Kalo encrypted container");
    ensure!(
        header[8] == VERSION,
        "unsupported Kalo encryption container version {}",
        header[8]
    );
    ensure!(
        header[9] == KDF_ARGON2ID,
        "unsupported Kalo key-derivation algorithm"
    );
    ensure!(
        header[10..12] == [0, 0] && header[21..24] == [0, 0, 0],
        "unsupported Kalo encryption flags"
    );
    let m_cost = u32::from_le_bytes(header[12..16].try_into().expect("fixed slice"));
    let t_cost = u32::from_le_bytes(header[16..20].try_into().expect("fixed slice"));
    let p_cost = header[20] as u32;
    ensure!(
        (MIN_M_COST..=MAX_M_COST).contains(&m_cost),
        "encrypted container asks for an unsupported Argon2 memory cost"
    );
    ensure!(
        (MIN_T_COST..=MAX_T_COST).contains(&t_cost),
        "encrypted container asks for an unsupported Argon2 iteration count"
    );
    ensure!(
        (1..=MAX_P_COST).contains(&p_cost),
        "encrypted container asks for an unsupported Argon2 parallelism"
    );
    let chunk_size = u32::from_le_bytes(header[24..28].try_into().expect("fixed slice"));
    ensure!(
        (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size),
        "encrypted container asks for an unsupported chunk size"
    );
    let metadata_len = u32::from_le_bytes(header[68..72].try_into().expect("fixed slice"));
    ensure!(
        metadata_len as usize >= TAG_BYTES && metadata_len as usize <= MAX_METADATA_BYTES,
        "encrypted container metadata length is invalid"
    );
    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(&header[28..44]);
    let mut metadata_nonce = [0u8; NONCE_BYTES];
    metadata_nonce.copy_from_slice(&header[44..68]);
    Ok(Header {
        m_cost,
        t_cost,
        p_cost,
        chunk_size,
        salt,
        metadata_nonce,
        metadata_len,
    })
}

fn parse_metadata(metadata: &[u8]) -> Result<(String, u64)> {
    ensure!(metadata.len() >= 12, "encrypted metadata is truncated");
    let name_len = u32::from_le_bytes(metadata[..4].try_into().expect("fixed slice")) as usize;
    ensure!(name_len <= MAX_NAME_BYTES, "encrypted filename is too long");
    ensure!(
        metadata.len() == 4 + name_len + 8,
        "encrypted metadata has an invalid length"
    );
    let name = std::str::from_utf8(&metadata[4..4 + name_len])
        .context("encrypted filename is not valid UTF-8")?
        .to_string();
    let size = u64::from_le_bytes(
        metadata[4 + name_len..]
            .try_into()
            .expect("fixed size slice"),
    );
    ensure!(
        size <= security::MAX_FILE_BYTES,
        "encrypted file is too large"
    );
    Ok((name, size))
}

fn chunk_aad(header: &[u8; HEADER_PREFIX], index: u64, length: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + HEADER_PREFIX + 12);
    aad.push(b'c');
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&length.to_le_bytes());
    aad
}

fn end_aad(header: &[u8; HEADER_PREFIX], chunks: u64, total: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + HEADER_PREFIX + 16);
    aad.push(b'e');
    aad.extend_from_slice(header);
    aad.extend_from_slice(&chunks.to_le_bytes());
    aad.extend_from_slice(&total.to_le_bytes());
    aad
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let _kdf = KDF_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_BYTES))
        .map_err(|error| anyhow!("invalid Argon2 parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    argon2
        .hash_password_into(passphrase, salt, &mut key[..])
        .map_err(|error| anyhow!("derive encryption key: {error}"))?;
    Ok(key)
}

fn random_nonce() -> Result<[u8; NONCE_BYTES]> {
    let mut nonce = [0u8; NONCE_BYTES];
    random_bytes(&mut nonce).map_err(|error| anyhow!("generate encryption nonce: {error}"))?;
    Ok(nonce)
}

fn random_bytes(buffer: &mut [u8]) -> std::result::Result<(), getrandom::Error> {
    getrandom::getrandom(buffer)
}

fn normalized_name(name: &str) -> String {
    let mut name = if name.trim().is_empty() {
        "file".to_string()
    } else {
        name.to_string()
    };
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
        "file".to_string()
    } else {
        name
    }
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("create {}", path.display()))
}

/// Detect the container magic before deciding how to save an incoming file.
pub fn is_container(path: &Path) -> Result<bool> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut magic = [0u8; 8];
    let mut read = 0;
    while read < magic.len() {
        let count = file
            .read(&mut magic[read..])
            .with_context(|| format!("read {}", path.display()))?;
        if count == 0 {
            return Ok(false);
        }
        read += count;
    }
    Ok(&magic == MAGIC)
}

/// A random, non-identifying container name in a private temp directory.
/// Dropping the value removes the container, so success, cancellation and
/// every error path clean up after themselves.
#[derive(Debug)]
pub struct TempContainer {
    path: PathBuf,
}

impl TempContainer {
    pub fn new() -> Result<Self> {
        let dir = std::env::temp_dir().join("kalo").join("outgoing");
        security::create_private_dir(&dir)
            .with_context(|| format!("create outgoing staging directory {}", dir.display()))?;
        Ok(Self {
            path: dir.join(format!("kalo-{}.kalo", Uuid::new_v4().simple())),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempContainer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kalo-crypto-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn encryptor() -> Encryptor {
        Encryptor::with_params(PASSPHRASE, MIN_M_COST, 2, 1, MIN_CHUNK_SIZE).unwrap()
    }

    fn decryptor(passphrase: &str) -> Decryptor {
        Encryption::new(false, passphrase.to_string())
            .decryptor()
            .expect("passphrase is set")
    }

    fn roundtrip(plaintext: &[u8], name: &str) {
        let dir = temp_dir();
        let input = dir.join("input.bin");
        let container = dir.join("container.kalo");
        std::fs::write(&input, plaintext).unwrap();
        let encryptor = encryptor();
        let expected = encryptor
            .container_len(plaintext.len() as u64, name)
            .unwrap();
        let written = encryptor.encrypt_file(&input, &container, name).unwrap();
        assert_eq!(written, expected);
        let decrypted = decryptor(PASSPHRASE)
            .decrypt_to(&container, &dir.join("out"))
            .unwrap();
        assert_eq!(decrypted.name, name);
        assert_eq!(decrypted.size, plaintext.len() as u64);
        assert_eq!(std::fs::read(&decrypted.path).unwrap(), plaintext);
        std::fs::remove_file(&decrypted.path).unwrap();
        std::fs::remove_file(&container).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn round_trips_empty_single_and_multi_chunk_files() {
        roundtrip(b"", "empty.txt");
        roundtrip(b"one byte", "note.txt");
        roundtrip(&vec![0x5a; MIN_CHUNK_SIZE as usize * 3 + 17], "photo.jpg");
    }

    #[test]
    fn round_trips_unicode_filename() {
        roundtrip(b"hello", "documento è finito.pdf");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = temp_dir();
        let input = dir.join("input.bin");
        let container = dir.join("container.kalo");
        std::fs::write(&input, b"secret").unwrap();
        encryptor()
            .encrypt_file(&input, &container, "secret.txt")
            .unwrap();
        let error = decryptor("not the right passphrase")
            .decrypt_to(&container, &dir.join("out"))
            .unwrap_err();
        assert!(format!("{error:#}").contains("wrong passphrase"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tampering_truncation_and_trailing_data_are_rejected() {
        let dir = temp_dir();
        let input = dir.join("input.bin");
        std::fs::write(&input, vec![7u8; MIN_CHUNK_SIZE as usize + 5]).unwrap();
        let encryptor = encryptor();

        let container = dir.join("tampered.kalo");
        encryptor
            .encrypt_file(&input, &container, "file.bin")
            .unwrap();
        let mut bytes = std::fs::read(&container).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        std::fs::write(&container, &bytes).unwrap();
        assert!(
            decryptor(PASSPHRASE)
                .decrypt_to(&container, &dir.join("out"))
                .is_err()
        );

        let container = dir.join("truncated.kalo");
        encryptor
            .encrypt_file(&input, &container, "file.bin")
            .unwrap();
        let mut bytes = std::fs::read(&container).unwrap();
        bytes.truncate(bytes.len() - 10);
        std::fs::write(&container, &bytes).unwrap();
        assert!(
            decryptor(PASSPHRASE)
                .decrypt_to(&container, &dir.join("out"))
                .is_err()
        );

        let container = dir.join("trailing.kalo");
        encryptor
            .encrypt_file(&input, &container, "file.bin")
            .unwrap();
        let mut bytes = std::fs::read(&container).unwrap();
        bytes.push(0);
        std::fs::write(&container, &bytes).unwrap();
        assert!(
            decryptor(PASSPHRASE)
                .decrypt_to(&container, &dir.join("out"))
                .is_err()
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detects_container_magic_only_for_kalo_containers() {
        let dir = temp_dir();
        let plain = dir.join("plain.txt");
        std::fs::write(&plain, b"just a file").unwrap();
        assert!(!is_container(&plain).unwrap());

        let input = dir.join("input.bin");
        std::fs::write(&input, b"secret").unwrap();
        let container = dir.join("container.kalo");
        encryptor()
            .encrypt_file(&input, &container, "secret.txt")
            .unwrap();
        assert!(is_container(&container).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn weak_passphrases_are_refused() {
        let error = match Encryptor::new("short") {
            Ok(_) => panic!("a short passphrase must be refused"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("at least"));
    }

    #[test]
    fn gate_sees_the_authenticated_size_before_plaintext_is_written() {
        let dir = temp_dir();
        let input = dir.join("input.bin");
        let container = dir.join("container.kalo");
        std::fs::write(&input, b"secret").unwrap();
        encryptor()
            .encrypt_file(&input, &container, "secret.txt")
            .unwrap();
        let out = dir.join("out");
        let mut seen = None;
        let error = decryptor(PASSPHRASE)
            .decrypt_to_gated(&container, &out, |size| {
                seen = Some(size);
                Err(anyhow!("deliberately no room"))
            })
            .unwrap_err();
        assert_eq!(seen, Some(6));
        assert!(format!("{error:#}").contains("deliberately no room"));
        assert!(!out.exists(), "no plaintext directory should be created");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn temp_container_is_removed_on_drop() {
        let temp = TempContainer::new().unwrap();
        std::fs::write(temp.path(), b"ciphertext").unwrap();
        let path = temp.path().to_path_buf();
        drop(temp);
        assert!(!path.exists());
    }
}
