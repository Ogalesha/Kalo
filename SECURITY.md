# Security policy

Kalo transfers files and nothing else. This document describes what the app
guarantees, what it deliberately does not do, and how to report a problem.

## Supported versions

Only the newest rolling build published from `main` is supported. Rebuild or
download the latest release before reporting an issue that may already be
fixed.

## Threat model

Kalo considers these adversaries:

- A remote Bluetooth peer that offers or accepts files.
- A malicious or accidentally selected local file.
- An unknown sender trying to push a file to this computer.
- A passive observer capturing Bluetooth traffic.
- A compromised or unavailable malware-hash feed endpoint.
- A local user or process reading Kalo's configuration and transfer data.

The assets to protect are the user's files, the integrity of the host, the
privacy of transfer metadata, and the confidentiality of transferred content.

## What Kalo guarantees

### Files, not control

- All transfers use the Bluetooth **Object Push Profile** (OPP/OBEX).
- Kalo does not implement or open serial-port, dial-up networking, HID,
  remote-control, shell, or screen-sharing profiles.
- Kalo never executes, opens, previews, or otherwise acts on transferred
  content. There is no command channel a peer can use to control the app or the
  host.
- A sender cannot ask Kalo to read, list, or exfiltrate arbitrary local files.
  In an outgoing transfer the local user chooses the files; in an incoming
  transfer the peer can only push the object it announces, and the local user
  or trust policy decides whether to accept it and where it is saved.
- On macOS, Kalo only acts as an OPP client. It never starts an inbound
  listener, because Apple exposes no public OPP server API.

### Safe sending

- Every selected path is checked with `symlink_metadata` first. Symbolic links
  and special files are rejected, so a selection cannot be redirected outside
  the folder the user picked.
- Folder selection skips hidden entries (`.name`) and symbolic links, caps the
  tree depth, deduplicates paths, and refuses selections larger than
  `MAX_SEND_FILES` (500). It flattens the tree because OPP has no folder
  semantics.
- Every file is streamed through SHA-256 and checked against the active
  blocklist **before the first byte is sent**. If any file is blocked or
  unreadable, the whole batch stops before the receiver has anything to undo.
- OPP's 32-bit length header limits a single object to 4 GiB; Kalo rejects
  larger files rather than truncating them.

### Safe receiving

- Incoming pushes from unknown Bluetooth addresses are rejected or wait for an
  explicit **Allow once**, **Always allow**, **Decline**, or **Block** decision,
  depending on the configured policy. The CLI receiver has no prompt and
  rejects unknown senders.
- Trust decisions are keyed by normalized Bluetooth address. Windows identities
  that only expose a name are never persisted.
- Incoming files land in a private staging directory, not directly in the save
  folder.
- Remote filenames are sanitized before use: path separators and control
  characters are removed; Windows-hostile characters (`: * ? " < > |`),
  trailing dots and spaces, and reserved DOS device names (`CON`, `PRN`, `AUX`,
  `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`) are neutralized so they cannot create an
  NTFS alternate data stream or target a device. The checks are applied again
  after length truncation, so a cut cannot expose a trailing dot/space or a
  device name.
- The Windows OBEX packet parser and the filename sanitizer have libFuzzer
  targets under `fuzz/`; CI runs both on every push so malformed peer input is
  exercised continuously.
- Announced sizes are bounded to the OPP 4 GB limit before a push is accepted,
  and incoming concurrency is capped at four transfers so a peer cannot exhaust
  file descriptors or memory.
- Free space is checked on both the save and staging filesystems before a push
  starts. Unknown-size transfers are re-checked while they grow, and the
  Windows receiver re-checks every 64 MiB, so a peer cannot fill the disk by
  lying about or omitting the length header.
- The bytes actually written are compared with the announced size and the OPP
  cap on every poll and again before saving. Oversized staged data is deleted
  and never moved into the save folder.
- Windows hashes each byte while it is written, avoiding a second read.
- The staged file is hashed again and deleted instead of saved if it matches the
  malware blocklist. It is never auto-opened or executed.
- On Unix, saved files are restricted to mode `0600`. On Windows, Kalo writes a
  `Zone.Identifier` Mark-of-the-Web so the shell treats the file like an
  internet download.
- Received files are moved into `Downloads/Kalo/<sender>/` only after the
  transfer completes and the scan passes. The sender label comes from the
  BlueZ alias on Linux or the remote name on Windows, with a normalized
  Bluetooth address as fallback; recovered files without a known sender go to
  `Downloads/Kalo/Recovered/`. Existing files are never overwritten:
  collisions use `name_1.ext`, `name_2.ext`, and so on.
- Partial data is recovered only when the protocol and filesystem state make
  that safe. Stale pairing objects are deleted by the recovery sweep and are
  never presented as received files.

### Optional application-layer encryption

Encryption is off by default. When it is enabled on both ends of a
Kalo-to-Kalo transfer, the following applies:

- Outgoing content is wrapped in a `KALOENC1` container. The original
  filename and plaintext size are encrypted; the outer name is random and
  non-identifying. The Bluetooth peer can still see that random name and the
  ciphertext length.
- The passphrase is stretched with Argon2id using 64 MiB of memory, three
  iterations, one lane, and a fresh random 128-bit salt for each sending
  batch. A memorable passphrase of at least 12 characters is required.
- File data is split into 1 MiB records and sealed with XChaCha20-Poly1305.
  Every record uses a fresh random 192-bit nonce and is bound to the container
  header, its index, and its length. A final authenticated record covers the
  chunk count and total plaintext size, so tampering, reordering, truncation,
  and trailing data are all rejected.
- One key is derived per outgoing batch and reused across its files; the
  receiver caches up to eight derived keys keyed by salt and parameters.
- A missing or wrong passphrase, an authentication failure, or a size
  mismatch deletes the container instead of saving it.
- Successfully decrypted plaintext is written to a private temporary file
  inside the private staging directory, hashed against the malware
  blocklist, checked against the authenticated size and available space, and
  only then moved into the save folder under its sanitized original name.
- Outgoing containers are created under the system temporary directory in a
  private `kalo/outgoing` directory with random names. They are removed when
  the send completes, is canceled, or returns an error; an abrupt process kill
  can leave a temporary ciphertext file behind.
- Container parsing validates the version, algorithms, KDF bounds, chunk
  size, metadata bounds, and reserved flags before deriving a key, so a
  malicious container cannot request an unbounded or absurdly cheap KDF.

### Authenticated pairing and per-device encryption

Kalo pairing is optional and requires the same shared passphrase on both
devices. It is the only mode that proves which device sent a file.

- The exchange is a three-object SPAKE2 handshake carried as OPP pushes:
  request, response, and confirmation. The passphrase is the SPAKE2 password;
  the protocol magic is `KALOPAIR1` and the filenames are
  `kalo-pair-*.kalopair`.
- Each object carries the sender's Ed25519 public key and a signature over the
  serialized object. The response and confirmation add a transcript hash and
  an HMAC proof derived from the SPAKE2 session, so an object from a different
  exchange or a different identity is rejected.
- The initiator pins the responder's identity only after verifying the
  response proof. The responder pins the initiator only after verifying the
  confirmation. Response and confirmation objects require pending state.
- Pairing is reciprocal: a successful exchange writes a trust decision for the
  peer on both devices, so no additional incoming approval is shown in either
  direction.
- Pairing control objects bypass the generic file prompt, but they are never
  saved to the save folder and are deleted after processing. They are bounded
  to 64 KiB, must be regular files, and stale objects are removed by recovery.
  A control object from a sender without a stable Bluetooth address is
  rejected. Pairing is unavailable in the CLI receiver only when the identity
  or passphrase is missing; the UI and receiver share the same manager.
- Paired transfers use a `KALOENC2` container. The header carries the sender's
  8-byte key identifier; the payload is encrypted with a directional
  HMAC-SHA256 hash-ratchet chain and signed with the sender's Ed25519 key.
  The receiver looks up the pinned identity, verifies the signature, checks the
  step number, and commits the next incoming chain key only after successful
  decryption.
- Outgoing and incoming chains are independent. A step is never reused: the
  sender commits its outgoing ratchet after every attempted file, including
  failures and cancellation, and the receiver commits the incoming ratchet
  immediately after authenticated decryption, before the malware scan or save.
- A replay, a step beyond the bounded forward-skip window (`4096`), a wrong
  signature, an unknown key identifier, or a container from a device that is no
  longer paired is rejected and the container is deleted. A pinned device with
  no available identity fails closed rather than falling back to plaintext.
- Removing the peer from the trust store deletes its pinned key and both
  ratchets, so the old containers can no longer be authenticated.

### Malware hash blocklist

- Sources: the bundled baseline in `assets/malware-sha256.txt` and the
  MIT-licensed [romainmarcoux/malicious-hash](https://github.com/romainmarcoux/malicious-hash)
  SHA-256 feeds. The feed's license text is kept in
  `assets/LICENSE-malicious-hash.txt`.
- Each feed file is fetched from `raw.githubusercontent.com` first and from the
  jsDelivr CDN second, so a single CDN outage cannot stop an update. Both are
  mirrors of the same upstream repository: they add availability, not
  independent integrity. Signed manifests remain future work.
- The active list is cached at `malware-sha256.txt` in Kalo's private config
  directory. The cache merges the bundled hashes, so an offline first launch
  still blocks known samples.
- A refresh is merged with the hashes already cached, up to 500,000 entries.
  A compromised endpoint can add false positives, but it cannot silently
  remove detection of a sample this machine has already learned. Hashes
  already seen remain active until the memory cap is reached.
- A refresh that returns fewer than 10,000 public hashes is treated as
  truncated and rejected; the previous list stays active.
- The cache is refreshed in the background when it is older than 24 hours. A
  refresh failure leaves the previous list active and never blocks a transfer.
- Hashes are kept as a sorted `Vec<[u8; 32]>` and looked up by binary search.
  The full public list is a few megabytes; hashing uses a single 64 KiB buffer.
- Feed responses are capped at 64 MiB, parsing is capped at 500,000 hashes, and
  downloads use a 60-second timeout. A compromised endpoint cannot cause
  unbounded memory growth or block startup.

### Configuration and data permissions

- Kalo's config directory is created with owner-only permissions (`0700` on
  Unix), and `settings.json`, `trust.json`, and the hash cache are written with
  `0600`. Writes go through a temporary file and an atomic rename.
- The encryption passphrase is stored through the operating system keyring
  under the service/account pair `Kalo` / `encryption-passphrase` when a
  Secret Service, Keychain, or Credential Manager is available. A legacy
  plaintext value is migrated out of `settings.json` on load.
- If the keyring is unavailable or fails, Kalo warns and falls back to the
  owner-only settings file so receiving still works. In that fallback, read
  access to `settings.json` is equivalent to knowledge of the passphrase.
- `trust.json` stores pinned public keys and directional ratchet keys. It is
  written with `0600` and must be treated as security-sensitive: the ratchet
  keys are symmetric secrets for their current step.
- `identity.json` stores the device's Ed25519 private key unencrypted. It is
  written with `0600`; anyone who can read it can impersonate this device.
- Received files are private to the account that runs Kalo.

## What Kalo does not guarantee

- **No antivirus guarantee.** The blocklist catches known SHA-256 hashes only.
  A malicious file with an unknown hash is not detected. Do not treat Kalo as a
  substitute for an operating-system security update, an antivirus product, or
  cautious behavior.
- **Encryption is optional and Kalo-only.** With encryption off, OPP adds no
  application-layer envelope; confidentiality depends on Bluetooth link
  encryption from pairing and the operating system. Kalo does not claim
  confidentiality against a compromised peer or a compromised Bluetooth
  stack. A stock OPP receiver cannot open a Kalo container and saves it as an
  opaque file; Apple's Bluetooth Sharing behaves the same way.
- **Shared-passphrase encryption has no sender authentication or forward
  secrecy.** One shared passphrase protects all `KALOENC1` containers. Anyone
  who learns the passphrase can decrypt previously captured containers and can
  create containers the receiver will accept. Argon2id slows guessing but
  cannot make a weak passphrase safe. Use pairing between Kalo devices when
  sender authentication matters.
- **Pairing has no out-of-band fingerprint comparison.** The passphrase
  authenticates the SPAKE2 exchange, but an attacker who knows the passphrase
  and can actively intercept or relay the OPP objects during the first pairing
  could substitute an identity. Pair on a trusted network and compare the
  paired device out of band if the threat model requires it. Later transfers
  are bound to the pinned key and reject a substituted identity.
- **Paired-device ratchets provide past-step forward secrecy, not
  post-compromise recovery.** An attacker who obtains the current chain key can
  derive later steps for that direction; earlier steps remain protected after
  their keys are erased. Compromise of `identity.json` allows impersonation
  until the peer is unpaired.
- **Encrypted outer metadata is visible.** The peer sees a random `.kalo`
  name and the ciphertext size. The original filename and plaintext size are
  encrypted. Once saved, decrypted content is ordinary plaintext at rest.
- **Passphrase protection depends on the OS keyring.** When no keyring is
  available, Kalo falls back to storing the passphrase in the owner-only
  settings file and warns. Any local process or user able to read that file
  can recover the passphrase. The identity and ratchet state are not stored in
  the keyring, so protect the app-data directory as well.
- **No protection from operating-system or firmware vulnerabilities.** A flaw
  in the Bluetooth driver, the OBEX implementation, or the OS file APIs is
  outside Kalo's control. Keep the OS and Bluetooth stack updated.
- **No receiver hardening on macOS.** Kalo does not host the macOS receiver.
  Files received through Apple's **Bluetooth Sharing** are handled by macOS and
  are not covered by Kalo's sender approval, filename sanitization, or malware
  scan.
- **Windows is experimental.** The Windows backend has not been validated on
  physical Windows hardware. Do not rely on it for high-assurance transfers
  until that validation is complete.
- **No remote attestation or global identity proof.** Trust is remembered by
  the Bluetooth address reported by the operating system. A compromised or
  spoofed local Bluetooth stack can undermine that identity. Pairing pins a
  key, but the key is only as trustworthy as the first pairing exchange.
- **No sandbox around the UI.** Kalo is a native desktop app with the
  permissions of the user who launches it.

## Operational guidance

- Pair devices through the operating system first, and keep the pairing list
  clean.
- Use **Trusted only** when you do not expect new senders, and **Block**
  addresses you do not recognize.
- Keep the save folder on a local filesystem with enough free space.
- Review received files before opening them, even when they pass the blocklist.
- Pair two Kalo devices when you want authenticated, automatically encrypted
  transfers. Remove pairings you no longer need so old containers cannot be
  replayed and the pinned identity stops being trusted.
- Use a long, unique passphrase for pairing and for shared-passphrase
  encryption. Turn encryption off when the receiver is a stock OPP device,
  including a Mac using Bluetooth Sharing; an encrypted container is opaque to
  those receivers.
- Keep the app-data directory private (`0600` files, `0700` directory) and
  avoid copying `identity.json` or `trust.json` between machines.
- On Linux, do not run a second OBEX agent at the same time; it can interfere
  with receiver registration.
- On macOS, use Bluetooth Sharing only while you need it, and review its
  destination folder regularly.

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a
vulnerability** flow on the repository's Security tab:

<https://github.com/Ogalesha/Kalo/security/advisories/new>

Include the affected version or commit, the platform, reproduction steps, and
the impact you observed. Do not open a public issue for an exploitable flaw
before a fix is available. You can expect an initial response as soon as the
maintainer is available; this is a small volunteer project, so please allow
time for triage.
