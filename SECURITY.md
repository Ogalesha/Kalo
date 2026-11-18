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
- A compromised or unavailable malware-hash feed endpoint.
- A local user or process reading Kalo's configuration and transfer data.

The assets to protect are the user's files, the integrity of the host, and the
privacy of transfer metadata.

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
- Received files are moved into the save folder only after the transfer
  completes and the scan passes. Partial data is recovered only when the
  protocol and filesystem state make that safe.

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
- Received files are private to the account that runs Kalo.

## What Kalo does not guarantee

- **No antivirus guarantee.** The blocklist catches known SHA-256 hashes only.
  A malicious file with an unknown hash is not detected. Do not treat Kalo as a
  substitute for an operating-system security update, an antivirus product, or
  cautious behavior.
- **No end-to-end encryption beyond Bluetooth.** OPP does not add an
  application-layer encryption envelope. Pairing can enable link encryption,
  but Kalo does not claim confidentiality against a compromised peer or a
  compromised Bluetooth stack.
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
- **No remote attestation or identity proof.** Trust is remembered by the
  Bluetooth address reported by the operating system. A compromised or spoofed
  local Bluetooth stack can undermine that identity.
- **No sandbox around the UI.** Kalo is a native desktop app with the
  permissions of the user who launches it.

## Operational guidance

- Pair devices through the operating system first, and keep the pairing list
  clean.
- Use **Trusted only** when you do not expect new senders, and **Block**
  addresses you do not recognize.
- Keep the save folder on a local filesystem with enough free space.
- Review received files before opening them, even when they pass the blocklist.
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
