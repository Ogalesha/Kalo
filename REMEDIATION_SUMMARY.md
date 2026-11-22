# Kalo remediation summary

Baseline: `86082ae`
Date: 2026-11-21/22
State: all audit changes are in the working tree, uncommitted and unpushed.

This is the change log for the audit described in `SECURITY_AUDIT.md`. It
maps every confirmed finding to its fix, test, and validation evidence.

## 1. Counts

| Category | Count |
| --- | --- |
| Confirmed findings | 18 |
| Fixed in the working tree | 18 |
| Unresolved confirmed code findings | 0 |
| High / Medium / Low / Informational | 2 / 7 / 8 / 1 |
| New or strengthened regression tests | 15+ (full suite: 143) |
| Dependencies updated | 0 |
| Known `cargo audit` vulnerabilities | 0 |
| Remaining `cargo audit` warnings | 6 |

“Zero unresolved confirmed code findings” does not mean zero vulnerabilities.
It means every finding confirmed during this pass has a code change and the
listed verification. Residual risks and unvalidated platforms are in section
6.

## 2. Fixes by area

### Pairing and authorization

- **F-01 (High):** receivers now use `TrustStore::is_pinned` and delete
  plaintext or `KALOENC1` pushes from a pinned address before scanning or
  saving (`src/agent.rs`, `src/win/receiver.rs`). New tests prove both
  downgrade paths are rejected.
- **F-05 (Medium):** inbound pairing state is capped at 32, expired on every
  object, and a duplicate request cannot replace an in-flight handshake
  (`src/identity.rs`). New tests cover the cap and replacement attempt.
- **F-06 (Medium):** pairing replies are limited to four concurrent workers
  on Linux (tokio semaphore) and four threads on Windows (atomic guard).
- **F-09 (Low):** sending uses the pinned key, not “fully paired”, and refuses
  to fall back if the outgoing chain is missing (`src/platform.rs`).
- **F-02 (High):** `TrustStore::persist` holds the data lock through the
  atomic write, so an older snapshot cannot overwrite newer trust/ratchet
  state (`src/trust.rs`). A concurrent-write test was added.

### Receive pipeline and availability

- **F-03 (Medium):** `PeerDecrypted` now returns `from_step` and `next_step`;
  `commit_incoming` validates the current position and stores the
  authenticated step. All four Linux/Windows call sites were updated. New
  skip and replay tests were added.
- **F-07 (Medium):** Linux authorization waits reserve a concurrency slot
  through an RAII guard (`CapacityReservation`); the reservation is released
  under the pending lock when the transfer is registered.
- **F-08 (Medium):** Windows acquires an `IncomingSlot` before spawning the
  connection worker, so rejected connections no longer create threads.
- **F-17 (Low):** the maximum-skip boundary is consistent between decryption
  and commit; a container at exactly 4096 skipped steps can be committed.

### Filesystem and data handling

- **F-10 (Medium):** Windows configuration moved from RoamingAppData to
  LocalAppData; incoming staging moved from shared TEMP to the private config
  directory (`src/paths.rs`, `src/win/receiver.rs`).
- **F-11 (Low):** outgoing containers and pairing objects now live under the
  private config directory (`src/crypto.rs`, `src/identity.rs`).
- **F-12 (Low):** moves set the source to 0600 before hard-linking; the
  cross-device copy creates the destination 0600 immediately
  (`src/sanitize.rs`).
- **F-13 (Low):** settings temp files use `create_new(true)` and mode 0600 at
  creation on Unix (`src/settings.rs`).
- **F-14 (Low):** bidi overrides, zero-width characters, and line/paragraph
  separators are stripped from filenames and peer labels.
- **F-15 (Low):** Windows peer names run through the shared sanitizer.
- **F-16 (Low):** the 200-byte filename cap is re-applied after reserved-name
  neutralization.

### Malware hash feed

- **F-04 (Medium):** refresh keeps the bundled baseline and all previously
  cached hashes, adding fresh hashes only into the remaining room. The
  second-review over-cap case is bounded and never evicts known entries
  (`src/security.rs`).

### CI and supply chain

- **F-18 (Info):** all GitHub Actions are pinned to full commit SHAs; a
  `security` job installs `cargo-audit 0.23.0` and runs `cargo audit`; the
  release job depends on it (`.github/workflows/ci.yml`).

## 3. Modified files

| File | Purpose |
| --- | --- |
| `src/agent.rs` | downgrade rejection, authorization reservations, reply cap, ratchet call sites, tests |
| `src/crypto.rs` | `from_step`/`next_step`, private temp staging, skip/boundary tests |
| `src/identity.rs` | pending cap/timeout/duplicate handling, label sanitization, private pairing files, tests |
| `src/paths.rs` | Windows LocalAppData |
| `src/platform.rs` | pinned-key send selection |
| `src/sanitize.rs` | bidi/format stripping, length-cap fix, 0600 move/copy, tests |
| `src/security.rs` | non-evicting blocklist merge, tests |
| `src/settings.rs` | safe temp creation, owner-only test |
| `src/trust.rs` | `is_pinned`, serialized persistence, ratchet contract, tests |
| `src/win/receiver.rs` | downgrade rejection, LocalAppData staging, slot-before-thread, reply cap, name sanitization, ratchet call sites |
| `.github/workflows/ci.yml` | SHA pinning, dependency-audit job, release dependency |
| `SECURITY.md` | updated guarantees and limits |
| `README.md` | user-facing behavior for downgrade rejection, skip policy, Windows paths |
| `SECURITY_AUDIT.md` | this audit’s scope, findings, evidence, residual risks |
| `REMEDIATION_SUMMARY.md` | this change log |

No dependency versions were changed. `Cargo.toml` and `Cargo.lock` are
untouched by the audit.

## 4. New and strengthened tests

- `agent::tests::a_paired_sender_cannot_downgrade_to_plaintext`
- `agent::tests::a_paired_sender_cannot_downgrade_to_the_shared_passphrase`
- `agent::tests::waiting_authorizations_count_toward_the_incoming_limit`
- `crypto::tests::peer_containers_can_skip_failed_send_steps`
- `crypto::tests::peer_container_at_the_maximum_skip_reports_a_committable_next_step`
- `identity::tests::a_second_request_cannot_replace_an_in_flight_handshake`
- `identity::tests::pending_pairing_requests_are_bounded`
- `sanitize::tests::reserved_name_prefix_cannot_exceed_the_length_cap`
- `sanitize::tests::filename_strips_bidi_and_invisible_formatting`
- `sanitize::tests::move_file_tightens_permissions_before_linking`
- `sanitize::tests::copy_fallback_creates_owner_only_files`
- `security::tests::merge_fresh_keeps_history_and_respects_the_cap` (extended)
- `settings::tests::settings_files_are_owner_only`
- `trust::tests::pinned_identity_is_visible_without_ratchet_chains`
- `trust::tests::incoming_ratchet_accepts_forward_skips_and_rejects_rewinds`
- `trust::tests::concurrent_trust_writes_do_not_lose_entries`

Full suite result: **143 passed, 0 failed**.

## 5. Commands and results

Environment: Linux 7.0.0-43-generic, rustc/cargo 1.98.1, cargo-audit 0.23.0,
LLVM-MinGW Windows GNU cross toolchain.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test --all-targets` | 143 passed, 0 failed |
| `cargo build --release --locked` | success |
| `cargo clippy --target x86_64-pc-windows-gnu --all-targets -- -D warnings` | clean |
| `/tmp/opencode/cargo-tools/bin/cargo-audit audit` | 0 vulnerabilities, 6 warnings, exit 0 |
| `cargo +nightly fuzz run obex_parser -- -max_total_time=45 -rss_limit_mb=2048` | 2,797,503 runs, no crash |
| `cargo +nightly fuzz run filename -- -max_total_time=60 -rss_limit_mb=2048` | 5,363,232 runs, no crash |
| Python YAML validation of CI | valid; seven jobs |
| repository secret-pattern scan | no matches |

`cargo audit` warnings: `paste`, `ttf-parser`, `zbus_names`, `zvariant`,
`zvariant_derive` (unmaintained) and `lru 0.16.4` (unsound,
RUSTSEC-2026-0253). `lru` arrives through `iced_wgpu` -> `cryoglyph 0.1.0`;
the advisory recommends `>= 0.18.2`, but `cryoglyph` pins the 0.16 line and no
newer release exists. No supported upgrade was available without an unrelated
iced dependency change.

## 6. Environment limits and unresolved issues

- No physical Windows 10/11 machine was available. Windows-specific changes
  were cross-compiled and Clippy-checked, not run. Native Windows CI exists
  but has not run on these uncommitted changes.
- macOS could not be type-checked locally because the Darwin SDK/C headers
  required by `ring` are missing. CI builds macOS. macOS cannot receive OPP by
  design, so it still cannot complete the incremental pairing exchange.
- No real Bluetooth hardware, two-adapter test, or phone interoperability
  test was performed. OBEX parsing was fuzzed in isolation.
- Six dependency advisories remain (five unmaintained, one unsound with no
  compatible patch).
- The malware blocklist remains a hash list; unknown malware is not detected.
- Bluetooth address spoofing can still cause unauthenticated prompt/connection
  noise and denial of service; downgrade from a pinned address is blocked.
- Release artifacts are not signed and have no SLSA provenance. Actions are
  SHA-pinned, but `cargo-audit` is installed from crates.io at a pinned
  version.
- `cargo-deny` and Semgrep were not available and were not run.
- Fuzzing is time-boxed and is not exhaustive.

## 7. Next steps

1. Review and commit the audit changes after explicit authorization.
2. Let CI run the Linux, Windows, macOS, Arch, fuzz, and dependency-audit jobs
   on the committed tree.
3. Validate on physical Windows 10/11 hardware: pairing, Windows staging
   path, downgrade rejection, reply cap, and the LocalAppData migration.
4. Validate on a real Linux/BlueZ desktop with two adapters and at least one
   phone: prompt timeout, authorization reservations, pairing, skip recovery,
   and disconnect/cancel paths.
5. Revisit the `lru` advisory when iced/cryoglyph publish a compatible
   update; run `cargo audit` and the full validation again.
6. Consider artifact signing/provenance and a `cargo-deny` configuration if
   the project wants an additional CI gate.
7. Re-audit after any change to pairing, trust persistence, crypto
   containers, or the receive pipeline.

## SECURITY AUDIT RESULTS

**Assessment:** the audit confirmed 18 actionable findings and fixed all of
them in the working tree: 2 High, 7 Medium, 8 Low, and 1 Informational. The
two High findings were a paired-address downgrade path and a trust-store
persistence rollback race; both affected core pairing guarantees. The
remaining findings were availability/resource-exhaustion issues, local
filesystem exposure windows, defense-in-depth gaps, and CI hardening. The
final suite has 143 passing tests, Clippy and rustfmt are clean, the release
build and Windows cross-target Clippy succeed, `cargo audit` reports 0 known
vulnerabilities and 6 warnings, and both fuzz targets ran millions of
executions without a crash after the one sanitizer bug they found was fixed.
This is a materially stronger posture, not proof of zero vulnerabilities.

**Five most important findings:**

1. **F-01 (High):** a paired Bluetooth address accepted plaintext and
   shared-passphrase containers, allowing an impersonator or downgraded
   sender to bypass pairing authentication. Receivers now require
   `KALOENC2` from any pinned address and delete other pushes.
2. **F-02 (High):** concurrent trust-store writes could persist an older
   snapshot last, resurrecting a removed/blocked decision or a consumed
   ratchet step after restart. Persistence now serializes under the data
   lock.
3. **F-03 (Medium):** legitimate forward ratchet skips (caused by failed or
   cancelled sends) were rejected, permanently breaking paired transfers
   after one failure. `from_step`/`next_step` are now carried through
   decryption and committed consistently.
4. **F-04 (Medium):** a full or compromised malware feed could evict hashes
   the machine already knew. Refresh now keeps all cached/bundled detections
   and only adds fresh hashes into remaining space.
5. **F-05 (Medium):** unauthenticated pairing requests could allocate
   unbounded pending state or replace an in-flight handshake. Pending state
   is capped at 32, expired on every object, and duplicates are refused.

**Exact changes:** see section 2 and `SECURITY_AUDIT.md` for the per-finding
root cause, affected functions, and tests.

**Executed tools:** `cargo fmt`, `cargo clippy`, `cargo test`,
`cargo build --release --locked`, Windows GNU cross-target Clippy,
`cargo-audit 0.23.0`, `cargo-fuzz` (`obex_parser`, `filename`), Python YAML
validation, and repository secret-pattern scanning.

**Unresolved issues:** no confirmed code finding remains without a fix. Six
dependency advisories remain (five unmaintained, `lru` unsound with no
compatible patch), and the residual risks in section 6 remain: blocklist
coverage, Bluetooth address spoofing/DoS, local config compromise, unsigned
artifacts, and time-boxed fuzzing.

**Remaining manual validation:** physical Windows 10/11 runtime testing,
Linux/BlueZ testing with real adapters/phones, macOS CI confirmation, and
CI execution of the full workflow on the committed tree. None of these were
available in this environment.
