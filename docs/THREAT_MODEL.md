# Threat Model

## In scope

- **Passive observer of HTTPS traffic** — TLS protects the wire; the server
  never sees plaintext (E2E).
- **Active MITM** — blocked by TLS 1.3 + HSTS + the user's existing
  Nginx-managed cert.
- **Compromised VPS** — attacker sees only wrapped_cek + ciphertext. Cannot
  decrypt without the master password.
- **Compromised client machine** — memory dump may reveal plaintext after
  unlock. Not mitigated (industry-accepted).
- **Weak master password** — Argon2id (64 MiB, t=3) + recommendation to use
  ≥ 6 diceware words.
- **Replay / rollback** — monotonic `version` + `If-Match` CAS on PUT/POST.
- **Server tampering** — AEAD tag verification fails on decrypt; tampering
  is detected.
- **Backup leak** — SQLite is already ciphertext; only the master password
  unlocks it.
- **API token leak** — does not equal data leak (E2E still protects).

## Out of scope

- Client machine full compromise (rubber hose, evil maid).
- Master password loss (by design — no recovery).
- Side-channel on Argon2 (we use a vetted library).
- DoS at the application layer (Nginx `limit_req` + 8 MB body cap).
- Post-quantum cryptanalysis (symmetric-256 + Argon2id are
  quantum-resistant; see design §2.4).

## Residual risk

- **Master password brute force**: Argon2id cost ~200 ms per guess.
  6-word diceware ≈ 2^77 candidate space → ~5M years at 1000 guesses/s.
- **Browser swap risk**: WASM cannot `mlock`; key material may land in
  swap. Mitigated by `lock()` clearing memory and tab-close clearing too.
- **Operator error**: weakest link. Mitigated by strong defaults, single
  source of crypto (`vault-core`).

## Design boundaries

- `vault-core` is `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
- All key material is wrapped in `Zeroizing` / `ZeroizeOnDrop` newtypes.
- All key comparisons go through `subtle::ConstantTimeEq`.
- The server binds to `127.0.0.1:8080` only; it cannot be reached from
  outside the host.
- The server never logs IPs (only `X-Forwarded-For` summaries), master
  password, raw ciphertext, or decrypted plaintext.
