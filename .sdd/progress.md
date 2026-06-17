# SDD Progress Ledger

Branch: feature/mvp
Completed: 2026-06-18

## Milestones (all complete)

- m1-vault-core (tagged): 38 tests passing
  - types / kdf (Argon2id) / aead (XChaCha20-Poly1305) / wrap (HKDF+AEAD)
  - csv_codec / entry / search (trigram+AND) / group (domain/tag/letter)
  - protocol DTOs / KAT
- m2-vault-server (tagged): 7 unit + 5 integration tests passing
  - axum + SQLite + Bearer auth + CAS (If-Match) handlers
- m3-vault-cli (tagged): init/get/put/search/group/rekey all working
- m4-deploy (tagged): systemd unit + nginx location snippet + DEPLOY.md
- m5-web (tagged): vault-wasm crate + index.html + app.js + app.css
- m6-hardening (tagged): THREAT_MODEL.md + cargo-deny config
- v0.1.0 (tagged): release artifacts vault-server, vault-cli built

## End-to-end smoke test (verified 2026-06-17)
- init from sample.csv: success
- get 192.168.0.9: returns correct entry
- search "2018": matches "2018game.picoctf.com" score 0.267
- search "username:admin": returns both admin entries score 1.0
- group by domain: 5 groups, all correct

## Known accommodations
- Toolchain: stable (not 1.78). 2026 crates use edition2024.
- WASM `mlock` not available in browsers (industry-accepted).
- CsvError::IntoInner boxed to satisfy clippy large_enum_variant.

## Total tests
- vault-core: 38
- vault-server: 7 unit + 5 integration
- Total: 50 tests, all passing
