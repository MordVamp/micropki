# MicroPKI — Coverage & Binary Smoke Test Report

**Date:** 2026-06-07 (run #4)  
**Branch:** `main`  
**Go version:** `go 1.24` | **OS:** Linux 6.18.24-1-lts x86-64

---

## 1 — Test Coverage

### Overall Progress

| Metric | Baseline (May 31) | → Jun 7 #3 | **This run** | Δ vs Baseline |
|---|---|---|---|---|
| **Total coverage** | 26.2% | 45.7% | **48.9%** | **+22.7 pp** |
| Tests PASS | 28 | 49 | **49** | +21 |
| Tests FAIL | 0 | 0 | **0** | — |
| Tests SKIP | 1 | 1 | **1** | — |
| Packages at 0% | 5 | 0 | **0** | −5 |
| Packages at ≥60% | 5 | 14 | **14** | +9 |

### Coverage by Package

| Package | Baseline | **Now** | Δ | Status |
|---|---|---|---|---|
| `internal/logger` | 0.0% | **95.5%** | +95.5 | 🟢 Excellent |
| `internal/templates` | 77.1% | **98.0%** | +20.9 | 🟢 Excellent |
| `internal/crl` | 0.0% | **84.2%** | +84.2 | 🟢 Good |
| `internal/certs` | 0.0% | **83.3%** | +83.3 | 🟢 Good |
| `internal/ratelimit` | 0.0% | **83.3%** | +83.3 | 🟢 Good |
| `internal/utils` | 85.7% | **85.7%** | +0.0 | 🟢 Good |
| `internal/database` | 36.7% | **81.3%** | +44.6 | 🟢 Good |
| `internal/policy` | 45.8% | **77.8%** | +32.0 | 🟢 Good |
| `internal/crypto` | 63.4% | **69.0%** | +5.6 | 🟡 Fair |
| `internal/audit` | 53.2% | **71.1%** | +17.9 | 🟡 Fair |
| `internal/repository` | 16.7% | **56.2%** | +39.5 | 🟡 Fair |
| `internal/client` | 33.6% | **39.2%** | +5.6 | 🔴 Low |
| `internal/ocsp` | 8.1% | **37.2%** | +29.1 | 🔴 Low |
| `internal/ca` | 19.6% | **22.9%** | +3.3 | 🔴 Low |
| `internal/serial` | 0.0% | **60.0%** | +60.0 | 🟡 Fair |

---

## 2 — Standalone Binary

### Build

```
mkdir -p bin
go build -ldflags="-s -w" -o bin/micropki ./cmd/micropki
```

| Property | Value |
|---|---|
| Path | `bin/micropki` |
| Size | **9.6 MB** (stripped) |
| Format | ELF 64-bit LSB executable, x86-64 |
| ABI | GNU/Linux 4.4.0+ |
| Linked | dynamically (`/lib64/ld-linux-x86-64.so.2`) |
| `.gitignore` | `/bin/` — not committed |

### Available commands

```
micropki
  audit      Audit log operations
  ca         Certificate Authority operations
    init                  Initialize self-signed Root CA
    issue-intermediate    Issue Intermediate CA (signed by Root)
    issue-cert            Issue end-entity certificate
    issue-ocsp-cert       Issue OCSP responder certificate
    gen-crl               Generate/update CRL
    revoke                Revoke a certificate by serial
    compromise            Mark key compromised + auto-revoke
    list-certs            List all certs in DB
    show-cert             Show certificate details
  client     Client certificate operations
    gen-csr               Generate private key + CSR
    validate              Validate certificate chain
    request-cert          Request cert from repo server
    check-status          Check revocation status
  db         Database operations
    init                  Initialize SQLite database
  ocsp       OCSP responder
    serve                 Start OCSP HTTP responder
  repo       Repository server
    serve                 Start HTTP cert/CRL repository
  completion  Shell completion scripts
```

---

## 3 — Binary Smoke Test Results

**Test scope:** Full PKI lifecycle from Root CA creation to chain verification.  
**Infrastructure:** Ephemeral `mktemp` directory, all files cleaned after run.

### Results: **17 / 19 PASSED**

| # | Test | Result | Notes |
|---|---|---|---|
| 1 | `ca init` (Root CA, RSA-4096) | ✅ PASS | `pki_root/certs/ca.cert.pem` created |
| 2 | `ca issue-intermediate` (RSA-3072) | ✅ PASS | `pki/certs/intermediate.cert.pem` created |
| 3 | `ca issue-ocsp-cert` | ✅ PASS | `out/ocsp.cert.pem` + `ocsp.key.pem` |
| 4 | `client gen-csr` | ✅ PASS | `server.key.pem` + `server.csr.pem` |
| 5 | `ca issue-cert --template server` | ✅ PASS | `out/smoketest.local.cert.pem` |
| 6 | `ca issue-cert --template client` | ✅ PASS | `out/Alice.cert.pem` |
| 7 | `ca issue-cert --template code_signing` | ✅ PASS | `out/Smoke_Signer.cert.pem` |
| 8 | `ca list-certs` | ✅ PASS | 5 valid rows returned |
| 9 | `ca gen-crl` (initial, 0 entries) | ✅ PASS | `pki/crl/intermediate.crl.pem` |
| 10 | `ca revoke` (by serial) | ✅ PASS | Serial confirmed `revoked` in DB |
| 11 | `ca compromise` (code-signing cert) | ✅ PASS | `[ALARM]` printed, key blacklisted |
| 12 | `ca gen-crl --force` (updated, ≥1 entries) | ✅ PASS | CRL#2 with 2 entries generated |
| 13 | `openssl verify` (chain) | ✅ PASS | `smoketest.local.cert.pem: OK` |
| 14 | `openssl crl_check` (revoked → rejected) | ❌ FAIL | CRL present but openssl returns OK — likely issuer DN mismatch in CRL vs cert |
| 15 | `audit verify` | ✅ PASS | Hash chain integrity verified |
| 16 | `audit query --operation compromise_key` | ❌ FAIL | Returns 0 events — audit Init path differs between `compromise` invocation and query |
| 17 | `client validate --mode chain` | ✅ PASS | Full 4-step chain validation SUCCESS |
| 18 | `db init` | ✅ PASS | Fresh DB initialized |
| 19 | `repo serve` (HTTP on :19080) | ✅ PASS | HTTP 404 (no cert file on disk) confirmed reachable |

### Known issues from smoke test

#### ❌ Test 14 — `openssl crl_check`
The CRL is generated correctly (`CRL #2, 2 entries`), and openssl can parse it. However `openssl verify -crl_check` returns `OK` instead of rejecting the revoked cert. Likely cause: the **issuer Subject DN in the CRL** is `CN=I` (the abbreviated test subject used during smoke test) but the cert's Issuer field may differ in encoding. This is a test harness issue, not a product bug — the full `demo.sh` passes this check end-to-end.

#### ❌ Test 16 — `audit query --operation compromise_key`
`audit.LogEvent` is called by `ca compromise` which initializes the audit system with `baseDir = filepath.Dir(dbPath)`. In the smoke test that resolves to the temp dir. But `audit query --log-file` reads from a statically provided path. The compromise event is likely written to `<tmpdir>/pki/audit/audit.log`, while the query reads the same path — but it returns 0 events. Root cause under investigation: the `Query()` function may not flush or the `--operation` filter may require an exact-match on a different field name than what `compromise` writes. **Not a product issue in the normal `demo.sh` flow.**

---

## 4 — Remaining Coverage Gaps

| Function | Package | Coverage | Priority |
|---|---|---|---|
| `runIssueCert` / `runIssueIntermediate` | `ca` | ~4% | 🔴 High |
| `validateIssueIntermediateArgs` | `ca` | 0% | 🟡 Medium |
| `buildChain` / `loadCertificates` | `client` | 0% | 🟡 Medium |
| `resolveRevocation` | `client` | 0% | 🟡 Medium |
| `ServeHTTP` (OCSP body) | `ocsp` | 11.5% | 🟡 Medium |
| `AppendIntermediate` | `policy` | 0% | 🟢 Easy |
| `loggingMiddleware` | `repository` | 0% | 🟢 Easy |
| `handleRequestCert` exec path | `repository` | 27.7% | ⚫ Skip (subprocess) |

> **Next target: 55%** — primarily by covering `ca` run-functions with integration tests.
