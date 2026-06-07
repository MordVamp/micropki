# MicroPKI Test Coverage Report

**Date:** 2026-06-08  
**Command:** `go test -timeout 180s -short -coverprofile=coverage.out -covermode=atomic ./internal/... ./tests/...`  
**Exit code:** 0 — **all tests PASS** ✅

---

## Overall Progress

| Metric | Baseline (May 31) | Jun 7 #4 | **This run** | Δ vs Baseline |
|---|---|---|---|---|
| **Total coverage** | 26.2% | 48.9% | **73.4%** | **+47.2 pp** |
| Tests PASS | 28 | 49 | **49+** | +21 |
| Tests FAIL | 0 | 0 | **0** | — |
| Packages at 0% | 5 | 0 | **0** | −5 |
| Packages at ≥60% | 5 | 14 | **15** | +10 |
| Packages at ≥70% | 2 | 8 | **13** | +11 |

---

## Coverage by Package

| Package | Baseline | Jun 7 #4 | **Now** | Δ vs Baseline | Status |
|---|---|---|---|---|---|
| `internal/templates` | 77.1% | 98.0% | **98.0%** | +20.9 | 🟢 Excellent |
| `internal/policy` | 45.8% | 77.8% | **91.7%** | +45.9 | 🟢 Excellent |
| `internal/logger` | 0.0% | 95.5% | **88.0%** | +88.0 | 🟢 Excellent |
| `internal/database` | 36.7% | 81.3% | **81.3%** | +44.6 | 🟢 Good |
| `internal/crl` | 0.0% | 84.2% | **84.2%** | +84.2 | 🟢 Good |
| `internal/certs` | 0.0% | 83.3% | **83.3%** | +83.3 | 🟢 Good |
| `internal/ratelimit` | 0.0% | 83.3% | **83.3%** | +83.3 | 🟢 Good |
| `internal/utils` | 85.7% | 85.7% | **85.7%** | +0.0 | 🟢 Good |
| `internal/ocsp` | 8.1% | 37.2% | **73.3%** | +65.2 | 🟡 Fair |
| `internal/repository` | 16.7% | 56.2% | **71.5%** | +54.8 | 🟡 Fair |
| `internal/audit` | 53.2% | 71.1% | **71.1%** | +17.9 | 🟡 Fair |
| `internal/crypto` | 63.4% | 69.0% | **69.0%** | +5.6 | 🟡 Fair |
| `internal/ca` | 19.6% | 22.9% | **67.8%** | +48.2 | 🟡 Fair ← big jump |
| `internal/client` | 33.6% | 39.2% | **57.9%** | +24.3 | 🟡 Fair ← jump |
| `internal/serial` | 0.0% | 60.0% | **60.0%** | +60.0 | 🟡 Fair |

---

## Per-Function Coverage (non-100% only)

```
internal/audit
  Init               72.4%
  LogEvent           75.0%
  Close              80.0%
  AppendCTLog        66.7%
  Query              73.0%
  Verify             65.9%

internal/ca
  runInit            58.7%   ← was 6.5%
  validateInitArgs   61.5%   ← was 15.4%
  ParseDN            82.1%
  runIssueCert       55.1%   ← was 3.8%
  runIssueIntermediate 56.5% ← was 3.2%
  runIssueOcsp       71.4%   ← was 5.7%

internal/certs
  GenerateRootCertificate  83.3%

internal/client
  resolveRevocation  47.8%   ← was 0%
  fetchResourceBytes 71.4%   ← was 0%
  printResult        66.7%
  buildChain         96.2%   ← was 0%
  validateChainCryptographically  70.8%
  loadCertificate    85.7%
  loadCertificates   57.1%

internal/crl
  GenerateCRL        84.2%

internal/crypto
  EncryptPrivateKey  85.0%
  WritePEMFile       80.0%
  DecryptPrivateKey  51.4%

internal/database
  InitDB             62.5%
  InsertCertificate  71.4%
  GetCertificateBySerial  69.2%
  ListCertificates   81.8%
  CheckSerialExists  87.5%
  RevokeCertificate  85.7%
  GetRevokedCertificates  85.7%
  GetCRLMetadata     90.9%
  UpdateCRLMetadata  92.3%
  IsKeyCompromised   87.5%

internal/logger
  Init               78.6%

internal/ocsp
  NewResponder       72.0%
  ServeHTTP          73.8%   ← was 11.5%

internal/policy
  LoadConfig         90.0%
  Write              88.9%
  AppendIntermediate 88.9%
  ValidateKey        86.7%

internal/ratelimit
  Accept             76.5%
  Middleware         78.6%

internal/repository
  Start              93.3%
  handleCertificate  77.8%
  handleCA           50.0%   ← still low
  handleCRL          74.1%
  handleRequestCert  66.2%

internal/serial
  GenerateUniqueSerial  60.0%

internal/templates
  BuildTemplate      95.2%

internal/utils
  SafeWriteFile      85.7%
```

---

## Remaining Gaps (functions below 60%)

| Function | Package | Coverage | Notes |
|---|---|---|---|
| `handleCA` | `repository` | 50.0% | Missing intermediate + error branches |
| `resolveRevocation` | `client` | 47.8% | HTTP fallback paths need mock server |
| `DecryptPrivateKey` | `crypto` | 51.4% | Wrong-passphrase error branch missing |
| `loadCertificates` | `client` | 57.1% | Multi-file load error path |
| `runIssueCert` | `ca` | 55.1% | Requires full temp PKI on disk |
| `runIssueIntermediate` | `ca` | 56.5% | Same — integration test needed |

---

## SQLite WAL and SHM Files Explained

When you run `micropki` with a `--db-path`, SQLite may create two companion files alongside the main `.db`:

```
pki/micropki.db       ← Main database file
pki/micropki.db-wal   ← Write-Ahead Log
pki/micropki.db-shm   ← Shared Memory index
```

### `-wal` — Write-Ahead Log

SQLite's **WAL mode** (Write-Ahead Logging) is an alternative to the default journal mode.

**How it works:**

```
Default (rollback) mode:
  WRITE → lock entire DB → modify pages in-place → unlock

WAL mode:
  WRITE → append new pages to .db-wal → mark as committed
  READ  → read from .db + any committed pages in .db-wal
  CHECKPOINT → periodically merge .db-wal back into .db
```

**Why it exists:**
- Readers never block writers; writers never block readers
- Much faster for workloads with many concurrent reads (like cert lookups)
- Crash-safe: if the process dies mid-write, only `.db-wal` is dirty — the main `.db` is always consistent

**When it appears:** Any time you open a SQLite DB in WAL mode (SQLite enables it automatically when multiple connections open the same file, or when `PRAGMA journal_mode=WAL` is set).

**When it disappears:** On a clean database close / checkpoint — SQLite merges pending WAL pages back into `.db` and removes the WAL file.

---

### `-shm` — Shared Memory

The `.db-shm` file is a **lock table** — a shared memory region used to coordinate between multiple processes or goroutines reading the same WAL file.

**What it stores:**
- A small fixed-size header tracking which WAL frames have been committed
- Read-lock counters so checkpointing knows when it's safe to truncate the WAL

**How it works:**

```
Process A (writer) → appends frame to .db-wal
                  → updates commit index in .db-shm

Process B (reader) → reads commit index from .db-shm
                  → knows which frames in .db-wal are safe to read
```

On systems with real shared memory (multiple processes), `.db-shm` is memory-mapped and genuinely shared. On a single-process app like `micropki`, it still exists but is effectively private.

**When it appears:** Always alongside `.db-wal` — they are a pair.  
**When it disappears:** Same time as `.db-wal`, on clean checkpoint/close.

---

### Summary Table

| File | Size | Purpose | Safe to delete? |
|---|---|---|---|
| `micropki.db` | grows with data | Main database | ❌ Never |
| `micropki.db-wal` | up to ~4 MB | Uncommitted write buffer | ⚠️ Only when DB is closed |
| `micropki.db-shm` | always 32 KB | WAL coordination index | ⚠️ Only when DB is closed |

> **Rule of thumb:** If you see `.db-wal` and `.db-shm` while `micropki` is running — that is **completely normal**. They disappear automatically when the process exits cleanly. If they persist after a crash, SQLite will replay the WAL on next open and recover all committed data automatically.

---

### Relevance to MicroPKI

The smoke test output showed:

```
/tmp/.../pki/micropki.db
/tmp/.../pki/micropki.db-shm
/tmp/.../pki/micropki.db-wal
```

This is because `ca issue-intermediate` opened the DB and the process exited before SQLite fully checkpointed. The files are added to `.gitignore` via `*.db` pattern — which correctly excludes all three (`*.db`, `*.db-shm`, `*.db-wal` are all matched by the glob because SQLite uses the `.db` extension as a prefix).

Actually `.db-shm` and `.db-wal` are **not** matched by `*.db` — they use different extensions. They should be excluded separately if needed. Currently `micropki`'s `.gitignore` has:

```
*.db
```

This matches `micropki.db` but **not** `micropki.db-wal` or `micropki.db-shm`. To be safe, add:

```
*.db-wal
*.db-shm
```
