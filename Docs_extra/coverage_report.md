# MicroPKI Test Coverage Report

**Date:** 2026-05-31  
**Command:** `go test -timeout 120s -short -coverprofile=coverage.out -covermode=atomic ./...`  
**Total coverage: 26.2%** — all tests PASS ✅

---

## Coverage by Package

| Package | Coverage | Status | Notes |
|---|---|---|---|
| `internal/utils` | **85.7%** | 🟢 Good | `SafeWriteFile` well covered |
| `internal/templates` | **77.1%** | 🟢 Good | `BuildTemplate`, `parseSANs` covered; `String()` missing |
| `internal/crypto` | **63.4%** | 🟡 Fair | RSA/ECC gen 100%; `DecryptPrivateKey` error paths thin |
| `internal/audit` | **53.2%** | 🟡 Fair | `Init`, `LogEvent`, `Verify` covered; `Query` at 0% |
| `internal/policy` | **45.8%** | 🟡 Fair | Validators covered; `Write`, `AppendIntermediate` at 0% |
| `internal/database` | **36.7%** | 🔴 Low | Insert/Get covered; Revoke, CRL, Compromise uncovered |
| `internal/client` | **33.6%** | 🔴 Low | GenCSR, RequestCert validation covered; `buildChain` at 0% |
| `internal/repository` | **16.7%** | 🔴 Low | `handleCA`, `handleCRL` partially; `Start`, middleware 0% |
| `internal/ocsp` | **8.1%** | 🔴 Low | Only HTTP method/media-type checks; `ServeHTTP` body 11% |
| `internal/crl` | **0.0%** | ⚫ None | `GenerateCRL` not tested at all |
| `internal/serial` | **0.0%** | ⚫ None | `GenerateUniqueSerial` not tested |
| `internal/logger` | **0.0%** | ⚫ None | No tests for logger package |
| `internal/ratelimit` | **0.0%** | ⚫ None | Token bucket, middleware untested |
| `internal/certs` | **0.0%** | ⚫ None | `GenerateRootCertificate` only called from tests/ (no coverage profile) |
| `cmd/micropki` | **0.0%** | ⚫ None | CLI entry — expected, no unit tests for Cobra wiring |

---

## Zero-Coverage Functions (Priority Targets)

### 🔴 High Priority — Core PKI Logic

| Package | Function | Why it matters |
|---|---|---|
| `internal/database` | `RevokeCertificate` | Used by `ca revoke` — critical path |
| `internal/database` | `GetRevokedCertificates` | Used by CRL generation |
| `internal/database` | `MarkKeyCompromised` / `IsKeyCompromised` | Blacklist mechanism |
| `internal/database` | `GetCRLMetadata` / `UpdateCRLMetadata` | CRL versioning |
| `internal/crl` | `GenerateCRL` | CRL builder — entire package uncovered |
| `internal/certs` | `GenerateRootCertificate` | Root cert generation |
| `internal/ca` | `ParseDN` | Used everywhere, 0% despite unit tests in tests/ package |
| `internal/ca` | `validateIssueIntermediateArgs` | Recently fixed, not yet tested |
| `internal/serial` | `GenerateUniqueSerial` | Every cert issuance depends on this |

### 🟡 Medium Priority — Network / Server

| Package | Function | Why it matters |
|---|---|---|
| `internal/ocsp` | `NewResponder` | Constructor not tested |
| `internal/ocsp` | `ServeHTTP` (full body) | Only entry conditions tested |
| `internal/repository` | `Start`, middleware | HTTP server startup untested |
| `internal/ratelimit` | All functions | Token-bucket DDoS protection untested |
| `internal/audit` | `Query` | Log query API at 0% |

### 🔵 Low Priority — Utility / Formatting

| Package | Function | Why it matters |
|---|---|---|
| `internal/policy` | `Write`, `AppendIntermediate` | Policy file writing |
| `internal/logger` | All | Logging infrastructure |
| `internal/ca` | `TruncateString`, `runInit` full path | Helper + main CA init flow |

---

## Per-Function Detail (selected)

```
internal/audit/audit.go         Init              72.4%
internal/audit/audit.go         LogEvent          75.0%
internal/audit/ct.go            AppendCTLog       66.7%
internal/audit/query.go         Query              0.0%  ← missing
internal/audit/verify.go        Verify            65.9%

internal/ca/ca.go               runInit            6.5%  ← mostly uncovered
internal/ca/ca.go               validateInitArgs  15.4%
internal/ca/issue_cert.go       runIssueCert       3.8%  ← critical path
internal/ca/issue_intermediate  runIssueIntermediate 3.2%
internal/ca/issue_intermediate  validateIssueIntermediateArgs 0.0%

internal/crypto/crypto.go       GenerateRSAKey   100.0%
internal/crypto/crypto.go       GenerateECCKey   100.0%
internal/crypto/crypto.go       EncryptPrivateKey 80.0%
internal/crypto/crypto.go       DecryptPrivateKey 45.9%

internal/database/database.go   InsertCertificate 85.7%
internal/database/database.go   RevokeCertificate  0.0%  ← critical
internal/database/database.go   MarkKeyCompromised 0.0%  ← critical

internal/templates/templates.go BuildTemplate     81.0%
internal/templates/templates.go parseSANs         71.4%

internal/utils/file.go          SafeWriteFile     85.7%
```

---

## Recommendations

1. **Biggest ROI** — add tests for `internal/database` revocation and compromise functions. These are central to PKI correctness and currently at 0%.
2. **CRL package** — `internal/crl.GenerateCRL` is entirely untested. A unit test can build a CRL from a mock revocation list without a real CA.
3. **Serial package** — one test calling `GenerateUniqueSerial` and checking uniqueness would bring coverage to 100%.
4. **`internal/ca` run-functions** — `runIssueCert` / `runIssueIntermediate` are at ~3-4%. Integration-style tests with temp directories (like `TestIntegrationCAInit`) would boost this significantly.
5. **Audit.Query** — trivial to test: write a few log lines to a temp file and call `Query()` with various filters.

> The 26.2% total is skewed by many zero-coverage packages.  
> The **actually tested packages average ~50%**, which is reasonable for a PKI demo project.
> Focus on database revocation paths and CRL generation first.
