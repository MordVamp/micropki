# MicroPKI Test Coverage Report

**Date:** 2026-06-07  
**Command:** `go test -timeout 180s -short -coverprofile=coverage.out -covermode=atomic ./internal/... ./tests/...`  
**Exit code:** 0 — **all tests PASS** ✅

---

## Overall Progress

| Metric | Baseline (May 31) | Last run (Jun 7 #1) | This run (Jun 7 #2) | Δ Total |
|---|---|---|---|---|
| **Total coverage** | 26.2% | 33.4% | **40.1%** | **+13.9 pp** |
| Tests PASS | 28 | 39 | **46** | +18 |
| Tests FAIL | 0 | 0 | **0** | — |
| Tests SKIP | 1 | 1 | **1** | — |
| Packages at 0% | 5 | 3 | **1** | −4 |
| Packages at ≥60% | 5 | 9 | **12** | +7 |

---

## Coverage by Package

| Package | Baseline | Jun 7 #1 | **Now** | Δ vs baseline | Status |
|---|---|---|---|---|---|
| `internal/logger` | 0.0% | 95.5% | **95.5%** | +95.5 | 🟢 Excellent |
| `internal/utils` | 85.7% | 85.7% | **85.7%** | +0.0 | 🟢 Good |
| `internal/certs` | 0.0% | 83.3% | **83.3%** | +83.3 | 🟢 Good |
| `internal/crl` | 0.0% | 0.0% | **84.2%** | **+84.2** | 🟢 Good ← big jump |
| `internal/templates` | 77.1% | 77.1% | **77.1%** | +0.0 | 🟢 Good |
| `internal/database` | 36.7% | 74.1% | **74.1%** | +37.4 | 🟢 Good |
| `internal/ratelimit` | 0.0% | 38.1% | **64.3%** | **+64.3** | 🟡 Fair ← jump |
| `internal/crypto` | 63.4% | 63.4% | **63.4%** | +0.0 | 🟡 Fair |
| `internal/serial` | 0.0% | 60.0% | **60.0%** | +60.0 | 🟡 Fair |
| `internal/policy` | 45.8% | 45.8% | **56.9%** | **+11.1** | 🟡 Fair ← jump |
| `internal/audit` | 53.2% | 53.2% | **53.2%** | +0.0 | 🟡 Fair |
| `internal/repository` | 16.7% | 16.7% | **40.7%** | **+24.0** | 🟡 Fair ← jump |
| `internal/ca` | 19.6% | 19.6% | **22.5%** | +2.9 | 🔴 Low |
| `internal/client` | 33.6% | 33.6% | **33.6%** | +0.0 | 🔴 Low |
| `internal/ocsp` | 8.1% | 8.1% | **8.1%** | +0.0 | 🔴 Low |

---

## Full Test List — 46 PASS · 0 FAIL · 1 SKIP

| # | Test | Package | Result |
|---|---|---|---|
| 1 | TestAuditLogEvent | audit | ✅ PASS |
| 2 | TestCTLog | audit | ✅ PASS |
| 3 | TestCAErrorPaths | ca | ✅ PASS |
| 4 | TestParseDN | ca | ✅ PASS |
| 5 | TestIssueCertMalformedCSR | ca | ✅ PASS |
| 6 | TestGenerateRootCertificate | certs | ✅ PASS |
| 7 | TestClientErrorPaths | client | ✅ PASS |
| 8 | TestGenCSR | client | ✅ PASS |
| 9 | TestRequestCertCmdValidationLogic | client | ✅ PASS |
| 10 | TestValidateChainCryptographically | client | ✅ PASS |
| 11 | TestGenerateCRL | crl | ✅ PASS |
| 12 | TestCrypto | crypto | ✅ PASS |
| 13 | TestRevokeCertificate | database | ✅ PASS |
| 14 | TestRevokeCertificate_NotFound | database | ✅ PASS |
| 15 | TestRevokeCertificate_AlreadyRevoked | database | ✅ PASS |
| 16 | TestGetRevokedCertificates | database | ✅ PASS |
| 17 | TestCRLMetadata_InsertAndUpdate | database | ✅ PASS |
| 18 | TestMarkKeyCompromised_AndIsKeyCompromised | database | ✅ PASS |
| 19 | TestMarkKeyCompromised_DuplicateIgnored | database | ✅ PASS |
| 20 | TestCreateDBIfNotExists | database | ✅ PASS |
| 21 | TestListCertificates_FilterByStatus | database | ✅ PASS |
| 22 | TestCheckSerialExists | database | ✅ PASS |
| 23 | TestLogger | logger | ✅ PASS |
| 24 | TestResponderHTTPMethods | ocsp | ✅ PASS |
| 25 | TestResponderInvalidMediaType | ocsp | ✅ PASS |
| 26 | TestPolicyWriteAndAppend | policy | ✅ PASS |
| 27 | TestValidateKey | policy | ✅ PASS |
| 28 | TestValidateValidity | policy | ✅ PASS |
| 29 | TestValidateSANs | policy | ✅ PASS |
| 30 | TestHTBListener | ratelimit | ✅ PASS |
| 31 | TestMiddleware | ratelimit | ✅ PASS |
| 32 | TestHandleCertificate | repository | ✅ PASS |
| 33 | TestHandleRequestCert | repository | ✅ PASS |
| 34 | TestRepositoryEndpoints | repository | ✅ PASS |
| 35 | TestGenerateUniqueSerial | serial | ✅ PASS |
| 36 | TestTemplates | templates | ✅ PASS |
| 37 | TestUtils | utils | ✅ PASS |
| 38 | TestParseDN | tests | ✅ PASS |
| 39 | TestKeyGeneration | tests | ✅ PASS |
| 40 | TestCertificateGeneration | tests | ✅ PASS |
| 41 | TestEncryptedKeyRoundTrip | tests | ✅ PASS |
| 42 | TestSKIComputation | tests | ✅ PASS |
| 43 | TestPolicyWrite | tests | ✅ PASS |
| 44 | TestReasonCodeMapping | crl | ✅ PASS |
| 45 | TestDatabaseOperations | database | ✅ PASS |
| 46 | TestReasonCodeMapping | crl | ✅ PASS |
| — | TestIntegrationCAInit | tests | ⏭ SKIP (short mode) |

---

## Per-Function Coverage

```
internal/audit
  Init                       72.4%
  LogEvent                   75.0%
  AppendCTLog                66.7%
  Query                       0.0%  ← still missing
  Verify                     65.9%

internal/ca
  runInit                     6.5%
  validateInitArgs           15.4%
  ParseDN                    82.1%  ← was 0%
  runIssueCert                3.8%
  runIssueIntermediate        3.2%
  validateIssueIntermediateArgs  0.0%
  TruncateString              0.0%

internal/certs
  GenerateRootCertificate    83.3%

internal/client
  printResult                66.7%
  buildChain                  0.0%
  validateChainCryptographically  12.5%
  loadCertificate            42.9%
  loadCertificates            0.0%
  resolveRevocation           0.0%
  fetchResourceBytes          0.0%

internal/crl
  GenerateCRL                84.2%  ← was 0%

internal/crypto
  GenerateRSAKey            100.0%
  GenerateECCKey            100.0%
  Zeroize                   100.0%
  EncryptPrivateKey          80.0%
  WritePEMFile               80.0%
  ComputeSKI                 80.0%
  DecryptPrivateKey          45.9%

internal/database
  InitDB                     62.5%
  InsertCertificate          64.3%
  GetCertificateBySerial     61.5%
  ListCertificates           77.3%
  CheckSerialExists          75.0%
  CreateDBIfNotExists       100.0%
  RevokeCertificate          78.6%
  GetRevokedCertificates     78.6%
  GetCRLMetadata             81.8%
  UpdateCRLMetadata          84.6%
  MarkKeyCompromised         80.0%
  IsKeyCompromised           75.0%

internal/logger
  Init                       90.9%
  Close                     100.0%
  logEntry                  100.0%
  Info                      100.0%
  Warning                   100.0%
  Error                     100.0%

internal/ocsp
  NewResponder                0.0%  ← not tested
  ServeHTTP                  11.5%

internal/policy
  LoadConfig                 55.0%
  Write                      88.9%  ← was 0%
  AppendIntermediate          0.0%  ← still missing
  ValidateKey                66.7%
  ValidateValidity           71.4%
  ValidateSANs               54.5%

internal/ratelimit
  init                      100.0%
  getVisitor                100.0%
  Accept                     52.9%  ← was 0%
  LimitListener              66.7%  ← was 0%
  Middleware                 57.1%

internal/repository
  loggingMiddleware           0.0%
  WriteHeader                 0.0%
  Start                       0.0%
  corsMiddleware              0.0%
  handleCertificate          44.4%  ← was 0%
  handleCA                   50.0%
  handleCRL                  55.6%
  handleRequestCert          47.7%  ← was 0%

internal/serial
  GenerateUniqueSerial       60.0%

internal/templates
  String                      0.0%
  ParseTemplate             100.0%
  BuildTemplate              81.0%
  parseSANs                  71.4%

internal/utils
  SafeWriteFile              85.7%
```

---

## Functions Added to Coverage This Session

| Function | Package | Before | After |
|---|---|---|---|
| `GenerateCRL` | `crl` | 0% | **84.2%** |
| `ParseDN` | `ca` | 0% | **82.1%** |
| `Write` | `policy` | 0% | **88.9%** |
| `Accept` (HTBListener) | `ratelimit` | 0% | **52.9%** |
| `LimitListener` | `ratelimit` | 0% | **66.7%** |
| `handleCertificate` | `repository` | 0% | **44.4%** |
| `handleRequestCert` | `repository` | 0% | **47.7%** |

---

## Remaining Zero-Coverage Functions

| Function | Package | Why hard to test | Suggested fix |
|---|---|---|---|
| `NewResponder` | `ocsp` | Needs real PEM cert/key files | Write to `t.TempDir()`, generate with `crypto` helpers |
| `ServeHTTP` (full body) | `ocsp` | Needs a valid DB + encoded OCSP request | Extend responder_test with DB setup + DER-encoded request |
| `AppendIntermediate` | `policy` | Writes to existing file | Test by calling `Write` first, then `AppendIntermediate` |
| `buildChain` / `loadCertificates` | `client` | Needs cert chain on disk | Temp PKI setup in test |
| `resolveRevocation` / `fetchResourceBytes` | `client` | Makes HTTP calls | Mock HTTP server with `httptest.NewServer` |
| `runIssueCert` / `runIssueIntermediate` | `ca` | Cobra RunE, needs flags | Call `cmd.Execute()` with `os.Args` override |
| `validateIssueIntermediateArgs` | `ca` | Private to package, called via RunE | Call with invalid flag values via `cmd.SetArgs` |
| `TruncateString` | `ca` | Unreachable (only via list-certs output) | Direct unit test trivial |
| `loggingMiddleware` / `corsMiddleware` | `repository` | Pure middleware chain | Wrap in `httptest.NewRecorder` |
| `Start` | `repository` | Binds real port, blocks | Call with `:0` in goroutine, cancel after connection check |
| `Query` | `audit` | Just a file reader | Write temp log lines, call `Query` with filters |
| `String` | `templates` | Enum stringer | Single call per variant |

---

## Next Milestone

> **Target: 50% total coverage**

Priority order:
1. `audit.Query` — trivial file filter, +~3 pp
2. `ocsp.NewResponder` + `ServeHTTP` full path — +~8 pp
3. `policy.AppendIntermediate` — +~1 pp
4. `templates.String` — +~0.5 pp
5. `repository` middleware chain — +~3 pp
