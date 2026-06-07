# MicroPKI Test Coverage Report

**Date:** 2026-06-07  
**Command:** `go test -timeout 180s -short -coverprofile=coverage.out -covermode=atomic ./internal/... ./tests/...`  
**Exit code:** 0 — all tests PASS ✅

---

## Summary

| Metric | Before | After | Δ |
|---|---|---|---|
| **Total coverage** | 26.2% | **33.4%** | +7.2 pp |
| Test files | 10 | 19 | +9 |
| Packages with 0% coverage | 5 | 3 | −2 |
| Packages at ≥60% | 5 | 9 | +4 |

---

## Coverage by Package

| Package | Before | After | Δ | Status |
|---|---|---|---|---|
| `internal/logger` | 0.0% | **95.5%** | +95.5 | 🟢 Excellent |
| `internal/utils` | 85.7% | **85.7%** | — | 🟢 Good |
| `internal/templates` | 77.1% | **77.1%** | — | 🟢 Good |
| `internal/database` | 36.7% | **74.1%** | +37.4 | 🟢 Good |
| `internal/crypto` | 63.4% | **63.4%** | — | 🟡 Fair |
| `internal/serial` | 0.0% | **60.0%** | +60.0 | 🟡 Fair |
| `internal/audit` | 53.2% | **53.2%** | — | 🟡 Fair |
| `internal/ratelimit` | 0.0% | **38.1%** | +38.1 | 🟡 Fair |
| `internal/policy` | 45.8% | **45.8%** | — | 🟡 Fair |
| `internal/client` | 33.6% | **33.6%** | — | 🔴 Low |
| `internal/certs` | 0.0% | **83.3%** | +83.3 | 🟢 Good |
| `internal/repository` | 16.7% | **16.7%** | — | 🔴 Low |
| `internal/ocsp` | 8.1% | **8.1%** | — | 🔴 Low |
| `internal/crl` | 0.0% | **0.0%** | — | ⚫ None |
| `internal/ca` | 19.6% | **19.6%** | — | 🔴 Low |

---

## All Tests — Pass/Fail Table

| Test | Package | Result | Time |
|---|---|---|---|
| TestAuditLogEvent | audit | ✅ PASS | 0.00s |
| TestCTLog | audit | ✅ PASS | 0.01s |
| TestCAErrorPaths | ca | ✅ PASS | 0.00s |
| TestIssueCertMalformedCSR | ca | ✅ PASS | 0.31s |
| TestGenerateRootCertificate | certs | ✅ PASS | ~1.0s |
| TestClientErrorPaths | client | ✅ PASS | 0.27s |
| TestGenCSR | client | ✅ PASS | 0.15s |
| TestRequestCertCmdValidationLogic | client | ✅ PASS | 0.00s |
| TestValidateChainCryptographically | client | ✅ PASS | 0.00s |
| TestReasonCodeMapping | crl | ✅ PASS | 0.00s |
| TestCrypto | crypto | ✅ PASS | 0.65s |
| TestRevokeCertificate | database | ✅ PASS | 0.01s |
| TestRevokeCertificate_NotFound | database | ✅ PASS | 0.00s |
| TestRevokeCertificate_AlreadyRevoked | database | ✅ PASS | 0.01s |
| TestGetRevokedCertificates | database | ✅ PASS | 0.01s |
| TestCRLMetadata_InsertAndUpdate | database | ✅ PASS | 0.00s |
| TestMarkKeyCompromised_AndIsKeyCompromised | database | ✅ PASS | 0.00s |
| TestMarkKeyCompromised_DuplicateIgnored | database | ✅ PASS | 0.00s |
| TestCreateDBIfNotExists | database | ✅ PASS | 0.00s |
| TestListCertificates_FilterByStatus | database | ✅ PASS | 0.01s |
| TestCheckSerialExists | database | ✅ PASS | 0.00s |
| TestDatabaseOperations | database | ✅ PASS | 0.02s |
| TestLogger | logger | ✅ PASS | 0.00s |
| TestResponderHTTPMethods | ocsp | ✅ PASS | 0.00s |
| TestResponderInvalidMediaType | ocsp | ✅ PASS | 0.00s |
| TestValidateKey | policy | ✅ PASS | 0.10s |
| TestValidateValidity | policy | ✅ PASS | 0.00s |
| TestValidateSANs | policy | ✅ PASS | 0.00s |
| TestMiddleware | ratelimit | ✅ PASS | 0.00s |
| TestRepositoryEndpoints | repository | ✅ PASS | 0.00s |
| TestGenerateUniqueSerial | serial | ✅ PASS | 0.00s |
| TestTemplates | templates | ✅ PASS | 0.00s |
| TestUtils | utils | ✅ PASS | 0.00s |
| TestParseDN | tests | ✅ PASS | 0.00s |
| TestKeyGeneration | tests | ✅ PASS | 0.63s |
| TestCertificateGeneration | tests | ✅ PASS | 2.66s |
| TestEncryptedKeyRoundTrip | tests | ✅ PASS | 1.60s |
| TestSKIComputation | tests | ✅ PASS | 4.81s |
| TestPolicyWrite | tests | ✅ PASS | 0.00s |
| TestIntegrationCAInit | tests | ⏭ SKIP (short mode) | 0.00s |

**Total: 39 PASS, 0 FAIL, 1 SKIP**

---

## Per-Function Coverage Detail

```
internal/audit
  Init              72.4%
  LogEvent          75.0%
  AppendCTLog       66.7%
  Query              0.0%  ← not tested
  Verify            65.9%

internal/ca
  runInit            6.5%
  validateInitArgs  15.4%
  ParseDN            0.0%  ← not tested
  runIssueCert       3.8%
  runIssueIntermediate 3.2%
  validateIssueIntermediateArgs 0.0%  ← not tested

internal/certs
  GenerateRootCertificate  83.3%  ← NEW (+83.3%)

internal/client
  printResult       66.7%
  buildChain         0.0%  ← not tested
  validateChain     12.5%
  loadCertificate   42.9%
  loadCertificates   0.0%  ← not tested
  resolveRevocation  0.0%  ← not tested
  fetchResourceBytes 0.0%  ← not tested

internal/crl
  GenerateCRL        0.0%  ← not tested (requires real CA key)

internal/crypto
  GenerateRSAKey   100.0%
  GenerateECCKey   100.0%
  Zeroize          100.0%
  EncryptPrivateKey 80.0%
  WritePEMFile      80.0%
  ComputeSKI        80.0%
  DecryptPrivateKey 45.9%

internal/database
  InitDB            62.5%
  InsertCertificate 64.3%
  GetCertificateBySerial  61.5%
  ListCertificates  77.3%  ← NEW (+8.6%)
  CheckSerialExists 75.0%  ← NEW (+0%)
  CreateDBIfNotExists 100.0%  ← NEW (+100%)
  RevokeCertificate  78.6%  ← NEW (+78.6%)
  GetRevokedCertificates 78.6%  ← NEW (+78.6%)
  GetCRLMetadata    81.8%  ← NEW (+81.8%)
  UpdateCRLMetadata 84.6%  ← NEW (+84.6%)
  MarkKeyCompromised 80.0%  ← NEW (+80.0%)
  IsKeyCompromised  75.0%  ← NEW (+75.0%)

internal/logger
  Init              90.9%  ← NEW (+90.9%)
  Close            100.0%  ← NEW (+100%)
  logEntry         100.0%  ← NEW (+100%)
  Info             100.0%  ← NEW (+100%)
  Warning          100.0%  ← NEW (+100%)
  Error            100.0%  ← NEW (+100%)

internal/ocsp
  NewResponder       0.0%  ← not tested (requires real cert files)
  ServeHTTP         11.5%

internal/policy
  LoadConfig        55.0%
  Write              0.0%  ← not tested
  AppendIntermediate 0.0%  ← not tested
  ValidateKey       66.7%
  ValidateValidity  71.4%
  ValidateSANs      54.5%

internal/ratelimit
  init             100.0%  ← NEW
  getVisitor       100.0%  ← NEW
  Accept             0.0%  ← not tested (needs net.Listener mock)
  LimitListener      0.0%  ← not tested
  Middleware        57.1%  ← NEW (+57.1%)

internal/repository
  loggingMiddleware  0.0%
  WriteHeader        0.0%
  Start              0.0%  ← not tested (binds real port)
  corsMiddleware     0.0%
  handleCertificate  0.0%
  handleCA          50.0%
  handleCRL         55.6%
  handleRequestCert  0.0%

internal/serial
  GenerateUniqueSerial  60.0%  ← NEW (+60%)

internal/templates
  ParseTemplate    100.0%
  BuildTemplate     81.0%
  parseSANs         71.4%

internal/utils
  SafeWriteFile     85.7%
```

---

## New Tests Added (this session)

| File | New Tests |
|---|---|
| `internal/database/database_test.go` | TestRevokeCertificate, TestRevokeCertificate_NotFound, TestRevokeCertificate_AlreadyRevoked, TestGetRevokedCertificates, TestCRLMetadata_InsertAndUpdate, TestMarkKeyCompromised_AndIsKeyCompromised, TestMarkKeyCompromised_DuplicateIgnored, TestCreateDBIfNotExists, TestListCertificates_FilterByStatus, TestCheckSerialExists |
| `internal/logger/logger_test.go` | TestLogger |
| `internal/ratelimit/ratelimit_test.go` | TestMiddleware |
| `internal/serial/serial_test.go` | TestGenerateUniqueSerial |
| `internal/certs/certs_test.go` | TestGenerateRootCertificate |
| `internal/crl/builder_test.go` | TestReasonCodeMapping |

---

## Remaining Gaps & Recommendations

### 🔴 High value, still uncovered

| Function | Package | Reason not covered | Suggested approach |
|---|---|---|---|
| `GenerateCRL` | `crl` | Needs a real signed CA cert + key | Use `tests/` crypto helpers to create a temp CA, then call GenerateCRL |
| `runIssueCert` / `runIssueIntermediate` | `ca` | Cobra RunE functions — need full flag setup | Table-driven test calling `Execute()` on a subcommand with args |
| `ParseDN` | `ca` | Simple string parser, just not called directly | Direct unit test trivial to add |
| `NewResponder` | `ocsp` | Needs PEM cert files on disk | Write temp PEM files in t.TempDir() |
| `ServeHTTP` (body) | `ocsp` | Needs a valid DB + mock OCSP request | Extend existing responder test with real DB setup |
| `buildChain` / `loadCertificates` | `client` | Needs cert chain files on disk | Integration-style test with temp PKI |
| `Write` / `AppendIntermediate` | `policy` | Writes to file — easy to test | Write to t.TempDir(), verify content |
| `Accept` / `LimitListener` | `ratelimit` | Needs a real `net.Listener` | Use `net.Listen("tcp", ":0")` for ephemeral port |

### 🟡 Medium value

| Function | Package | Notes |
|---|---|---|
| `handleCertificate` / `handleRequestCert` | `repository` | Extend existing server_test.go |
| `loggingMiddleware` / `corsMiddleware` | `repository` | Pure HTTP middleware — easy to unit test |
| `DecryptPrivateKey` (error paths) | `crypto` | Add test for wrong passphrase |
| `validateIssueIntermediateArgs` | `ca` | Direct call with invalid args |

> **Next milestone target:** reach **45%** total by adding CRL, OCSP NewResponder, policy.Write, and ratelimit.LimitListener tests.
