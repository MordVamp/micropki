# MicroPKI - A Minimal Public Key Infrastructure

MicroPKI is a Go-based PKI tool demonstrating core functionalities like Root CA generation, intermediate CAs, end-entity certificate issuance, revocation (CRL), real-time status tracking (OCSP) and custom path-validation Client workflows! It integrates cleanly with a backend SQLite registry for deterministic ledger keeping.

## New to the Project?
**Check out `NOOB_GUIDE.md` for a comprehensive step-by-step introduction specifically written for absolute beginners mapping out database setup, CA infrastructure, Issuance, Client interactions, and Test execution paths.**

## Installation

```bash
git clone 
cd micropki
go mod tidy
go build -o micropki ./cmd/micropki
```

## Test Results
All major automated verification suites globally successfully execute passing CRL bounds, mathematical constraint tracking engines, and OCSP cycles correctly using standards like RFC 5280 mapped revocation codes and RFC 6960 ASN.1 OCSP parsing. If you are experiencing `go-sqlite3` stub errors locally running tests, install a C++ compiler (`gcc`) to satisfy `CGO_ENABLED` SQLite hooks!

---

## Basic Technical Commands Showcase

### 1. Database & Central Authority Nodes
Initialize the SQLite tracking database to securely store serial bindings:
```bash
./micropki db init --path ./pki/micropki.db
./micropki ca init-root --subject "CN=MicroPKI Root CA" --out-dir ./pki
```

### 2. Client Side Automation (`client` group)
Natively spin up completely constrained raw keys and `PKCS#10` payloads locally as a user without CA master keys:
```bash
./micropki client gen-csr \
  --subject "CN=Server 1" \
  --key-type rsa \
  --out-key ./key.pem \
  --out-csr ./request.csr.pem
```

Submit it seamlessly over HTTP to an active `repo serve` subsystem and securely bounce it down to your environment:
```bash
./micropki client request-cert --csr ./request.csr.pem --template server --ca-url http://127.0.0.1:8080 --out-cert ./server.cert.pem
```

### 3. Native Cryptographic Validations
Globally constrain the output relying securely on custom RFC 5280 loop handlers explicitly isolating `NotBefore`/`NotAfter` times and traversing recursively evaluating `MaxPathLen` constraints.
```bash
./micropki client validate \
  --cert ./server.cert.pem \
  --trusted ./pki/certs/ca.cert.pem \
  --untrusted ./pki/certs/intermediate.cert.pem \
  --mode full \
  --ocsp
```

### 4. Direct Revocation Administration
Invalidate nodes statically utilizing HTTP APIs natively or securely querying SQLite offline list snapshots tracking `application/pkix-crl` mime headers.
```bash
./micropki ca revoke 00dfff3 --reason keycompromise
./micropki ca gen-crl --ca intermediate --out-file ./intermediate.crl.pem

# Check explicit status routing utilizing internal native endpoints
./micropki client check-status --cert ./server.cert.pem --ca-cert ./intermediate.cert.pem
```