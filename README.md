# MicroPKI - A Minimal Public Key Infrastructure

MicroPKI is a Go-based PKI tool demonstrating core functionalities like Root CA generation, intermediate CAs, end-entity certificate issuance, revocation (CRL), and real-time status tracking (OCSP). It integrates tightly with a backend SQLite registry for deterministic ledger keeping.

## Installation

```bash
git clone 
cd micropki
go mod tidy
make build
```

## Test Results
All major automated verification suites successfully execute passing CRL and OCSP cycles correctly using standards like RFC 5280 mapped revocation codes and RFC 6960 ASN.1 OCSP parsing.

---

## Basic Usage

### 1. Initialize SQLite Ledger

Initialize the SQLite tracking database first to sync operations state consistently!
```bash
./micropki db init --path ./pki/micropki.db
```

### 2. Issuing Authorities

Generate a Root CA, and an Intermediate CA directly from the CLI:
```bash
./micropki ca init-root --subject "CN=MicroPKI Root CA" --out-dir ./pki

./micropki ca issue-intermediate \
  --ca-cert ./pki/certs/ca.cert.pem \
  --ca-key ./pki/private/ca.key.pem \
  --ca-pass-file ./secrets/ca.pass \
  --subject "CN=MicroPKI Intermediate CA"
```

### 3. Issue and Revoke Server Certificates

Issue a new certificate, query its tracking status via the CLI, and revoke it directly into the database if compromised:
```bash
# Issue an end-entity web server
./micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/ca.pass \
  --subject "CN=Server 1"

# Query tracked certs
./micropki ca list-certs

# Revoke a parsed identity (uses its hex serial number)
./micropki ca revoke 00df23a --reason keycompromise
```

### 4. Compile Distributable CRL Database

Build all recognized revocations onto a single distributable PEM `.crl` format encoded exactly as expected by proxy platforms:
```bash
./micropki ca gen-crl --ca intermediate --out-file ./pki/crl/intermediate.crl.pem
```
Verify independently using the Unix OpenSSL standard: `openssl crl -inform PEM -in ./pki/crl/intermediate.crl.pem -text -noout`

### 5. Launch Real-time OCSP Responder

Serve live independent status checks securely via the isolated responder HTTP service to completely mitigate broad CRL limitations:

```bash
# Mint an isolated signing cert reserved purely for the HTTP Responder
./micropki ca issue-ocsp-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/ca.pass \
  --subject "CN=MicroPKI OCSP Live Responder"

# Launch daemon locally on port 8081 against sqlite tracking registry
./micropki ocsp serve \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --responder-cert ./pki/certs/ocsp.cert.pem \
  --responder-key ./pki/certs/ocsp.key.pem \
  --port 8081

# Verify independently via standard OpenSSL client ping in another terminal
openssl ocsp -url http://127.0.0.1:8081 \
  -issuer ./pki/certs/intermediate.cert.pem \
  -cert ./pki/certs/server1.cert.pem
```

### 6. Static Repository Server

If distributing raw files is preferred, standard endpoints exist mapping files across the workspace tree recursively to fetch items via GET over port `8080`: 

```bash
./micropki repo serve --port 8080 --cert-dir ./pki/certs
curl -s http://127.0.0.1:8080/crl
curl -s http://127.0.0.1:8080/ca/intermediate
```