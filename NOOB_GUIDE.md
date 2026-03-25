# The Ultimate Beginner's Guide to MicroPKI

Welcome! If you're new to Public Key Infrastructure (PKI) and Go programming, this guide is built for you! We will walk you through exactly how to install, test, and use the MicroPKI toolkit, which lets you act as your own Certificate Authority (CA) running on your local machine!

## 1. Installation

### Prerequisites
- **Go 1.18+**: You need Go installed on your machine.
- **GCC (C Compiler)**: Because this project expertly uses `go-sqlite3` for its backing database, you **must** have a C compiler installed and CGO enabled to cross-compile the SQLite engine logic. 
  - **On Windows**: Install [MinGW-w64](https://www.mingw-w64.org/) via MSYS2.
  - **On Linux**: `sudo apt install build-essential`
  - **On macOS**: `xcode-select --install`

### Downloading & Building
```bash
git clone https://github.com/your-username/micropki.git
cd micropki

# Ensure all dependencies are downloaded:
go mod tidy

# Build the executable (Make sure CGO_ENABLED=1)
go build -o micropki ./cmd/micropki
```

## 2. Running the Automated Tests

MicroPKI includes a comprehensive suite of unit tests validating RFC 5280 constraints, revocation math, and JSON structures. 

*Beware*: Because the SQLite database requires CGO, trying to run tests on a Windows machine without `gcc` installed will result in a "stub" error!

To run the tests successfully:
```bash
# Ensure CGO is enabled in your specific terminal
export CGO_ENABLED=1  # On Linux/macOS
$env:CGO_ENABLED="1"  # On Windows PowerShell

go test -v ./internal/...
```
You should see output ending in `PASS` across the packages!

---

## 3. Step-by-Step Command Usage

Here is how to run the entire system from scratch mimicking absolute enterprise standards (Sprints 1 through 6).

### Step 1: Initialize the Database
Before issuing any certificates, you must create the tracking database. Every issuance and revocation is globally tracked here natively!
```bash
./micropki db init --path ./pki/micropki.db
```

### Step 2: Create Your Certificate Authorities (Root & Intermediate)
Create the absolute top-level trusted Root CA (the master key), and then an Intermediate CA that does the actual daily work.
```bash
# Create Root CA
./micropki ca init-root --subject "CN=MicroPKI Super Root" --out-dir ./pki

# Issue Intermediate CA
./micropki ca issue-intermediate \
  --root-cert ./pki/certs/ca.cert.pem \
  --root-key ./pki/private/ca.key.pem \
  --root-pass-file ./secrets/ca.pass \
  --passphrase-file ./secrets/intermediate.pass \
  --subject "CN=MicroPKI Daily Intermediate"
```

### Step 3: Start the CA Web Server (Repository)
Now that the CA is completely ready, run the repository web server. This allows remote clients to download Certificate Revocation Lists (CRL), fetch dynamic `.pem` authorities, and request certs over HTTP directly!
```bash
# Start server in the background (runs on port 8080)
./micropki repo serve \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --cert-dir ./pki/certs \
  --db-path ./pki/micropki.db &
```

### Step 4: Act as a Client!
Imagine you are another machine that needs a certificate for `api.example.com`.
```bash
# Generate a raw private key and a CSR (Certificate Signing Request) natively
./micropki client gen-csr \
  --subject "CN=api.example.com" \
  --key-type rsa \
  --out-key ./api.key.pem \
  --out-csr ./api.csr.pem

# Post the CSR dynamically to the Web Server! It will issue your signed cert back automatically!
./micropki client request-cert \
  --csr ./api.csr.pem \
  --template server \
  --ca-url "http://127.0.0.1:8080" \
  --out-cert ./api.cert.pem
```

### Step 5: Validate the New Certificate!
You received `api.cert.pem`. Is it legitimate? Does it have the right constraints and signatures? Let's computationally trace it backwards to the Root globally bridging maximum path-length limits!
```bash
./micropki client validate \
  --cert ./api.cert.pem \
  --trusted ./pki/certs/ca.cert.pem \
  --untrusted ./pki/certs/intermediate.cert.pem \
  --mode chain
```

### Step 6: Revoke a Bad Certificate
Uh oh, `api.example.com` got hacked. Let's globally revoke it across the registry using its dynamic hex serial number!
```bash
# Find the specific serial number
./micropki ca list-certs

# Revoke it explicitly writing reason strings to the database!
./micropki ca revoke <serial_number_here> --reason keycompromise
```

### Step 7: Distribute Revocation Status (CRL & OCSP)
Let everyone on the network mathematically compute that the certificate is revoked!

**Option A: Boot the Live OCSP Engine! (Recommended)**
OCSP checks certificates individually via sub-millisecond API hooks natively dynamically linked!
```bash
# Issue an isolated, delegated signing authority cert!
./micropki ca issue-ocsp-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --subject "CN=MicroPKI Live Responder"

# Run it on port 8081!
./micropki ocsp serve \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --responder-cert ./pki/certs/ocsp.cert.pem \
  --responder-key ./pki/certs/ocsp.key.pem \
  --port 8081 &
```

**Option B: Generate the Offline DB Snapshot (CRL)**
```bash
# Generate the massive static list of serial numbers locally
./micropki ca gen-crl --ca intermediate --out-file ./pki/crl/intermediate.crl.pem
```

Finally, anyone intelligently checking validation now using `--ocsp` natively on `client validate` or `client check-status` will see the explicit rejection logic! You've mastered PKI!
