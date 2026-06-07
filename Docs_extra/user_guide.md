# MicroPKI User Guide

**Binary:** `bin/micropki` (ELF 64-bit, 9.6 MB, Linux x86-64)  
**Build:** `go build -ldflags="-s -w" -o bin/micropki ./cmd/micropki`

---

## Quick Start — Full PKI in 5 Minutes

```bash
BIN=./bin/micropki

# 1. Prepare secrets
mkdir -p usb secrets
echo "my-root-passphrase"  > secrets/root.pass
echo "my-inter-passphrase" > secrets/inter.pass

# 2. Root CA
$BIN ca init \
  --subject "CN=My Root CA,O=Acme,C=US" \
  --key-type rsa --key-size 4096 --validity-days 3650 \
  --passphrase-file secrets/root.pass \
  --usb-path usb --out-dir pki_root

# 3. Intermediate CA
$BIN ca issue-intermediate \
  --root-cert pki_root/certs/ca.cert.pem \
  --root-key  usb/ca.key.pem \
  --root-pass-file  secrets/root.pass \
  --passphrase-file secrets/inter.pass \
  --subject "CN=My Intermediate CA,O=Acme" \
  --key-type rsa --key-size 3072 --validity-days 1825 \
  --out-dir pki --db-path pki/micropki.db

# 4. Issue a server cert
$BIN ca issue-cert \
  --ca-cert pki/certs/intermediate.cert.pem \
  --ca-key  pki/private/intermediate.key.pem \
  --ca-pass-file secrets/inter.pass \
  --template server --subject "CN=api.example.com" \
  --san "dns:api.example.com" --san "ip:10.0.0.1" \
  --out-dir out --db-path pki/micropki.db

# 5. Verify the chain
openssl verify \
  -CAfile pki_root/certs/ca.cert.pem \
  -untrusted pki/certs/intermediate.cert.pem \
  out/api.example.com.cert.pem
```

---

## Command Reference

### `ca init` — Initialize Root CA

Creates a self-signed Root CA certificate and encrypted private key.

```bash
micropki ca init \
  --subject "CN=Root CA,O=Org,C=US" \
  --key-type rsa          \  # rsa | ecc
  --key-size 4096         \  # RSA: 4096 (min). ECC: 384
  --validity-days 3650    \
  --passphrase-file /path/to/root.pass \
  --usb-path /mnt/usb     \  # USB dir for offline key storage (must exist)
  --out-dir   ./pki_root  \  # output: certs/ and policy.txt
  [--force]                  # overwrite existing files
```

**Output files:**
```
pki_root/
  certs/ca.cert.pem       ← Root CA certificate (public)
  policy.txt              ← Policy document
usb/
  ca.key.pem              ← Encrypted root private key (keep OFFLINE)
```

> ⚠️ The USB directory **must exist** before running. Create it with `mkdir -p usb`.

---

### `ca issue-intermediate` — Issue Intermediate CA

Signs an Intermediate CA using the Root CA key.

```bash
micropki ca issue-intermediate \
  --root-cert  pki_root/certs/ca.cert.pem \
  --root-key   usb/ca.key.pem             \
  --root-pass-file  secrets/root.pass     \  # Root CA passphrase
  --passphrase-file secrets/inter.pass    \  # NEW intermediate key passphrase
  --subject "CN=Intermediate CA,O=Org"   \
  --key-type rsa --key-size 3072         \  # RSA min 3072, ECC min 384
  --validity-days 1825                   \
  --out-dir  ./pki                       \
  --db-path  ./pki/micropki.db           \
  [--pathlen 0]                          \  # Path length constraint
  [--permitted-dns "example.com"]        \  # Name Constraints (allow)
  [--excluded-dns  "bad.example.com"]       # Name Constraints (deny)
```

**Output files:**
```
pki/
  certs/intermediate.cert.pem   ← Intermediate certificate
  private/intermediate.key.pem  ← Encrypted intermediate key
  csrs/intermediate.csr.pem     ← CSR (reference)
  micropki.db                   ← SQLite database
  policy.txt
```

> ⚠️ Two passphrase flags are required: `--root-pass-file` (unlocks root key) and `--passphrase-file` (encrypts the new intermediate key).

---

### `ca issue-cert` — Issue End-Entity Certificate

Issues a leaf certificate using the Intermediate CA.

```bash
micropki ca issue-cert \
  --ca-cert      pki/certs/intermediate.cert.pem \
  --ca-key       pki/private/intermediate.key.pem \
  --ca-pass-file secrets/inter.pass              \
  --template     server                          \  # server | client | code_signing
  --subject      "CN=app.example.com"            \
  --san          "dns:app.example.com"           \  # repeatable
  --san          "ip:10.0.0.1"                  \
  --out-dir      ./out                           \
  --db-path      ./pki/micropki.db              \
  [--csr         ./request.csr.pem]             \  # use existing CSR
  [--validity-days 365]
```

**Templates:**

| Template | Key Usage | Extended KU | SAN Required |
|---|---|---|---|
| `server` | digitalSignature | serverAuth | ✅ DNS or IP |
| `client` | digitalSignature | clientAuth | ❌ optional |
| `code_signing` | digitalSignature | codeSigning | ✅ DNS |

**Output files:**
```
out/
  <CN>.cert.pem    ← Certificate
  <CN>.key.pem     ← Private key (only if no --csr provided)
```

---

### `ca issue-ocsp-cert` — Issue OCSP Responder Certificate

```bash
micropki ca issue-ocsp-cert \
  --ca-cert      pki/certs/intermediate.cert.pem \
  --ca-key       pki/private/intermediate.key.pem \
  --ca-pass-file secrets/inter.pass              \
  --subject      "CN=OCSP Responder"             \
  --san          "dns:ocsp.example.com"          \
  --out-dir      ./out                           \
  --db-path      ./pki/micropki.db              \
  [--validity-days 365]
```

**Output:** `out/ocsp.cert.pem` + `out/ocsp.key.pem`

---

### `ca gen-crl` — Generate Certificate Revocation List

```bash
micropki ca gen-crl \
  --ca               intermediate           \  # intermediate | root
  --out-file         pki/crl/intermediate.crl.pem \
  --passphrase-file  secrets/inter.pass    \
  --db-path          pki/micropki.db       \
  [--next-update 7]                        \  # days until next CRL update
  [--force]                                   # overwrite existing CRL file
```

Run with `--force` to update the CRL after revoking certificates.

---

### `ca revoke` — Revoke Certificate by Serial

```bash
# Get serial from cert
SERIAL=$(openssl x509 -in out/app.cert.pem -noout -serial | cut -d= -f2 | tr '[:upper:]' '[:lower:]')

micropki ca revoke "$SERIAL" \
  --reason keyCompromise    \  # see RFC 5280 reason codes below
  --db-path pki/micropki.db
```

**Reason codes:** `unspecified` · `keyCompromise` · `caCompromise` · `affiliationChanged` · `superseded` · `cessationOfOperation` · `certificateHold`

---

### `ca compromise` — Emergency Key Compromise Response

Immediately revokes the certificate **and** blacklists the public key hash so no future certificate can reuse that key.

```bash
micropki ca compromise \
  --cert     out/Compromised.cert.pem \
  --reason   keyCompromise            \
  --db-path  pki/micropki.db         \
  [--force]
```

Prints `[ALARM]` on success. The key hash is written to the `compromised_keys` DB table.

---

### `ca list-certs` — List Database Certificates

```bash
micropki ca list-certs \
  --db-path pki/micropki.db  \
  [--status valid]           \  # valid | revoked | expired
  [--format json]               # table (default) | json
```

---

### `ca show-cert` — Show Certificate Details

```bash
micropki ca show-cert <serial> --db-path pki/micropki.db
```

---

## Client Commands

### `client gen-csr` — Generate Key + CSR

```bash
micropki client gen-csr \
  --subject "CN=app.example.com,O=Org" \
  --san     "dns:app.example.com"      \  # repeatable
  --san     "ip:192.168.1.10"         \
  --out-key ./app.key.pem             \
  --out-csr ./app.csr.pem            \
  [--key-type rsa]                    \  # rsa | ecc
  [--key-size 2048]
```

> ⚠️ The key is written **unencrypted**. Store it securely.

---

### `client validate` — Validate Certificate Chain

```bash
micropki client validate \
  --cert      out/app.cert.pem                    \
  --trusted   pki_root/certs/ca.cert.pem          \  # Root CA bundle
  --untrusted pki/certs/intermediate.cert.pem     \  # repeatable
  --mode      chain                               \  # chain | full
  [--crl      pki/crl/intermediate.crl.pem]      \  # static CRL fallback
  [--ocsp]                                        \  # live OCSP check
  [--format   json]                               \  # text (default) | json
  [--validation-time "2025-01-01T00:00:00Z"]        # historical check
```

**Modes:**
- `chain` — cryptographic path validation only (fast, offline)
- `full` — chain + revocation via CRL/OCSP

---

### `client request-cert` — Request Cert from Repo Server

```bash
micropki client request-cert \
  --csr       ./app.csr.pem       \
  --template  server              \
  --ca-url    http://127.0.0.1:8080 \
  --out-cert  ./app.cert.pem
```

Requires `repo serve` to be running with `X-API-Key: changeme` authentication.

---

### `client check-status` — Check Revocation Status

```bash
micropki client check-status \
  --cert    out/app.cert.pem          \
  --ca-cert pki/certs/intermediate.cert.pem \
  [--crl      pki/crl/intermediate.crl.pem] \
  [--ocsp-url http://127.0.0.1:8081/ocsp]
```

---

## Audit Commands

### `audit verify` — Verify Hash Chain Integrity

```bash
micropki audit verify \
  --log-file pki/audit/audit.log  \
  [--chain-file pki/audit/chain.dat]
```

Verifies every log entry's HMAC and the prev→current hash chain. Prints `[OK] Audit log integrity verified successfully.`

---

### `audit query` — Query Audit Log

```bash
micropki audit query \
  --log-file  pki/audit/audit.log     \
  [--operation compromise_key]        \  # filter by operation name
  [--level     AUDIT]                 \  # filter by level
  [--serial    6a255b14e8520f90]      \  # filter by cert serial
  [--from      "2026-01-01T00:00:00Z"] \
  [--to        "2026-12-31T23:59:59Z"]
```

Output is one JSON object per line. Pipe through `python3 -m json.tool` for pretty-printing.

**Common operation values:** `init_ca` · `issue_intermediate` · `issue_cert` · `revoke_cert` · `compromise_key` · `gen_crl`

---

## Server Commands

### `ocsp serve` — OCSP Responder

```bash
micropki ocsp serve \
  --port    8081                                \
  --db-path pki/micropki.db                    \
  --ca-cert pki/certs/intermediate.cert.pem    \
  --cert    out/ocsp.cert.pem                  \
  --key     out/ocsp.key.pem
```

Responds to HTTP POST at `/ocsp`. Test with:
```bash
openssl ocsp \
  -issuer pki/certs/intermediate.cert.pem \
  -cert   out/app.cert.pem \
  -url    http://127.0.0.1:8081/ocsp \
  -noverify
```

---

### `repo serve` — HTTP Certificate Repository

Serves certificates, CRLs, and accepts certificate issuance requests.

```bash
micropki repo serve \
  --host         127.0.0.1                           \
  --port         8080                                \
  --db-path      pki/micropki.db                    \
  --cert-dir     pki/certs                          \
  --ca-cert      pki/certs/intermediate.cert.pem    \
  --ca-key       pki/private/intermediate.key.pem   \
  --ca-pass-file secrets/inter.pass                 \
  [--rate-limit 100]   \  # requests/sec (0 = disabled)
  [--rate-burst 10]
```

**Endpoints:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/ca/root` | Root CA certificate (PEM) |
| `GET` | `/ca/intermediate` | Intermediate CA certificate (PEM) |
| `GET` | `/crl?ca=intermediate` | Current CRL (PEM) |
| `GET` | `/certificate/<serial>` | Certificate by hex serial |
| `POST` | `/request-cert?template=<t>` | Issue cert (requires `X-API-Key: changeme`) |

---

### `db init` — Initialize Database

```bash
micropki db init --db-path ./pki/micropki.db
```

Creates the SQLite schema (certificates, crl\_metadata, compromised\_keys tables). Called automatically by most commands.

---

## Directory Layout Reference

After a complete setup, the working tree looks like:

```
usb/
  ca.key.pem                  ← Root CA private key (KEEP OFFLINE)

pki_root/
  certs/ca.cert.pem           ← Root CA certificate (public)
  policy.txt

pki/
  certs/
    intermediate.cert.pem     ← Intermediate CA certificate
    ocsp.cert.pem             ← OCSP responder certificate
  private/
    intermediate.key.pem      ← Encrypted intermediate key
  crl/
    intermediate.crl.pem      ← Current CRL
  csrs/
    intermediate.csr.pem
  audit/
    audit.log                 ← HMAC hash-chained audit log
    chain.dat                 ← Hash chain state
    ct.log                    ← Certificate Transparency log
    audit.key                 ← HMAC secret key
  micropki.db                 ← SQLite database

secrets/
  root.pass                   ← Root CA passphrase (protect carefully)
  inter.pass                  ← Intermediate CA passphrase

out/
  app.example.com.cert.pem    ← Issued certificate
  app.example.com.key.pem     ← Leaf private key
```

---

## Common Workflows

### Renew a certificate

```bash
# Re-issue with same CSR, new serial
micropki ca issue-cert \
  --ca-cert pki/certs/intermediate.cert.pem \
  --ca-key  pki/private/intermediate.key.pem \
  --ca-pass-file secrets/inter.pass \
  --template server --subject "CN=app.example.com" \
  --san "dns:app.example.com" \
  --csr out/app.csr.pem \
  --out-dir out --db-path pki/micropki.db --force
```

### Revoke + update CRL

```bash
SERIAL=$(openssl x509 -in out/app.cert.pem -noout -serial | cut -d= -f2 | tr A-Z a-z)
micropki ca revoke "$SERIAL" --reason keyCompromise --db-path pki/micropki.db
micropki ca gen-crl \
  --ca intermediate \
  --out-file pki/crl/intermediate.crl.pem \
  --passphrase-file secrets/inter.pass \
  --db-path pki/micropki.db --force
```

### Run OCSP + Repo servers in background

```bash
micropki ocsp serve \
  --db-path pki/micropki.db \
  --ca-cert pki/certs/intermediate.cert.pem \
  --cert out/ocsp.cert.pem --key out/ocsp.key.pem &

micropki repo serve \
  --db-path pki/micropki.db \
  --cert-dir pki/certs \
  --ca-cert pki/certs/intermediate.cert.pem \
  --ca-key  pki/private/intermediate.key.pem \
  --ca-pass-file secrets/inter.pass &
```

### Validate with live revocation check

```bash
micropki client validate \
  --cert      out/app.cert.pem \
  --trusted   pki_root/certs/ca.cert.pem \
  --untrusted pki/certs/intermediate.cert.pem \
  --mode      full \
  --ocsp \
  --crl  pki/crl/intermediate.crl.pem
```

---

## Key Size Policy Reference

| Type | CA | Leaf |
|---|---|---|
| RSA | ≥ 3072 bits (root: 4096) | ≥ 2048 bits |
| ECC | ≥ 384 bits | ≥ 256 bits |

Certificates generated with weaker keys are **rejected** by the policy engine with a clear error message.

---

## Tips

- **Always run `demo.sh` first** to verify your environment works end-to-end before production use.
- All commands accept `--log-file <path>` to redirect operational logs to a file.
- The audit log at `pki/audit/audit.log` is HMAC hash-chained — run `audit verify` after any operation to confirm integrity.
- Keep `usb/ca.key.pem` and `secrets/root.pass` **offline and air-gapped** — the Root CA should only come online to sign Intermediate CAs.
- Use `perf_test.sh` to benchmark issuance throughput before deploying.
