#!/bin/bash
set -e

echo "=== MicroPKI Complete Demo (Sprints 1-8) ==="

# Cleanup
echo "=> Cleaning up previous state..."
rm -rf ./pki ./secrets ./out ./audit.log ./chain.dat

echo "=> Building micropki..."
go build -o micropki.exe ./cmd/micropki

# 1. Initialize Root CA
echo "=> Initializing Root CA..."
mkdir -p ./secrets
echo "rootpass" > ./secrets/root.pass
./micropki.exe ca init --subject "CN=MicroPKI Root CA,O=Security" \
    --key-type rsa --key-size 4096 --validity-days 3650 \
    --passphrase-file ./secrets/root.pass --out-dir ./pki

# 2. Issue Intermediate CA
echo "=> Issuing Intermediate CA..."
echo "interpass" > ./secrets/intermediate.pass
./micropki.exe ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./secrets/root.pass \
    --subject "CN=MicroPKI Intermediate CA,O=Security" \
    --key-type rsa --key-size 3072 \
    --passphrase-file ./secrets/intermediate.pass \
    --out-dir ./pki

# 3. Issue OCSP Responder Cert
echo "=> Issuing OCSP Responder Certificate..."
./micropki.exe ca issue-ocsp-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --subject "CN=MicroPKI OCSP Responder" \
    --out-dir ./pki/certs

# Generate CRL
echo "=> Generating initial CRL..."
./micropki.exe ca gen-crl --ca intermediate --out-file ./pki/crl/intermediate.crl.pem

# 4. Start Servers
echo "=> Starting HTTP Repository Server..."
./micropki.exe repo serve --port 8080 &
REPO_PID=$!

echo "=> Starting OCSP Responder..."
./micropki.exe ocsp serve --port 8081 &
OCSP_PID=$!

sleep 2

# 5. Issue Server Certificate
echo "=> Generating CSR for test server..."
mkdir -p ./out
./micropki.exe client gen-csr \
    --subject "CN=localhost" \
    --san "dns:localhost" \
    --out-key ./out/server.key.pem \
    --out-csr ./out/server.csr.pem

echo "=> Issuing Server Certificate..."
./micropki.exe ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "CN=localhost" \
    --csr ./out/server.csr.pem \
    --out-dir ./out

# 6. TLS Verification
echo "=> Verifying Server Certificate chain..."
openssl verify -CAfile ./pki/certs/ca.cert.pem -untrusted ./pki/certs/intermediate.cert.pem ./out/localhost.cert.pem || echo "[Warning] OpenSSL verification failed"

# 7. Code Signing Example
echo "=> Issuing Code Signing Certificate..."
./micropki.exe ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=DevOps Code Signer" \
    --out-dir ./out
    
echo "=> Signing a file..."
echo "Hello, secure world!" > ./out/data.txt
openssl dgst -sha256 -sign ./out/DevOps_Code_Signer.key.pem -out ./out/data.sig ./out/data.txt
echo "=> Verifying signature..."
openssl dgst -sha256 -verify <(openssl x509 -in ./out/DevOps_Code_Signer.cert.pem -pubkey -noout) -signature ./out/data.sig ./out/data.txt

# 8. Revocation & Audit
echo "=> Revoking server certificate..."
# Extract serial using powershell syntax if windows, else standard bash. Bash relies on openssl.
SERIAL=$(openssl x509 -in ./out/localhost.cert.pem -noout -serial | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
if [ ! -z "$SERIAL" ]; then
    ./micropki.exe ca revoke $SERIAL --reason keyCompromise
fi

echo "=> Verifying Audit Log Chain..."
./micropki.exe audit verify

echo "=> Simulating Key Compromise with 'ca compromise'..."
./micropki.exe ca compromise --cert ./out/DevOps_Code_Signer.cert.pem --reason keyCompromise

echo "=> Querying Audit Log for compromise events..."
./micropki.exe audit query --operation "compromise_key"

# Cleanup
echo "=> Shutting down servers..."
kill $REPO_PID $OCSP_PID || true
wait $REPO_PID $OCSP_PID 2>/dev/null || true

echo "=== Demo Complete ==="
