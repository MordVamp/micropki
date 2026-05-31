#!/bin/bash
set -e

echo "=== MicroPKI Complete Demo (Sprints 1-8) ==="

# Cleanup
echo "=> Cleaning up previous state..."
rm -rf ./pki_root ./pki ./secrets ./out ./audit.log ./chain.dat

if command -v go &> /dev/null; then
    echo "=> Building micropki..."
    go build -o micropki ./cmd/micropki
else
    echo "=> Using pre-compiled micropki binary..."
fi

# 1. Initialize Root CA
echo "=> Initializing Root CA (Isolated Environment)..."
mkdir -p ./secrets
mkdir -p ./pki_root_usb
echo "rootpass" > ./secrets/root.pass
./micropki ca init --subject "CN=MicroPKI Root CA,O=Security" \
    --key-type rsa --key-size 4096 --validity-days 3650 \
    --passphrase-file ./secrets/root.pass --out-dir ./pki_root \
    --usb-path ./pki_root_usb

# 2. Issue Intermediate CA
echo "=> Issuing Intermediate CA (Separated from Root)..."
echo "interpass" > ./secrets/intermediate.pass
./micropki ca issue-intermediate \
    --root-cert ./pki_root/certs/ca.cert.pem \
    --root-pass-file ./secrets/root.pass \
    --usb-path ./pki_root_usb \
    --subject "CN=MicroPKI Intermediate CA,O=Security" \
    --key-type rsa --key-size 3072 \
    --passphrase-file ./secrets/intermediate.pass \
    --out-dir ./pki \
    --db-path ./pki/micropki.db

# "Unplug" USB Drive to simulate offline Root CA
echo "=> 'Unplugging' USB drive with Root CA Key..."
mv ./pki_root_usb ./pki_root_usb_offline

# 3. Issue OCSP Responder Cert
echo "=> Issuing OCSP Responder Certificate..."
./micropki ca issue-ocsp-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --subject "CN=MicroPKI OCSP Responder" \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db

# Generate CRL
echo "=> Generating initial CRL..."
./micropki ca gen-crl --ca intermediate --out-file ./pki/crl/intermediate.crl.pem --db-path ./pki/micropki.db

# 4. Start Servers
echo "=> Starting HTTP Repository Server..."
./micropki repo serve --port 8080 --db-path ./pki/micropki.db &
REPO_PID=$!

echo "=> Starting OCSP Responder..."
./micropki ocsp serve --port 8081 --db-path ./pki/micropki.db &
OCSP_PID=$!

sleep 2

# 5. Issue Server Certificate
echo "=> Generating CSR for test server..."
mkdir -p ./out
./micropki client gen-csr \
    --subject "CN=localhost" \
    --san "dns:localhost" \
    --out-key ./out/server.key.pem \
    --out-csr ./out/server.csr.pem

echo "=> Demonstrating Policy Enforcement (Weak Key Rejection)..."
openssl req -new -newkey rsa:1024 -nodes -keyout ./out/weak.key -out ./out/weak.csr -subj "/CN=weak" 2>/dev/null
./micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "CN=weak" \
    --csr ./out/weak.csr \
    --out-dir ./out \
    --db-path ./pki/micropki.db && echo "[FAIL] System allowed weak key!" || echo "[PASS] Policy engine correctly rejected weak key."

echo "=> Issuing Server Certificate..."
./micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "CN=localhost" \
    --csr ./out/server.csr.pem \
    --out-dir ./out \
    --db-path ./pki/micropki.db

# 6. TLS Verification
echo "=> Verifying Server Certificate chain (Static)..."
openssl verify -CAfile ./pki_root/certs/ca.cert.pem -untrusted ./pki/certs/intermediate.cert.pem ./out/localhost.cert.pem || echo "[Warning] OpenSSL verification failed"

# 6.5 Real TLS Server Demonstration
echo "=> Starting real HTTPS server for TLS Demonstration..."
cat ./pki_root/certs/ca.cert.pem ./pki/certs/intermediate.cert.pem > ./out/chain.pem
openssl s_server -accept 8443 -cert ./out/localhost.cert.pem -key ./out/server.key.pem -CAfile ./out/chain.pem -quiet &
TLS_PID=$!
sleep 1

echo "=> Connecting client to HTTPS server (Should PASS)..."
echo "Q" | openssl s_client -connect localhost:8443 -CAfile ./out/chain.pem -quiet || echo "[FAIL] Connection failed"

# 7. Code Signing Example
echo "=> Issuing Code Signing Certificate..."
./micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=DevOps Code Signer" \
    --out-dir ./out \
    --db-path ./pki/micropki.db
    
echo "=> Signing a file..."
echo "Hello, secure world!" > ./out/data.txt
openssl dgst -sha256 -sign ./out/DevOps_Code_Signer.key.pem -out ./out/data.sig ./out/data.txt
echo "=> Verifying signature..."
openssl dgst -sha256 -verify <(openssl x509 -in ./out/DevOps_Code_Signer.cert.pem -pubkey -noout) -signature ./out/data.sig ./out/data.txt

# 8. Revocation & Audit
echo "=> Revoking server certificate..."
SERIAL=$(openssl x509 -in ./out/localhost.cert.pem -noout -serial | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
if [ ! -z "$SERIAL" ]; then
    ./micropki ca revoke $SERIAL --reason keyCompromise --db-path ./pki/micropki.db
fi

echo "=> Generating updated CRL..."
./micropki ca gen-crl --ca intermediate --out-file ./pki/crl/intermediate.crl.pem --db-path ./pki/micropki.db

echo "=> Connecting client to HTTPS server with Revocation Checking (Should FAIL)..."
echo "Q" | openssl s_client -connect localhost:8443 -CAfile ./out/chain.pem -crl_check -CRLfile ./pki/crl/intermediate.crl.pem -quiet && echo "[FAIL] Connection succeeded despite revocation!" || echo "[PASS] Connection rejected due to revocation."

echo "=> Stopping HTTPS server..."
kill $TLS_PID || true

echo "=> Verifying Audit Log Chain..."
./micropki audit verify

echo "=> Simulating Key Compromise with 'ca compromise'..."
./micropki ca compromise --cert ./out/DevOps_Code_Signer.cert.pem --reason keyCompromise --db-path ./pki/micropki.db

echo "=> Querying Audit Log for compromise events..."
./micropki audit query --operation "compromise_key"

# Cleanup
echo "=> Shutting down servers..."
kill $REPO_PID $OCSP_PID || true
wait $REPO_PID $OCSP_PID 2>/dev/null || true

echo "=== Demo Complete ==="
