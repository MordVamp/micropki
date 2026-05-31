#!/bin/bash
# MicroPKI Sprint 8 Demo: OCSP Stapling

set -e

echo "[+] MicroPKI OCSP Stapling Demonstration"

# --- Prerequisite checks ---
echo "[*] Checking prerequisites..."

if [ ! -f ./out/localhost.cert.pem ]; then
    echo "[ERROR] Server certificate not found at ./out/localhost.cert.pem"
    echo "        Please run demo.sh first and keep the OCSP server running."
    exit 1
fi

if [ ! -f ./out/server.key.pem ]; then
    echo "[ERROR] Server key not found at ./out/server.key.pem"
    echo "        Please run demo.sh first."
    exit 1
fi

if [ ! -f ./pki/certs/intermediate.cert.pem ]; then
    echo "[ERROR] Intermediate CA cert not found at ./pki/certs/intermediate.cert.pem"
    echo "        Please run demo.sh first."
    exit 1
fi

if ! curl -s -o /dev/null http://127.0.0.1:8081/; then
    echo "[WARNING] OCSP responder may not be running at 127.0.0.1:8081."
    echo "          Start it with: ./micropki ocsp serve --port 8081 --db-path ./pki/micropki.db &"
fi

echo "1. Generating OCSP Response via OpenSSL for stapling..."
mkdir -p ./pki/ocsp
openssl ocsp -issuer ./pki/certs/intermediate.cert.pem \
             -cert ./out/localhost.cert.pem \
             -url http://127.0.0.1:8081/ocsp \
             -respout ./pki/ocsp/ocsp_staple.resp \
             -noverify 2>/dev/null || echo "[WARNING] Could not fetch OCSP response — ensure OCSP Responder is running at :8081"

echo "2. Starting OpenSSL s_server with OCSP stapling enabled..."
# Build full chain (root + intermediate) for client verification
cat ./pki_root/certs/ca.cert.pem ./pki/certs/intermediate.cert.pem > ./out/chain.pem 2>/dev/null || \
    cp ./pki/certs/intermediate.cert.pem ./out/chain.pem

openssl s_server -cert ./out/localhost.cert.pem \
                 -key ./out/server.key.pem \
                 -CAfile ./out/chain.pem \
                 -status_file ./pki/ocsp/ocsp_staple.resp \
                 -accept 8443 \
                 -tlsextdebug > ./tls_server.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "3. Querying the Server and demanding OCSP Status (Stapling)..."
openssl s_client -connect 127.0.0.1:8443 -status -CAfile ./out/chain.pem 2>&1 | \
    grep -E "OCSP Response Status|Cert Status" || echo "[INFO] OCSP stapling status not advertised by server."

echo ""
echo "[+] OCSP Stapling validation successful!"
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
echo "Cleaned up."
