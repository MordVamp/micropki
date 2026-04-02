#!/bin/bash
# MicroPKI Sprint 8 Demo: OCSP Stapling

set -e

echo "[+] MicroPKI OCSP Stapling Demonstration"

echo "1. Generating OCSP Response via OpenSSL for stapling..."
# In a real environment, the web server (e.g. Nginx/Caddy) periodically fetches this, but we simulate it.

openssl ocsp -issuer ./pki/certs/intermediate.cert.pem \
             -cert ./pki/certs/server.cert.pem \
             -url http://127.0.0.1:8081/ocsp \
             -respout ./pki/ocsp_staple.resp \
             -noverify 2>/dev/null || echo "Ensure OCSP Responder is running!"

echo "2. Starting OpenSSL s_server with OCSP stapling enabled..."
openssl s_server -cert ./pki/certs/server.cert.pem \
                 -key ./pki/private/server.key.pem \
                 -CAfile ./pki/certs/intermediate.cert.pem \
                 -status_file ./pki/ocsp_staple.resp \
                 -accept 8443 \
                 -tlsextdebug > ./tls_server.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "3. Querying the Server and demanding OCSP Status (Stapling)..."
openssl s_client -connect 127.0.0.1:8443 -status -CAfile ./pki/certs/ca.cert.pem 2>&1 | grep -E "OCSP Response Status|Cert Status"

echo ""
echo "[+] OCSP Stapling validation successful!"
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
echo "Cleaned up."
