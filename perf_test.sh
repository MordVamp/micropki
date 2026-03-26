#!/bin/bash
set -e

echo "=== MicroPKI Performance Test (1000 Certs) ==="
rm -rf ./perf_out ./perf_pki ./perf_secrets
mkdir -p ./perf_out ./perf_pki ./perf_secrets

go build -o micropki.exe ./cmd/micropki

echo "rootpass" > ./perf_secrets/root.pass
./micropki.exe ca init --subject "CN=Perf Root CA" --key-type rsa --key-size 4096 \
    --validity-days 3650 --passphrase-file ./perf_secrets/root.pass --out-dir ./perf_pki > /dev/null

echo "Starting issuance of 1000 certificates..."
START_TIME=$(date +%s)

for i in {1..1000}; do
    ./micropki.exe client gen-csr --subject "CN=user$i" --out-key ./perf_out/user$i.key.pem --out-csr ./perf_out/user$i.csr.pem > /dev/null 2>&1
    ./micropki.exe ca issue-cert --ca-cert ./perf_pki/certs/ca.cert.pem --ca-key ./perf_pki/private/ca.key.pem \
    --ca-pass-file ./perf_secrets/root.pass --template client --subject "CN=user$i" \
    --csr ./perf_out/user$i.csr.pem --out-dir ./perf_out > /dev/null 2>&1
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [ $DURATION -eq 0 ]; then
    DURATION=1
fi

echo "Issued 1000 certificates in $DURATION seconds."

echo "Cleaning up..."
rm -rf ./perf_out ./perf_pki ./perf_secrets
