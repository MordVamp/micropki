# MicroPKI Runbook — Sequences by Situation

Each block is a numbered sequence of commands.
One command per line. Comment explains what it does.

---

## 1. First-Time PKI Setup (Root + Intermediate CA)

```bash
1  mkdir -p usb secrets pki pki_root                                        # create working directories

2  echo "my-root-passphrase"  > secrets/root.pass                           # write root CA passphrase to file

3  echo "my-inter-passphrase" > secrets/inter.pass                          # write intermediate CA passphrase to file

4  ./bin/micropki ca init --subject "CN=Root CA,O=Acme" --key-type rsa --key-size 4096 --validity-days 3650 --passphrase-file secrets/root.pass --usb-path usb --out-dir pki_root  # create self-signed Root CA, key goes to usb/

5  ./bin/micropki ca issue-intermediate --root-cert pki_root/certs/ca.cert.pem --root-key usb/ca.key.pem --root-pass-file secrets/root.pass --passphrase-file secrets/inter.pass --subject "CN=Intermediate CA,O=Acme" --key-type rsa --key-size 3072 --validity-days 1825 --out-dir pki --db-path pki/micropki.db  # sign Intermediate CA with Root, create DB

6  cp usb/ca.key.pem /secure-offline-storage/                               # move root key offline — never keep it on the server
```

---

## 2. Issue a Server TLS Certificate (with existing CSR)

```bash
1  ./bin/micropki client gen-csr --subject "CN=api.example.com" --san "dns:api.example.com" --san "ip:10.0.0.1" --out-key out/api.key.pem --out-csr out/api.csr.pem  # generate private key and CSR

2  ./bin/micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --template server --subject "CN=api.example.com" --san "dns:api.example.com" --san "ip:10.0.0.1" --csr out/api.csr.pem --out-dir out --db-path pki/micropki.db  # sign CSR, output cert to out/

3  openssl verify -CAfile pki_root/certs/ca.cert.pem -untrusted pki/certs/intermediate.cert.pem out/api.example.com.cert.pem  # verify chain with openssl
```

---

## 3. Issue a Client Authentication Certificate

```bash
1  ./bin/micropki client gen-csr --subject "CN=alice,O=Acme" --out-key out/alice.key.pem --out-csr out/alice.csr.pem  # generate key and CSR for client

2  ./bin/micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --template client --subject "CN=alice,O=Acme" --csr out/alice.csr.pem --out-dir out --db-path pki/micropki.db  # issue client cert (no SAN required)

3  ./bin/micropki client validate --cert out/alice.cert.pem --trusted pki_root/certs/ca.cert.pem --untrusted pki/certs/intermediate.cert.pem --mode chain  # verify the issued cert validates correctly
```

---

## 4. Issue a Code Signing Certificate

```bash
1  ./bin/micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --template code_signing --subject "CN=CI Pipeline Signer" --san "dns:ci.acme.internal" --out-dir out --db-path pki/micropki.db  # issue code signing cert (SAN required)

2  openssl dgst -sha256 -sign out/CI_Pipeline_Signer.key.pem -out artifact.sig artifact.bin  # sign a binary artifact

3  openssl dgst -sha256 -verify <(openssl x509 -in out/CI_Pipeline_Signer.cert.pem -pubkey -noout) -signature artifact.sig artifact.bin  # verify the signature
```

---

## 5. Revoke a Certificate and Update the CRL

```bash
1  SERIAL=$(openssl x509 -in out/api.example.com.cert.pem -noout -serial | cut -d= -f2 | tr A-Z a-z)  # extract hex serial from certificate

2  ./bin/micropki ca revoke "$SERIAL" --reason keyCompromise --db-path pki/micropki.db  # mark cert revoked in database

3  mkdir -p pki/crl  # ensure CRL output directory exists

4  ./bin/micropki ca gen-crl --ca intermediate --out-file pki/crl/intermediate.crl.pem --passphrase-file secrets/inter.pass --db-path pki/micropki.db --force  # regenerate CRL including new revoked entry

5  openssl crl -in pki/crl/intermediate.crl.pem -noout -text | grep -A2 "Revoked"  # confirm revoked serial appears in CRL
```

---

## 6. Emergency Key Compromise Response

```bash
1  ./bin/micropki ca compromise --cert out/compromised.cert.pem --reason keyCompromise --db-path pki/micropki.db  # revoke cert AND blacklist the public key hash

2  ./bin/micropki ca gen-crl --ca intermediate --out-file pki/crl/intermediate.crl.pem --passphrase-file secrets/inter.pass --db-path pki/micropki.db --force  # publish updated CRL immediately

3  ./bin/micropki audit query --log-file pki/audit/audit.log --operation compromise_key  # confirm the compromise event is in the audit log

4  ./bin/micropki client gen-csr --subject "CN=api.example.com" --san "dns:api.example.com" --out-key out/api-new.key.pem --out-csr out/api-new.csr.pem  # generate replacement key (old one is blacklisted)

5  ./bin/micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --template server --subject "CN=api.example.com" --san "dns:api.example.com" --csr out/api-new.csr.pem --out-dir out --db-path pki/micropki.db  # issue replacement certificate
```

---

## 7. Start All Servers (OCSP + Repo)

```bash
1  ./bin/micropki ca issue-ocsp-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --subject "CN=OCSP Responder" --san "dns:ocsp.acme.internal" --out-dir out --db-path pki/micropki.db  # issue OCSP responder certificate (one-time)

2  ./bin/micropki ocsp serve --port 8081 --db-path pki/micropki.db --ca-cert pki/certs/intermediate.cert.pem --cert out/ocsp.cert.pem --key out/ocsp.key.pem &  # start OCSP responder in background on :8081

3  ./bin/micropki repo serve --port 8080 --db-path pki/micropki.db --cert-dir pki/certs --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass &  # start HTTP repository server in background on :8080

4  curl -s http://127.0.0.1:8080/ca/intermediate -o /dev/null -w "%{http_code}"  # health-check: should return 200

5  openssl ocsp -issuer pki/certs/intermediate.cert.pem -cert out/api.example.com.cert.pem -url http://127.0.0.1:8081/ocsp -noverify  # test OCSP responder returns a response
```

---

## 8. Validate a Certificate (Offline, Chain Only)

```bash
1  ./bin/micropki client validate --cert out/api.example.com.cert.pem --trusted pki_root/certs/ca.cert.pem --untrusted pki/certs/intermediate.cert.pem --mode chain  # cryptographic chain validation, no network
```

---

## 9. Validate a Certificate (Full — CRL + OCSP)

```bash
1  ./bin/micropki client validate --cert out/api.example.com.cert.pem --trusted pki_root/certs/ca.cert.pem --untrusted pki/certs/intermediate.cert.pem --mode full --crl pki/crl/intermediate.crl.pem --ocsp  # full validation: chain + local CRL + live OCSP check
```

---

## 10. Check Revocation Status of a Single Certificate

```bash
1  ./bin/micropki client check-status --cert out/api.example.com.cert.pem --ca-cert pki/certs/intermediate.cert.pem --crl pki/crl/intermediate.crl.pem  # check via local CRL

2  ./bin/micropki client check-status --cert out/api.example.com.cert.pem --ca-cert pki/certs/intermediate.cert.pem --ocsp-url http://127.0.0.1:8081/ocsp  # check via live OCSP responder
```

---

## 11. Request a Certificate via Repo Server (Client Side)

```bash
1  ./bin/micropki client gen-csr --subject "CN=service.acme.internal" --san "dns:service.acme.internal" --out-key out/svc.key.pem --out-csr out/svc.csr.pem  # generate CSR locally

2  ./bin/micropki client request-cert --csr out/svc.csr.pem --template server --ca-url http://127.0.0.1:8080 --out-cert out/svc.cert.pem  # send CSR to repo server (requires X-API-Key: changeme)
```

---

## 12. Audit Log Verification

```bash
1  ./bin/micropki audit verify --log-file pki/audit/audit.log  # verify HMAC hash chain integrity of entire audit log

2  ./bin/micropki audit query --log-file pki/audit/audit.log --level AUDIT  # show all AUDIT-level events

3  ./bin/micropki audit query --log-file pki/audit/audit.log --operation revoke_cert  # filter by revocation events only

4  ./bin/micropki audit query --log-file pki/audit/audit.log --serial 6a255b14e8520f90  # find all events for a specific certificate serial

5  ./bin/micropki audit query --log-file pki/audit/audit.log --from "2026-01-01T00:00:00Z" --to "2026-12-31T23:59:59Z"  # query events within a date range
```

---

## 13. List and Inspect Certificates in the Database

```bash
1  ./bin/micropki ca list-certs --db-path pki/micropki.db  # list all certs (table format)

2  ./bin/micropki ca list-certs --db-path pki/micropki.db --status revoked  # show only revoked certs

3  ./bin/micropki ca list-certs --db-path pki/micropki.db --status valid --format json  # export valid certs as JSON

4  ./bin/micropki ca show-cert "$SERIAL" --db-path pki/micropki.db  # show full details for one cert by serial
```

---

## 14. Renew an Expiring Certificate

```bash
1  SERIAL=$(openssl x509 -in out/api.example.com.cert.pem -noout -serial | cut -d= -f2 | tr A-Z a-z)  # get serial of old cert

2  ./bin/micropki ca revoke "$SERIAL" --reason superseded --db-path pki/micropki.db  # revoke old cert (reason: superseded)

3  ./bin/micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --template server --subject "CN=api.example.com" --san "dns:api.example.com" --csr out/api.csr.pem --out-dir out --db-path pki/micropki.db --force  # reissue with same CSR, new serial and validity

4  ./bin/micropki ca gen-crl --ca intermediate --out-file pki/crl/intermediate.crl.pem --passphrase-file secrets/inter.pass --db-path pki/micropki.db --force  # publish updated CRL marking old cert revoked
```

---

## 15. Performance / Bulk Issuance Test

```bash
1  ./bin/micropki ca init --subject "CN=Perf Root CA" --key-type rsa --key-size 4096 --validity-days 3650 --passphrase-file secrets/root.pass --usb-path usb --out-dir perf_pki_root  # create root CA for perf test

2  ./bin/micropki ca issue-intermediate --root-cert perf_pki_root/certs/ca.cert.pem --root-key usb/ca.key.pem --root-pass-file secrets/root.pass --passphrase-file secrets/inter.pass --subject "CN=Perf Intermediate CA" --key-type rsa --key-size 3072 --validity-days 1825 --out-dir perf_pki --db-path perf_pki/micropki.db  # create intermediate CA

3  for i in $(seq 1 100); do ./bin/micropki client gen-csr --subject "CN=user$i" --out-key perf_out/user$i.key.pem --out-csr perf_out/user$i.csr.pem > /dev/null 2>&1; done  # generate 100 CSRs

4  for i in $(seq 1 100); do ./bin/micropki ca issue-cert --ca-cert perf_pki/certs/intermediate.cert.pem --ca-key perf_pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --template client --subject "CN=user$i" --csr perf_out/user$i.csr.pem --out-dir perf_out --db-path perf_pki/micropki.db > /dev/null 2>&1; done  # issue 100 certs

5  ./bin/micropki ca list-certs --db-path perf_pki/micropki.db | wc -l  # count total certs in DB
```
