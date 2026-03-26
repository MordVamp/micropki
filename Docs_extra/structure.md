# MicroPKI Directory Structure

The repository is modularized natively by Go package responsibilities representing an active Enterprise microservices architecture:

```text
micropki/
├── cmd/
│   └── micropki/           # Main Cobra CLI entrypoint housing all subcommands (ca, client, repo, ocsp, audit, db)
├── internal/
│   ├── audit/              # Cryptographic NDJSON hash chain logger & CT simulator (Sprint 7)
│   ├── ca/                 # Certificate Authority engine (Init, Issue, Revoke, Compromise, CRL)
│   ├── certs/              # X.509 core template generation utilities
│   ├── client/             # Client-side validation engines, CSR builders, and OCSP requests
│   ├── crl/                # Certificate Revocation List native builders
│   ├── crypto/             # Cryptographic primitive helpers (RSA, ECC, SKI, AES wrappers)
│   ├── database/           # SQLite backing ledger enforcing constraints and tracking compromises
│   ├── logger/             # Standard CLI formatted logging handler
│   ├── ocsp/               # Real-time HTTP responder engine parsing RFC 6960 requests
│   ├── policy/             # Policy engine preventing weak keys, excessive validities, and wildcards
│   ├── ratelimit/          # Token Bucket rate limiter protecting repo & ocsp web servers
│   ├── repository/         # HTTP repository serving CA certs, CRLs, and dynamic issuance endpoints
│   ├── serial/             # Cryptographically secure random serial number generator
│   └── templates/          # EKU/KU mapping engine (server, client, code_signing profiles)
├── demo.sh                 # Fully automated E2E Sprint 1-8 evaluation script testing code-signing & audits
├── perf_test.sh            # High-volume execution script measuring database IO throughput
├── NOOB_GUIDE.md           # Beginner instruction manual to manually operate CA nodes
├── README.md               # Master architecture and technical overview documentation
├── go.mod                  # Go module definition
└── structure.md            # This file
```