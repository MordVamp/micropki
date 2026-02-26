# MicroPKI - A Minimal Public Key Infrastructure

MicroPKI is a single-handed PKI implementation demonstrating core concepts: Root CA, Intermediate CA, certificate issuance, revocation, and validation. This project is part of a multi-sprint implementation.

## Sprint 1: Root CA Foundation

This sprint implements a self-signed Root CA with secure key storage and audit logging.

### Prerequisites

- Go 1.18 or later
- Make (optional)

### Installation

Clone the repository and build the binary:

```bash
git clone 
cd micropki
make build