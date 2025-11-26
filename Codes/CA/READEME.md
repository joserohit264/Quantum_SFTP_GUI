# Simple Robust Local Certificate Authority CLI

`ca_tool.py` is a minimal yet robust command-line tool for managing a local Certificate Authority (CA) workflow. It allows you to generate RSA keys, create Certificate Signing Requests (CSRs), sign CSRs to produce certificates, and verify certificates — all using JSON-based formats with base64-encoded keys and signatures.

---

## Features

- **gen-keys `<subject>`**  
  Generate an RSA key pair (`<subject>_private.pem`, `<subject>_public.pem`) stored in `keys/`.

- **init-csr `<out.json>` --subject `<Name>`**  
  Create a CSR JSON file (`certs/<out.json>`) embedding the subject's public key in base64 DER.

- **sign `<csr.json>` `<cert.json>`**  
  Use the CA private key (`keys/CA_private.pem`) to sign a CSR, producing a certificate JSON file (`certs/<cert.json>`) that includes the CA public key and signature.

- **verify `<cert.json>` [--pretty]**  
  Verify a certificate's validity, signature, and timestamps. Uses pinned CA keys (`keys/CA_public.pem`) if available.

---

## Requirements

- Python 3.7+
- [cryptography](https://cryptography.io/en/latest/) package

Install dependencies with:

```bash
pip install cryptography
```

## Installation

Clone the repository or download the `ca_tool.py` script directly.

Make sure you have write permissions in the working directory, as the tool creates `keys/` and `certs/` directories.

## Usage

All commands create/read files under `keys/` and `certs/` directories respectively.

### Generate RSA Keys

```bash
./ca_tool.py gen-keys <subject> [--size 2048]
```

Example:

```bash
./ca_tool.py gen-keys CA
./ca_tool.py gen-keys Client
```

### Initialize a CSR

Creates a CSR JSON file embedding the public key of `<subject>`.

```bash
./ca_tool.py init-csr <out.json> --subject <Name> [--days 365] [--serial <serial>]
```

Example:

```bash
./ca_tool.py init-csr client1_csr.json --subject Client --days 365
```

### Sign a CSR

Sign a CSR JSON using the CA's private key.

```bash
./ca_tool.py sign <csr.json> <cert.json>
```

Example:

```bash
./ca_tool.py sign client1_csr.json client1_cert.json
```

### Verify a Certificate

Verify the signature and validity period of a certificate JSON.

```bash
./ca_tool.py verify <cert.json> [--pretty]
```

Example:

```bash
./ca_tool.py verify client1_cert.json --pretty
```

## Notes

- Keys and signatures are stored as base64 within JSON for portability.
- Deterministic JSON serialization is used for signing and verifying to avoid signature mismatches.
- The CA key pair (`CA_private.pem` and `CA_public.pem`) must be generated first before signing certificates.
- You can customize RSA key sizes via the `--size` flag on `gen-keys`.
