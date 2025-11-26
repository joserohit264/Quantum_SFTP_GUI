# Certificate Authority (CA) Tool – Test Suite

This repository contains unit tests for the **CA Tool**, which implements a minimal custom certificate authority and verification logic.  
The tests validate core certificate operations such as signing, verification, and handling of invalid certificates.

---

## 🧪 Test Coverage

The test file [`tests/test_ca_tool.py`](tests/test_ca_tool.py) covers the following scenarios:

1. **Valid Flow**
   - `test_full_flow_valid`: Generates a CA key pair, signs a certificate, and verifies successfully.

2. **Tampering Cases**
   - `test_signature_tamper`: Ensures detection of certificates with tampered signatures.
   - `test_signature_corruption`: Ensures corrupted certificates fail verification.

3. **Validity Period Checks**
   - `test_expired_cert`: Rejects expired certificates.
   - `test_future_dated_cert`: Rejects certificates that are not yet valid.

4. **Error Handling**
   - `test_invalid_json`: Rejects malformed certificate files with an explicit `Invalid JSON format` error.
   - `test_wrong_ca_key`: Detects verification attempts with mismatched CA public keys.

5. **Key Generation**
   - `test_key_generation`: Ensures the `gen-keys` command creates both private and public RSA key files correctly.

---

## ▶️ Running the Tests

1. Activate your Python environment:
   ```bash
   source py_env/bin/activate
   ```

2. Run the full test suite:
   ```bash
   pytest -v
   ```

   Example output:
   ```bash
   collected 8 items

   tests/test_ca_tool.py::test_full_flow_valid PASSED
   tests/test_ca_tool.py::test_signature_tamper PASSED
   tests/test_ca_tool.py::test_signature_corruption PASSED
   tests/test_ca_tool.py::test_expired_cert PASSED
   tests/test_ca_tool.py::test_invalid_json PASSED
   tests/test_ca_tool.py::test_wrong_ca_key PASSED
   tests/test_ca_tool.py::test_future_dated_cert PASSED
   tests/test_ca_tool.py::test_key_generation PASSED
   ```

## ⚠️ Notes

- Certificates are stored under the `certs/` directory during test execution.
- Keys are generated in the `keys/` directory using the built-in Python `cryptography` library.
- Date validity checks currently use `datetime.utcnow()`. Consider migrating to timezone-aware objects in the future to avoid deprecation warnings.

## 📂 Project Structure

```
Codes/CA/
├── ca_tool.py          # Main CA tool (key generation, signing, verification)
├── tests/
│   └── test_ca_tool.py # Test suite
├── certs/              # Temporary certificate storage (created during tests)
└── keys/               # RSA key storage
```

## ✅ Summary

This test suite ensures that the CA Tool:

- Correctly generates and verifies certificates,
- Detects tampering and invalid data,
- Enforces validity periods,
- Handles malformed or mismatched certificates gracefully,
- Generates valid RSA key pairs for both CA and clients.
