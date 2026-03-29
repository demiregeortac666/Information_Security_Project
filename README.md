# TrustVerify

A Python CLI tool for file integrity verification and digital signatures using SHA-256 and RSA.

**Team Argus** | Demir Ege Ortac 230208045 | Yunus Emre Varol 230208028
OSTIM Technical University | Mini Project I | 2025-2026

---

## Requirements
```bash
pip install cryptography
```

---

## Usage

Set `FILES_PATH` and `BASE_PATH` in `trustverify.py`, then call the functions:
```python
generate_keys()                  # Generate RSA key pair (run once)
generate_manifest(FILES_PATH)    # Create manifest.json
check_integrity(FILES_PATH)      # Detect tampered files
sign()                           # Sign the manifest with private key
verify()                         # Verify signature with public key
```

---

## Libraries

- `hashlib` — SHA-256 hashing
- `cryptography` — RSA signing and verification
