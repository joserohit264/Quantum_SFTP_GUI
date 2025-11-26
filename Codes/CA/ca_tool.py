#!/usr/bin/env python3
"""
ca_tool.py - Simple robust local Certificate Authority CLI (PQC Version)

Features:
 - gen-keys <subject>         -> keys/<subject>_private.bin, keys/<subject>_public.bin (Dilithium2)
 - init-csr <out.json> --subject <Name>
                             -> certs/<out.json> containing CSR (public key in base64)
 - sign <csr.json> <cert.json> -> CA (keys/CA_private.bin) signs CSR -> certificate JSON (adds CA_Public_Key + Signature)
 - verify <cert.json> [--pretty] -> Verify certificate; prefer pinned keys/CA_public.bin
Notes:
 - All keys and signatures stored as base64 inside JSON.
 - Uses deterministic JSON serialization (sorted keys, compact separators) excluding 'Signature' and 'CA_Public_Key' when signing.
"""
import argparse, base64, json, os, sys, time, uuid
from datetime import datetime, timedelta, timezone

# PQC Imports
try:
    from dilithium_py.dilithium import Dilithium2
except ImportError as e:
    print(f"Error: PQC libraries not found. Ensure dilithium-py is installed. {e}", file=sys.stderr)
    sys.exit(1)

# -------------------- Configuration --------------------
KEYS_DIR = "keys"
CERTS_DIR = "certs"

# -------------------- Utilities --------------------
def ensure_dirs():
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(CERTS_DIR, exist_ok=True)

def save_json(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=4)
    print(f"Saved JSON to {path}")

def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load JSON from {path}: {e}")
        sys.exit(1)

def _serialize_for_signing(data: dict) -> bytes:
    """
    Deterministic serialization used for signing and verifying.
    Excludes 'Signature' and 'CA_Public_Key' fields.
    """
    to_sign = {k: v for k, v in data.items() if k not in ("Signature", "CA_Public_Key")}
    return json.dumps(to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Pretty helpers
def _loading(msg: str, dots: int = 3, delay: float = 0.18):
    sys.stdout.write(msg)
    sys.stdout.flush()
    for _ in range(dots):
        time.sleep(delay)
        sys.stdout.write(".")
        sys.stdout.flush()
    print()

# -------------------- Key functions --------------------
def gen_keys(subject: str):
    """Generate Dilithium2 keypair and save under keys/ as binary files."""
    ensure_dirs()
    subj = subject.replace(" ", "_")
    priv_path = os.path.join(KEYS_DIR, f"{subj}_private.bin")
    pub_path = os.path.join(KEYS_DIR, f"{subj}_public.bin")

    pk, sk = Dilithium2.keygen()
    
    with open(priv_path, "wb") as f:
        f.write(sk)
    with open(pub_path, "wb") as f:
        f.write(pk)

    print(f"Keys generated: {priv_path}, {pub_path}")

def _load_public_bin(subject: str) -> bytes:
    path = os.path.join(KEYS_DIR, f"{subject}_public.bin")
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Public key not found: {path} (run: gen-keys {subject})")
        sys.exit(1)

def _load_ca_private_key() -> bytes:
    path = os.path.join(KEYS_DIR, "CA_private.bin")
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"CA private key not found: {path} (run: gen-keys CA)")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to load CA private key: {e}")
        sys.exit(1)

# -------------------- CSR functions --------------------
def init_csr(output_filename: str, subject: str = "Client", validity_days: int = 365, serial: str = None):
    ensure_dirs()
    pub_bytes = _load_public_bin(subject)
    pub_b64 = base64.b64encode(pub_bytes).decode("utf-8")

    if serial is None:
        serial = uuid.uuid4().hex

    now = datetime.now(timezone.utc)
    csr = {
        "Version": 1,
        "Serial_Number": str(serial),
        "Signature_Algorithm": "Dilithium2",
        "Issuer": "CA_Name",
        "Validity_Not_Before": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Validity_Not_After": (now + timedelta(days=validity_days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Subject": subject,
        "Public_Key": pub_b64,   # base64
        "Key_Algorithm": "Dilithium2",
    }

    out_path = os.path.join(CERTS_DIR, output_filename)
    save_json(csr, out_path)
    print(f"CSR initialized for '{subject}' -> {out_path}")

# -------------------- Signing functions --------------------
def sign_csr(csr_path: str, cert_path: str):
    ensure_dirs()
    csr_full = os.path.join(CERTS_DIR, csr_path)
    cert_full = os.path.join(CERTS_DIR, cert_path)

    csr = load_json(csr_full)
    if csr.get("Signature"):
        print("Input CSR already contains 'Signature' field. Aborting.")
        sys.exit(1)

    ca_priv = _load_ca_private_key()
    # Add CA_Public_Key after signing, but compute message from CSR fields (serialize excludes CA_Public_Key)
    message = _serialize_for_signing(csr)
    
    signature = Dilithium2.sign(ca_priv, message)
    sig_b64 = base64.b64encode(signature).decode("utf-8")

    # Attach CA public key base64 (from keys/CA_public.bin)
    ca_pub_path = os.path.join(KEYS_DIR, "CA_public.bin")
    try:
        with open(ca_pub_path, "rb") as f:
            ca_pub_bytes = f.read()
    except FileNotFoundError:
        print(f"CA public key not found: {ca_pub_path} (run: gen-keys CA)")
        sys.exit(1)

    ca_pub_b64 = base64.b64encode(ca_pub_bytes).decode("utf-8")

    certificate = csr.copy()
    certificate["CA_Public_Key"] = ca_pub_b64
    certificate["Signature"] = sig_b64

    save_json(certificate, cert_full)
    print(f"Certificate created: {cert_full}")

# -------------------- Verification functions --------------------
def verify_certificate(cert_path: str, pretty: bool = True) -> bool:
    cert_full = os.path.join(CERTS_DIR, cert_path)
    cert = load_json(cert_full)

    def fail(msg: str):
        print(msg)
        return False

    if pretty:
        print("\nStarting certificate verification...\n")

    # Basic field checks
    if cert.get("Version") != 1:
        return fail("Unsupported Version (expected 1)")

    if not cert.get("Serial_Number"):
        return fail("Invalid certificate: empty Serial Number")

    if cert.get("Signature_Algorithm") != "Dilithium2" or cert.get("Key_Algorithm") != "Dilithium2":
        return fail(f"Unsupported algorithms (Signature: {cert.get('Signature_Algorithm')}, Key: {cert.get('Key_Algorithm')})")

    # Validity
    try:
        not_before = datetime.strptime(cert["Validity_Not_Before"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(cert["Validity_Not_After"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception as e:
        return fail(f"Invalid date format in certificate: {e}")

    now = datetime.now(timezone.utc)
    if pretty:
        _loading("Checking validity")
    if not (not_before <= now <= not_after):
        return fail(f"Certificate not valid at this time ({now.isoformat()}); valid window: {cert['Validity_Not_Before']} -> {cert['Validity_Not_After']}")

    # Determine CA public key to use: prefer pinned local keys/CA_public.bin
    ca_public_key_bytes = None
    ca_source = None
    pinned_ca_path = os.path.join(KEYS_DIR, "CA_public.bin")
    if os.path.exists(pinned_ca_path):
        try:
            with open(pinned_ca_path, "rb") as f:
                ca_public_key_bytes = f.read()
            ca_source = f"pinned {pinned_ca_path}"
        except Exception as e:
            return fail(f"Failed to load pinned CA public key: {e}")
    else:
        # fallback to embedded CA_Public_Key (base64) in cert
        ca_b64 = cert.get("CA_Public_Key")
        if not ca_b64:
            return fail("No CA public key found (neither pinned nor embedded).")
        try:
            ca_public_key_bytes = base64.b64decode(ca_b64)
            ca_source = "embedded in certificate"
        except Exception as e:
            return fail(f"Failed to parse embedded CA public key: {e}")

    if pretty:
        _loading("Using CA public key", dots=2)
        print(f"Using CA public key from: {ca_source}")

    # Signature verification
    if pretty:
        _loading("Verifying signature", dots=4)
    sig_b64 = cert.get("Signature")
    if not sig_b64:
        return fail("Certificate missing Signature")

    try:
        signature = base64.b64decode(sig_b64)
    except Exception as e:
        return fail(f"Failed to decode Signature (base64): {e}")

    # Rebuild the message deterministically (must exclude Signature and CA_Public_Key)
    message = _serialize_for_signing(cert)

    try:
        valid = Dilithium2.verify(ca_public_key_bytes, message, signature)
        if not valid:
             return fail("Signature verification FAILED: Invalid signature")
    except Exception as e:
        return fail(f"Signature verification FAILED: {e}")

    if pretty:
        print("\nCertificate verification complete — all checks passed!\n")
    else:
        print("Certificate is VALID")

    return True

# -------------------- CLI --------------------
def main():
    ensure_dirs()
    parser = argparse.ArgumentParser(description="Quantum-resistant CA CLI Tool (Dilithium2)")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    p_gen = subparsers.add_parser("gen-keys", help="Generate Dilithium2 keypair stored in keys/")
    p_gen.add_argument("subject", help="Subject name (CA, Client, Server, etc.)")
    
    p_init = subparsers.add_parser("init-csr", help="Create CSR JSON using <subject>_public.bin from keys/")
    p_init.add_argument("out", help="Output CSR filename (saved under certs/)")
    p_init.add_argument("--subject", default="Client", help="Subject whose public key will be embedded (default: Client)")
    p_init.add_argument("--days", type=int, default=365, help="Validity window days (default: 365)")
    p_init.add_argument("--serial", default=None, help="Optional serial (default: random UUID hex)")

    p_sign = subparsers.add_parser("sign", help="Sign CSR (certs/<csr>) with CA private key (keys/CA_private.bin)")
    p_sign.add_argument("csr", help="CSR filename in certs/")
    p_sign.add_argument("cert", help="Output certificate filename in certs/")

    p_verify = subparsers.add_parser("verify", help="Verify certificate JSON in certs/")
    p_verify.add_argument("cert", help="Certificate filename in certs/")
    p_verify.add_argument("--pretty", action="store_true", help="Pretty step-by-step output")

    args = parser.parse_args()

    if args.cmd == "gen-keys":
        gen_keys(args.subject)
    elif args.cmd == "init-csr":
        init_csr(args.out, subject=args.subject, validity_days=args.days, serial=args.serial)
    elif args.cmd == "sign":
        sign_csr(args.csr, args.cert)
    elif args.cmd == "verify":
        ok = verify_certificate(args.cert, pretty=args.pretty)
        if not ok:
            sys.exit(2)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
