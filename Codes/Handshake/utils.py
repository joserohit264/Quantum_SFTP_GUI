import os
import json
import base64
from pathlib import Path
from datetime import datetime, timezone
import sys
import copy

# PQC Imports
try:
    from dilithium_py.dilithium import Dilithium2
    from kyber_py.kyber import Kyber512
except ImportError as e:
    print(f"Error: PQC libraries not found. Ensure kyber-py and dilithium-py are installed. {e}", file=sys.stderr)
    sys.exit(1)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuration (Relative to project root) ---
# Assuming Handshake/ is peer to CA/
BASE_DIR = Path(os.path.abspath(__file__)).parents[1]
CA_DIR = BASE_DIR / "CA"
CERTS_DIR = CA_DIR / "certs"
KEYS_DIR = CA_DIR / "keys"

# --- I/O Helpers ---

def generate_serial() -> str:
    """Generates a random serial number for a certificate."""
    return str(int.from_bytes(os.urandom(16), 'big'))

def load_json(filename: str, directory: Path = CERTS_DIR) -> dict:
    """Loads a JSON file from the specified directory (defaults to CA/certs)."""
    path = directory / filename
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found at {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in {path}", file=sys.stderr)
        sys.exit(1)

def _get_key_path(subject: str, is_private: bool) -> Path:
    """Constructs the path for a Dilithium key (.bin)."""
    key_type = "private" if is_private else "public"
    return KEYS_DIR / f"{subject}_{key_type}.bin"

def load_dilithium_private_key(subject: str) -> bytes:
    """Loads a Dilithium private key from keys/{subject}_private.bin."""
    path = _get_key_path(subject, is_private=True)
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Private key not found at {path}", file=sys.stderr)
        sys.exit(1)

def load_dilithium_public_key(subject: str) -> bytes:
    """Loads a Dilithium public key from keys/{subject}_public.bin."""
    path = _get_key_path(subject, is_private=False)
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Public key not found at {path}", file=sys.stderr)
        sys.exit(1)

def load_cert(filename: str) -> dict:
    """Loads a certificate JSON from CA/certs/."""
    return load_json(filename)

# --- Cryptographic Helpers ---

def serialize_for_signing(data: dict) -> bytes:
    """
    Deterministic serialization used for signing and verifying messages.
    Excludes 'Signature' and 'CA_Public_Key'.
    """
    to_sign = {k: v for k, v in data.items() if k not in ("Signature", "CA_Public_Key")}
    # Use sort_keys=True and compact separators to match ca_tool.py's serialization
    return json.dumps(to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sign_message(private_key: bytes, message: bytes) -> str:
    """Signs a message using the Dilithium private key and returns base64-encoded signature."""
    # Dilithium2.sign returns bytes
    signature = Dilithium2.sign(private_key, message)
    return base64.b64encode(signature).decode("utf-8")

def verify_signature(public_key: bytes, message: bytes, signature_b64: str) -> bool:
    """Verifies a base64-encoded signature against a message using the Dilithium public key."""
    try:
        signature = base64.b64decode(signature_b64)
        return Dilithium2.verify(public_key, message, signature)
    except Exception as e:
        print(f"Signature verification failed: {e}", file=sys.stderr)
        return False

def check_cert_validity(cert: dict) -> bool:
    """Checks if a certificate is currently within its validity period."""
    try:
        not_before = datetime.strptime(cert["Validity_Not_Before"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(cert["Validity_Not_After"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        print("Error: Certificate is missing or has an invalid date format.", file=sys.stderr)
        return False

    now = datetime.now(timezone.utc)
    if not (not_before <= now <= not_after):
        print(f"Error: Certificate is not valid at this time ({now.isoformat()}).", file=sys.stderr)
        return False
    return True

# --- Certificate Public Key Extractor ---

def get_public_key_from_cert(cert: dict) -> bytes:
    """
    Extracts the subject's Dilithium public key (bytes) from the certificate's Public_Key field (base64).
    """
    pub_b64 = cert.get("Public_Key")
    if not pub_b64:
        raise ValueError("Certificate is missing 'Public_Key' field.")
    
    try:
        return base64.b64decode(pub_b64)
    except Exception as e:
        raise ValueError(f"Failed to decode public key from certificate: {e}")

def calculate_transcript_hash(client_hello: dict, server_hello: dict, client_key_share: dict) -> bytes:
    """
    Calculates the SHA256 hash over the deterministic serialization of the core 
    handshake messages to create the 'transcript_hash'.
    """
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    
    # Define clean_cert internally for local use
    def _clean_cert(cert: dict) -> dict:
        cleaned = cert.copy()
        cleaned.pop("Signature", None)
        cleaned.pop("CA_Public_Key", None)
        return cleaned

    messages_to_process = [
        ("ClientHello", client_hello), 
        ("ServerHello", server_hello), 
        ("ClientKeyShare", client_key_share)
    ]

    print("\n--- DEBUG: Transcript Hash Calculation ---")
    
    for name, msg in messages_to_process:
        msg_copy = copy.deepcopy(msg)
        
        # 1. Clean top-level handshake signature
        msg_copy.pop("Signature", None)
        
        # 2. Clean nested certificates
        if "client_cert" in msg_copy:
            msg_copy["client_cert"] = _clean_cert(msg_copy["client_cert"])
        if "server_cert" in msg_copy:
            msg_copy["server_cert"] = _clean_cert(msg_copy["server_cert"])

        # Create the serialized byte stream
        serialized_data = serialize_for_signing(msg_copy)
        
        # Update main transcript hash
        h.update(serialized_data)

    print("--- END DEBUG ---\n")
    return h.finalize()
        
def derive_session_key(shared_key: bytes, client_nonce: str, server_nonce: str, transcript_hash: bytes) -> bytes:
    """
    Derives the session key using HKDF-SHA256.
    K_s = HKDF(Shared_Key, client_nonce, server_nonce, transcript_hash)
    """
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    
    # Concatenate salt (nonces) and info (transcript hash) with the shared key
    # Note: In a real HKDF, salt and info are separate. Here we mix them into the input for simplicity/prototype.
    info = transcript_hash + client_nonce.encode('utf-8') + server_nonce.encode('utf-8')
    
    h.update(shared_key + info)
    
    return h.finalize()

def clean_cert(cert: dict) -> dict:
    """Removes CA-specific signing fields (Signature, CA_Public_Key) recursively."""
    cleaned = cert.copy()
    cleaned.pop("Signature", None)
    cleaned.pop("CA_Public_Key", None)
    return cleaned

# --- Encryption Helpers ---

def encrypt_data(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts data using AES-GCM.
    Returns (nonce, ciphertext). Tag is included in ciphertext by AESGCM.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts data using AES-GCM.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
