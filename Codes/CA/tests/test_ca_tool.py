import os
import subprocess
import json
import tempfile
import shutil
import pytest
from pathlib import Path
from datetime import datetime, timedelta, timezone

CA_TOOL = os.path.abspath("ca_tool.py")

@pytest.fixture
def temp_env(tmp_path):
    """Setup isolated environment with keys/ and certs/ inside tmp_path."""
    cwd = tmp_path
    os.chdir(cwd)
    os.mkdir("keys")
    os.mkdir("certs")
    yield cwd
    os.chdir("/")  # cleanup working dir


def run_cmd(args, check=True):
    """Helper to run CLI command and capture output."""
    result = subprocess.run(
        ["python", CA_TOOL] + args,
        capture_output=True,
        text=True
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {args}\n{result.stderr}")
    return result


def test_full_flow_valid(temp_env):
    """End-to-end: gen-keys -> CSR -> sign -> verify (success)."""
    run_cmd(["gen-keys", "CA"])
    run_cmd(["gen-keys", "Client"])

    run_cmd(["init-csr", "client_csr.json", "--subject", "Client"])
    csr_path = "certs/client_csr.json"
    assert os.path.exists(csr_path)

    run_cmd(["sign", "client_csr.json", "client_cert.json"])
    cert_path = "certs/client_cert.json"
    assert os.path.exists(cert_path)

    result = run_cmd(["verify", "client_cert.json"])
    assert "VALID" in result.stdout


def test_signature_tamper(temp_env):
    """Tampering with Subject should fail verification."""
    run_cmd(["gen-keys", "CA"])
    run_cmd(["gen-keys", "Client"])
    run_cmd(["init-csr", "client_csr.json", "--subject", "Client"])
    run_cmd(["sign", "client_csr.json", "client_cert.json"])

    # Load and tamper
    cert_path = "certs/client_cert.json"
    cert = json.load(open(cert_path))
    cert["Subject"] = "Mallory"
    json.dump(cert, open(cert_path, "w"), indent=2)

    result = run_cmd(["verify", "client_cert.json"], check=False)
    assert "FAILED" in result.stdout


def test_signature_corruption(temp_env):
    """Corrupting signature must fail verification."""
    run_cmd(["gen-keys", "CA"])
    run_cmd(["gen-keys", "Client"])
    run_cmd(["init-csr", "client_csr.json", "--subject", "Client"])
    run_cmd(["sign", "client_csr.json", "client_cert.json"])

    cert_path = "certs/client_cert.json"
    cert = json.load(open(cert_path))
    cert["Signature"] = "AAAAA"  # invalid base64
    json.dump(cert, open(cert_path, "w"), indent=2)

    result = run_cmd(["verify", "client_cert.json"], check=False)
    out = result.stdout.lower()
    assert "failed" in out or "error" in out


def test_expired_cert(temp_env):
    """Expired certificate should fail."""
    run_cmd(["gen-keys", "CA"])
    run_cmd(["gen-keys", "Client"])
    run_cmd(["init-csr", "expired_csr.json", "--subject", "Client"])
    
    csr_path = "certs/expired_csr.json"
    csr = json.load(open(csr_path))
    now = datetime.now(timezone.utc)
    csr["Validity_Not_Before"] = (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    csr["Validity_Not_After"] = (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    json.dump(csr, open(csr_path, "w"), indent=2)

    run_cmd(["sign", "expired_csr.json", "expired_cert.json"])
    result = run_cmd(["verify", "expired_cert.json"], check=False)
    assert "not valid" in result.stdout.lower()

def test_invalid_json(temp_env):
    """Malformed JSON should fail verification."""
    run_cmd(["gen-keys", "CA"])
    bad_cert = Path("certs/bad.json")
    bad_cert.write_text("{not-valid-json}")
    result = run_cmd(["verify", "bad.json"], check=False)
    assert "Invalid JSON format" in result.stdout or "Failed to load JSON" in result.stdout

def test_wrong_ca_key(temp_env):
    """Using mismatched CA key must fail verification."""
    run_cmd(["gen-keys", "CA"])
    run_cmd(["gen-keys", "Client"])
    run_cmd(["init-csr", "client_csr.json", "--subject", "Client"])
    run_cmd(["sign", "client_csr.json", "client_cert.json"])

    # Replace CA_public.pem with a fake one (note: KEYS_DIR, not certs/)
    run_cmd(["gen-keys", "FakeCA"])
    os.replace("keys/FakeCA_public.pem", "keys/CA_public.pem")  # <-- FIX 2

    result = run_cmd(["verify", "client_cert.json"], check=False)
    assert "FAILED" in result.stdout

def test_future_dated_cert(temp_env):
    """Certificate not yet valid must be rejected."""
    run_cmd(["gen-keys", "CA"])
    run_cmd(["gen-keys", "Client"])
    run_cmd(["init-csr", "client_csr.json", "--subject", "Client"])
    run_cmd(["sign", "client_csr.json", "client_cert.json"])

    cert_path = Path("certs/client_cert.json")
    cert = json.loads(cert_path.read_text())
    cert["Validity_Not_Before"] = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cert_path.write_text(json.dumps(cert, indent=2))

    result = run_cmd(["verify", "client_cert.json"], check=False)
    assert "not valid at this time" in result.stdout

def test_key_generation(temp_env):
    """Ensure gen-keys creates a valid keypair."""
    run_cmd(["gen-keys", "TestCA"])

    keys_dir = Path("keys")
    key_files = list(keys_dir.glob("TestCA_*pem"))

    # Ensure both private and public exist
    priv_candidates = [f for f in key_files if "private" in f.name]
    pub_candidates = [f for f in key_files if "public" in f.name]

    assert priv_candidates, "Private key file not generated"
    assert pub_candidates, "Public key file not generated"

    from cryptography.hazmat.primitives import serialization
    priv = serialization.load_pem_private_key(priv_candidates[0].read_bytes(), password=None)
    pub = serialization.load_pem_public_key(pub_candidates[0].read_bytes())

    assert priv.key_size >= 2048
    assert pub.key_size == priv.key_size
