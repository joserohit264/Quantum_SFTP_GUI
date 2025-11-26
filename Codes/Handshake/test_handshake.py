import pytest
import subprocess
import os
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
import base64
import copy
# Add the parent directory to the path to import utils
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))

# Import the code we are testing
from handshake_client import ClientHandshakeState
import utils

# --- Configuration ---
# Path to the ca_tool.py executable
CA_TOOL = str(Path("../CA/ca_tool.py").resolve())
# Path to the CA directory, which is the expected working directory for ca_tool.py
CA_TOOL_DIR = Path("../CA/").resolve() 

TEST_SUBJECT = "TestClient"
TEST_CERT_FILE = "test_client_cert.json"

@pytest.fixture(scope="session", autouse=True)
def setup_ca_keys():
    """
    Fixture to ensure CA and Client keys/certs exist before tests run.
    FIXED: Now synchronizes LIVE keys (Client, Server) after CA key is regenerated.
    """
    print("\n--- CA Setup Fixture Running ---")

    # Ensure keys/ and certs/ exist in the CA directory (already done by utils import, but safe to keep)
    utils.CA_DIR.mkdir(exist_ok=True)
    utils.KEYS_DIR.mkdir(exist_ok=True)
    utils.CERTS_DIR.mkdir(exist_ok=True)

    def run_ca_cmd(args):
        try:
            result = subprocess.run(
                ["python", CA_TOOL] + args,
                capture_output=True,
                text=True,
                check=True,
                # --- FIX: Change the current working directory for the subprocess ---
                cwd=CA_TOOL_DIR 
                # ------------------------------------------------------------------
            )
            return result
        except subprocess.CalledProcessError as e:
            print(f"CA Command failed: {args}\nStdout: {e.stdout}\nStderr: {e.stderr}", file=sys.stderr)
            raise

    # 1. Generate CA keys (OVERWRITES LIVE CA KEY)
    run_ca_cmd(["gen-keys", "CA"])
    
    # --- SYNCHRONIZATION: Ensure all LIVE keys/certs are valid against the NEW CA key ---
    
    # 2. Re-synchronize LIVE Client keys/certs
    run_ca_cmd(["gen-keys", "Client"]) # Regenerate Client keypair
    run_ca_cmd(["init-csr", "client_csr.json", "--subject", "Client"])
    run_ca_cmd(["sign", "client_csr.json", "client_cert.json"]) # Re-sign with new CA key

    # 3. Re-synchronize LIVE Server keys/certs
    run_ca_cmd(["gen-keys", "Server"]) # Regenerate Server keypair
    run_ca_cmd(["init-csr", "server_csr.json", "--subject", "Server"])
    run_ca_cmd(["sign", "server_csr.json", "server_cert.json"]) # Re-sign with new CA key

    # --- Test Keys Setup (This ensures the unit tests use a clean set) ---
    
    TEST_SUBJECT = "TestClient" # Assuming this constant is defined globally in the file
    TEST_CERT_FILE = "test_client_cert.json"

    run_ca_cmd(["gen-keys", TEST_SUBJECT])
    run_ca_cmd(["init-csr", TEST_CERT_FILE, "--subject", TEST_SUBJECT])
    run_ca_cmd(["sign", TEST_CERT_FILE, TEST_CERT_FILE])

    print("--- CA Setup Fixture Complete ---")

def test_client_hello_generation(setup_ca_keys):
    """
    Test Phase 1.3: Verifies that ClientHandshakeState correctly generates the ClientHello message
    with all required fields (cert, nonce, timestamp).
    """
    
    # 1. Initialize the Client Handshake State
    client_state = ClientHandshakeState(TEST_CERT_FILE, TEST_SUBJECT)

    # 2. Generate the ClientHello Message
    client_hello = client_state.generate_client_hello()

    # 3. Verification Checks
    
    # a. Check high-level structure
    assert client_hello["Type"] == "ClientHello"
    assert "CipherSuite" in client_hello
    
    # b. Check client state attributes are saved
    assert client_state.client_nonce is not None
    assert client_state.client_timestamp is not None
    
    # c. Check message contains state attributes
    assert client_hello["client_nonce"] == client_state.client_nonce
    assert client_hello["client_timestamp"] == client_state.client_timestamp
    
    # d. Check timestamp format and plausibility
    try:
        dt = datetime.strptime(client_hello["client_timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        # Corrected line: use timedelta directly (or datetime.timedelta if only datetime was imported)
        assert datetime.now(timezone.utc) - dt < timedelta(seconds=5) 
    except ValueError:
        pytest.fail("Client timestamp is not in the required ISO format.")

    # e. Check certificate presence and subject
    cert = client_hello["client_cert"]
    assert isinstance(cert, dict)
    assert cert["Subject"] == TEST_SUBJECT
    assert "Public_Key" in cert


def test_loaded_key_and_cert_match():
    """
    Verifies that the private key loaded by the ClientHandshakeState matches the public key
    embedded in the loaded certificate (RSA key pair consistency check).
    """
    client_state = ClientHandshakeState(TEST_CERT_FILE, TEST_SUBJECT)

    # 1. Get Public Key from the loaded Private Key object
    private_key_pub = client_state.private_key.public_key()
    
    # 2. Get Public Key from the loaded Certificate object
    cert_pub = utils.get_public_key_from_cert(client_state.cert)
    
    # 3. Compare the modulus and exponent (core of RSA public key)
    private_key_pub_nums = private_key_pub.public_numbers()
    cert_pub_nums = cert_pub.public_numbers()

    assert private_key_pub_nums.n == cert_pub_nums.n, "Public key modulus (n) mismatch"
    assert private_key_pub_nums.e == cert_pub_nums.e, "Public key exponent (e) mismatch"

# ... (existing code, ensure setup_ca_keys fixture is updated and works) ...

from handshake_server import ServerHandshakeState 
import utils
import uuid

# New configurations for Server
TEST_SERVER_SUBJECT = "Server"
TEST_SERVER_CERT_FILE = "test_server_cert.json"

@pytest.fixture(scope="session")
def setup_server_keys(setup_ca_keys):
    """
    Extends setup to ensure Server keys/certs exist.
    We need to call ca_tool.py from the CA directory again.
    """
    print("\n--- Server Setup Fixture Running ---")
    CA_TOOL = str(Path("../CA/ca_tool.py").resolve())
    CA_TOOL_DIR = Path("../CA/").resolve() 

    def run_ca_cmd(args):
        try:
            subprocess.run(
                ["python", CA_TOOL] + args,
                capture_output=True,
                text=True,
                check=True,
                cwd=CA_TOOL_DIR 
            )
        except subprocess.CalledProcessError as e:
            print(f"CA Command failed: {args}\nStdout: {e.stdout}\nStderr: {e.stderr}", file=sys.stderr)
            raise

    # 1. Generate Server keys
    run_ca_cmd(["gen-keys", TEST_SERVER_SUBJECT])

    # 2. Create CSR
    run_ca_cmd(["init-csr", TEST_SERVER_CERT_FILE, "--subject", TEST_SERVER_SUBJECT])

    # 3. Sign the CSR
    run_ca_cmd(["sign", TEST_SERVER_CERT_FILE, TEST_SERVER_CERT_FILE])

    print("--- Server Setup Fixture Complete ---")

# We need a mock ClientHello message to test the ServerHello generation
def create_mock_client_hello() -> dict:
    """Creates a basic mock ClientHello message with a valid, clean certificate structure."""
    client_cert = utils.load_cert(TEST_CERT_FILE)
    
    # FIX: Use the global utility to clean the cert BEFORE it goes into the mock message
    clean_client_cert = utils.clean_cert(client_cert)
    
    # Use a recent timestamp to pass freshness check
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    return {
        "Type": "ClientHello",
        "client_cert": clean_client_cert,  # <--- INSERT CLEANED CERT
        "client_nonce": uuid.uuid4().hex,
        "client_timestamp": ts,
        "CipherSuite": "RSA_DH_SHA256_PROTOTYPE"
    }

def test_server_hello_generation_and_signature_validity(setup_server_keys):
    """
    Test Phase 1.4: Server receives a valid ClientHello, generates a ServerHello,
    and the resulting server signature is cryptographically valid.
    """
    
    # 1. Setup Server State and Mock ClientHello
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    mock_client_hello = create_mock_client_hello()
    
    # Set the client_hello on the server state (as the server would after verification)
    server_state.verify_client_hello(mock_client_hello)
    
    # 2. Generate ServerHello
    server_hello = server_state.generate_server_hello()

    # 3. Verification Checks
    
    # a. Check high-level structure
    assert server_hello["Type"] == "ServerHello"
    assert "Signature" in server_hello
    assert "server_cert" in server_hello
    assert "dh_public_key" in server_hello
    assert "dh_params" in server_hello
    
    # b. Verify the Server's own signature
    sig_server_b64 = server_hello.pop("Signature") # Remove sig for deterministic serialization
    
    # Recreate the message the server signed (which is the server_hello minus sig)
    message_signed = utils.serialize_for_signing(server_hello)
    
    # The public key to verify against is the one embedded in the server_cert
    server_pub_key = utils.get_public_key_from_cert(server_hello["server_cert"])

    # 4. Final signature check
    is_valid = utils.verify_signature(server_pub_key, message_signed, sig_server_b64)
    
    assert is_valid, "Server signature verification failed! The ServerHello message is invalidly signed."

# ... (after test_server_hello_generation_and_signature_validity) ...

def test_server_rejects_expired_client_hello(setup_server_keys):
    """
    Test Phase 1.4: Verifies the server rejects a ClientHello containing an expired certificate.
    """
    
    # 1. Setup Server State
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    
    # 2. Create a ClientHello based on a tampered (expired) certificate
    expired_cert = utils.load_cert(TEST_CERT_FILE)
    
    # Set the 'Not_After' date to a time in the past
    past_date = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expired_cert["Validity_Not_After"] = past_date
    
    mock_client_hello_expired = {
        "Type": "ClientHello",
        "client_cert": expired_cert,
        "client_nonce": uuid.uuid4().hex,
        "client_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "CipherSuite": "RSA_DH_SHA256_PROTOTYPE" 
    }

    # 3. Attempt verification (should fail)
    is_valid = server_state.verify_client_hello(mock_client_hello_expired)
    
    assert not is_valid, "Server failed to reject an expired client certificate."


def test_server_signature_fails_if_client_nonce_tampered(setup_server_keys):
    """
    Test Phase 1.4: Ensures the server's signature is bound to the ClientHello content 
    (specifically the nonce). Tampering the nonce after signing should invalidate the signature.
    """
    # 1. Setup Server State and Mock ClientHello
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    mock_client_hello = create_mock_client_hello()
    
    # 2. Server processes and signs the valid ClientHello
    server_state.verify_client_hello(mock_client_hello)
    server_hello_original = server_state.generate_server_hello()

    # --- TAMPERING STEP ---
    # The signature in server_hello_original was calculated using the original nonce.
    # We now create a new ServerHello object for verification, but tamper with the nonce
    # that the signature covers (in the hash part of the message).
    
    server_hello_tampered = server_hello_original.copy()
    # The signature covers the 'client_nonce' field inside the ServerHello payload (message_to_sign)
    server_hello_tampered["client_nonce"] = "TAMPERED_NONCE_12345" 
    
    # 3. Verification attempt (should fail)
    sig_server_b64 = server_hello_tampered.pop("Signature") 
    message_signed_tampered = utils.serialize_for_signing(server_hello_tampered)
    server_pub_key = utils.get_public_key_from_cert(server_hello_tampered["server_cert"])

    is_valid = utils.verify_signature(server_pub_key, message_signed_tampered, sig_server_b64)
    
    # Assert that the verification failed due to the mismatch
    assert not is_valid, "Server signature should have failed when client_nonce was tampered."


# ... after test_server_rejects_expired_client_hello ...

def test_server_rejects_old_client_hello_timestamp(setup_server_keys):
    """
    Test Phase 1.4: Verifies the server rejects a ClientHello with a timestamp older than 30 seconds.
    """
    # 1. Setup Server State
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    
    # 2. Create a ClientHello with an old timestamp (e.g., 60 seconds old)
    old_time = datetime.now(timezone.utc) - timedelta(seconds=60)
    old_ts_str = old_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    client_cert = utils.load_cert(TEST_CERT_FILE)

    mock_client_hello_old = {
        "Type": "ClientHello",
        "client_cert": client_cert,
        "client_nonce": uuid.uuid4().hex,
        "client_timestamp": old_ts_str,
        "CipherSuite": "RSA_DH_SHA256_PROTOTYPE" 
    }

    # 3. Attempt verification (should fail due to freshness)
    is_valid = server_state.verify_client_hello(mock_client_hello_old)
    
    assert not is_valid, "Server failed to reject a stale ClientHello (older than 30s)."    

# ... after test_server_rejects_old_client_hello_timestamp ...

def test_server_rejects_untrusted_client_cert_signature(setup_server_keys):
    """
    Test Phase 1.4: Verifies the server rejects a ClientHello whose embedded 
    client_cert signature has been tampered with or is invalid (CA check fails).
    """
    # 1. Setup Server State
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    
    # 2. Create a MOCK ClientHello
    tampered_client_hello = create_mock_client_hello()
    
    # --- TAMPERING STEP ---
    # Load the legitimate client cert, tamper its signature, and put it back
    tampered_cert = tampered_client_hello["client_cert"].copy()
    
    # Overwrite the signature with garbage (invalid base64)
    tampered_cert["Signature"] = "GARBAGE_SIGNATURE_TO_FAIL_DECODE" 
    
    tampered_client_hello["client_cert"] = tampered_cert
    
    # 3. Attempt verification (should fail)
    is_valid = server_state.verify_client_hello(tampered_client_hello)
    
    assert not is_valid, "Server failed to reject client certificate with a tampered signature."
    
# ... (after test_server_rejects_old_client_hello_timestamp) ...

def test_shared_key_derivation_match():
    """
    Test Phase 2: Verifies that the Shared Key computed independently by the 
    Client and the Server (using DH prototype) matches exactly.
    """
    
    # --- Setup: Server Key Generation (P1.4 logic) ---
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    mock_client_hello = create_mock_client_hello()
    server_state.verify_client_hello(mock_client_hello)
    server_hello = server_state.generate_server_hello()
    # Server's DH Private Key and Shared Key logic are now ready.

    # --- Client Side: Verification and Shared Key Computation (P2.1/2.2 logic) ---
    client_state = ClientHandshakeState(TEST_CERT_FILE, TEST_SUBJECT)
    client_state.generate_client_hello() # Initialize client state
    client_state.verify_server_hello(server_hello)
    client_key_share = client_state.generate_key_share() 
    
    # Store the client's computed shared key
    client_shared_key = client_state.shared_key

    # --- Server Side: Receive and Compute Shared Key (P2.3 logic) ---
    server_state.receive_key_share(client_key_share)
    
    # Store the server's computed shared key
    server_shared_key = server_state.shared_key

    # --- Verification ---
    assert client_shared_key == server_shared_key, "Shared Key computation mismatch! DH exchange failed."
    assert len(client_shared_key) > 0, "Shared Key should not be empty."

def test_transcript_hash_consistency():
    """
    Test P3.1: Verifies that the transcript hash calculated independently by the 
    Client and Server is identical and stable.
    """
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    mock_client_hello = create_mock_client_hello()
    server_state.verify_client_hello(mock_client_hello)
    server_hello = server_state.generate_server_hello()
    
    client_state = ClientHandshakeState(TEST_CERT_FILE, TEST_SUBJECT)
    client_state.generate_client_hello()
    client_state.verify_server_hello(server_hello)
    client_key_share = client_state.generate_key_share() 
    
    # Client calculates the hash
    client_finished = client_state.generate_client_finished(client_key_share)
    client_hash = client_state.transcript_hash

    # Server calculates the hash
    server_state.receive_key_share(client_key_share)
    server_state.verify_client_finished(client_finished, client_key_share)
    server_hash = server_state.transcript_hash
    
    assert client_hash == server_hash, "Transcript Hash mismatch between Client and Server."
    assert len(client_hash) == 32, "Transcript Hash should be 32 bytes (SHA256 output)."

def test_client_authentication_success():
    """
    Test P3.2: Verifies that the server successfully verifies the ClientFinished 
    signature against the transcript hash using the Client's public key.
    """
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    mock_client_hello = create_mock_client_hello()
    server_state.verify_client_hello(mock_client_hello)
    server_hello = server_state.generate_server_hello()
    
    client_state = ClientHandshakeState(TEST_CERT_FILE, TEST_SUBJECT)
    client_state.generate_client_hello()
    client_state.verify_server_hello(server_hello)
    client_key_share = client_state.generate_key_share()
    client_finished = client_state.generate_client_finished(client_key_share)
    
    # Server attempts verification
    server_state.receive_key_share(client_key_share)
    is_authenticated = server_state.verify_client_finished(client_finished, client_key_share)
    
    assert is_authenticated, "Client authentication failed: Server rejected the ClientFinished signature."

def test_authentication_fails_on_tampered_transcript():
    """
    Test P3.3: Verifies that authentication fails if the signature in ClientFinished 
    does not match the Server's calculated transcript hash.
    """
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    mock_client_hello = create_mock_client_hello()
    server_state.verify_client_hello(mock_client_hello)
    server_hello = server_state.generate_server_hello()
    
    client_state = ClientHandshakeState(TEST_CERT_FILE, TEST_SUBJECT)
    client_state.generate_client_hello()
    client_state.verify_server_hello(server_hello)
    client_key_share = client_state.generate_key_share()
    
    # Client signs the hash (legitimate signature)
    client_finished_original = client_state.generate_client_finished(client_key_share)
    
    # --- TAMPERING STEP ---
    # We modify the client_key_share AFTER the client has signed it, 
    # forcing the Server's calculated transcript hash to be different.
    tampered_key_share = client_key_share.copy()
    tampered_key_share["client_public_key"] = base64.b64encode(b"TAMPERED_KEY_HASH_BREAK").decode('utf-8')
    
    # Server receives the tampered key share and original signed ClientFinished
    server_state.receive_key_share(tampered_key_share)
    
    # Server verifies the signature against its NEW (tampered) transcript hash
    is_authenticated = server_state.verify_client_finished(client_finished_original, tampered_key_share)
    
    assert not is_authenticated, "Authentication succeeded despite a tampered key share affecting the transcript hash."

def test_session_key_derivation_match():
    """
    Test P3.4: Verifies that the final session key K_s derived by both the Client 
    and Server using HKDF (prototype) matches exactly.
    """
    server_state = ServerHandshakeState(TEST_SERVER_CERT_FILE)
    mock_client_hello = create_mock_client_hello()
    server_state.verify_client_hello(mock_client_hello)
    server_hello = server_state.generate_server_hello()
    
    client_state = ClientHandshakeState(TEST_CERT_FILE, TEST_SUBJECT)
    client_state.generate_client_hello()
    client_state.verify_server_hello(server_hello)
    client_key_share = client_state.generate_key_share()
    
    # Client computes the final message and stores the hash
    client_finished = client_state.generate_client_finished(client_key_share)
    
    # 1. Server Finalization
    server_state.receive_key_share(client_key_share)
    server_state.verify_client_finished(client_finished, client_key_share)
    server_state.generate_server_finished() # This step derives and stores K_s on server
    server_session_key = server_state.session_key
    
    # 2. Client Finalization (Manually run KDF, as client finished logic isn't written yet)
    client_nonce = client_state.client_nonce
    server_nonce = server_state.server_nonce
    client_transcript_hash = client_state.transcript_hash
    
    client_session_key = utils.derive_session_key(
        client_state.shared_key, client_nonce, server_nonce, client_transcript_hash
    )

    # 3. Verification
    assert server_session_key == client_session_key, "Final Session Key K_s mismatch!"
    assert len(server_session_key) > 0, "Session Key should not be empty."

def calculate_transcript_hash(client_hello: dict, server_hello: dict, client_key_share: dict) -> bytes:
    """
    Calculates the SHA256 hash over the deterministic serialization of the core 
    handshake messages to create the 'transcript_hash'.
    
    The critical part is cleaning the nested certificates before serialization 
    for the hash calculation.
    """
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    
    # Define clean_cert internally for local use
    def _clean_cert(cert: dict) -> dict:
        cleaned = cert.copy()
        cleaned.pop("Signature", None)
        cleaned.pop("CA_Public_Key", None)
        return cleaned

    # 1. Hash ClientHello
    # We must deep-copy to avoid modifying the ClientHello object used elsewhere.
    ch_copy = copy.deepcopy(client_hello)
    ch_copy.pop("Signature", None)
    # Recursively clean the nested certificate
    if "client_cert" in ch_copy:
        ch_copy["client_cert"] = _clean_cert(ch_copy["client_cert"])
    
    h.update(serialize_for_signing(ch_copy))

    # 2. Hash ServerHello
    sh_copy = copy.deepcopy(server_hello)
    sh_copy.pop("Signature", None) # Exclude top-level signature
    # Recursively clean the nested certificate
    if "server_cert" in sh_copy:
        sh_copy["server_cert"] = _clean_cert(sh_copy["server_cert"])

    h.update(serialize_for_signing(sh_copy))

    # 3. Hash ClientKeyShare (does not contain certificates/signatures, so no deep clean needed)
    ks_copy = client_key_share.copy()
    h.update(serialize_for_signing(ks_copy))

    return h.finalize()
