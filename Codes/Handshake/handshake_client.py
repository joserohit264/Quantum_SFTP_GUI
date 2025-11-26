import socket
import sys
import json
import uuid
from datetime import datetime, timezone
import os
import base64

# Add the parent directory to the path to import utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))
try:
    import utils
    from kyber_py.kyber import Kyber512
except ImportError:
    print("Error: Could not import utils.py or PQC libs. Ensure they are in the correct path.", file=sys.stderr)
    sys.exit(1)

# --- Configuration ---
HOST = os.environ.get('SERVER_IP', '127.0.0.1')
PORT = 8888
BUFFER_SIZE = 4096

# --- Socket I/O Functions ---

def send_message(s: socket.socket, message: dict):
    """Sends a JSON message over the established connection."""
    try:
        data = json.dumps(message).encode('utf-8')
        # Prepend 4-byte length prefix
        s.sendall(len(data).to_bytes(4, byteorder='big') + data)
    except Exception as e:
        print(f"Client Error sending data: {e}", file=sys.stderr)
        raise

def receive_message(s: socket.socket) -> dict:
    """Receives a message, reading the 4-byte length prefix first."""
    try:
        raw_len = s.recv(4)
        if not raw_len:
            raise ConnectionAbortedError("Connection closed by peer before length received.")
        
        msg_len = int.from_bytes(raw_len, byteorder='big')
        
        chunks = []
        bytes_recd = 0
        while bytes_recd < msg_len:
            chunk = s.recv(min(msg_len - bytes_recd, BUFFER_SIZE)) 
            if chunk == b'':
                raise ConnectionAbortedError("Connection closed unexpectedly.")
            chunks.append(chunk)
            bytes_recd += len(chunk)

        data = b"".join(chunks).decode('utf-8')
        return json.loads(data)
    except ConnectionAbortedError:
        raise
    except Exception as e:
        print(f"Client Error receiving data: {e}", file=sys.stderr)
        raise

# --- Handshake State Management ---

class ClientHandshakeState:
    """Manages the client-side state and message generation for the handshake."""
    def __init__(self, cert_filename: str, key_subject: str):
        self.cert_filename = cert_filename
        self.key_subject = key_subject
        
        # Load Client Certificate and Dilithium Private Key
        self.cert = utils.load_cert(cert_filename)
        self.private_key = utils.load_dilithium_private_key(key_subject)

        # State
        self.client_nonce = None
        self.client_timestamp = None
        self.client_hello_message = None
        self.server_hello = None
        self.shared_key = None
        self.transcript_hash = None

    def generate_client_hello(self) -> dict:
        """Generates the ClientHello message."""
        self.client_nonce = uuid.uuid4().hex
        self.client_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        self.client_hello_message = {
            "Type": "ClientHello",
            "client_cert": self.cert,
            "client_nonce": self.client_nonce,
            "client_timestamp": self.client_timestamp,
            "CipherSuite": "KYBER512_DILITHIUM2" 
        }
        return self.client_hello_message

    def verify_server_hello(self, server_hello: dict) -> bool:
        """Verifies the ServerHello's integrity and signature."""
        if server_hello.get("Type") != "ServerHello":
            print("Verification FAILED: Invalid ServerHello structure.", file=sys.stderr)
            return False

        # 1. Check Server Certificate Validity
        server_cert = server_hello["server_cert"]
        if not utils.check_cert_validity(server_cert):
            print("Verification FAILED: Server certificate is not currently valid.", file=sys.stderr)
            return False

        # 2. Extract Server Public Key from Certificate
        server_pub_key = utils.get_public_key_from_cert(server_cert)

        # 3. Verify Signature
        message_to_verify = server_hello.copy()
        sig_server_b64 = message_to_verify.pop("Signature", None)
        
        if not sig_server_b64:
             print("Verification FAILED: ServerHello missing signature.", file=sys.stderr)
             return False

        if "server_cert" in message_to_verify:
             message_to_verify["server_cert"] = utils.clean_cert(message_to_verify["server_cert"])
        
        serialized_msg = utils.serialize_for_signing(message_to_verify)
        
        if not utils.verify_signature(server_pub_key, serialized_msg, sig_server_b64):
            print("Verification FAILED: Server signature is invalid.", file=sys.stderr)
            return False

        print("Verification PASSED: ServerHello integrity and signature confirmed.")        
        self.server_hello = server_hello
        return True
                
    def generate_key_share(self) -> dict:
        """
        Phase 2: Performs Kyber Encapsulation.
        """
        # 1. Get Server's Kyber Public Key from ServerHello
        server_kyber_pk_b64 = self.server_hello.get("server_key_share")
        if not server_kyber_pk_b64:
            raise ValueError("ServerHello is missing Kyber public key (server_key_share).")
            
        server_kyber_pk = base64.b64decode(server_kyber_pk_b64)

        # 2. Encapsulate -> Shared Key, Ciphertext
        # Note: Kyber512.encaps returns (shared_key, ciphertext) based on our test
        self.shared_key, ciphertext = Kyber512.encaps(server_kyber_pk)
        
        print(f"[P2.2] Shared Key computed (Size: {len(self.shared_key)} bytes).")

        # 3. Prepare ClientKeyShare
        client_key_share = {
            "Type": "ClientKeyShare",
            "client_ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        return client_key_share

    def generate_client_finished(self, client_key_share: dict) -> dict:
        """
        Phase 3: Calculates transcript hash and signs it.
        """
        # 1. Calculate Transcript Hash
        self.transcript_hash = utils.calculate_transcript_hash(
            self.client_hello_message, self.server_hello, client_key_share
        )
        transcript_hash_hex = self.transcript_hash.hex()
        print(f"[P3.2] Transcript Hash computed: {transcript_hash_hex[:12]}...")

        # 2. Sign the Hash with Dilithium
        sig_client_finish_b64 = utils.sign_message(self.private_key, self.transcript_hash)
        
        # 3. Prepare message
        client_finished_msg = {
            "Type": "ClientFinished",
            "Signature": sig_client_finish_b64,
            "transcript_hash": transcript_hash_hex
        }
        return client_finished_msg

# --- Main Client Logic ---

def start_client(cert_filename: str = "client_cert.json", key_subject: str = "Client"):
    print(f"Connecting QSFtp Handshake Client to {HOST}:{PORT}...")
    
    client_state = ClientHandshakeState(cert_filename, key_subject)
    client_hello_msg = client_state.generate_client_hello()
    print(f"[P1.3] Generated ClientHello for Subject: {client_state.cert['Subject']}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print("Successfully connected to server.")
            
            # Step 1: Send ClientHello
            send_message(s, client_hello_msg)
            print("[TX] Sent ClientHello.")
            
            # Step 2: Receive ServerHello
            server_hello = receive_message(s)
            print(f"\n[RX] Received ServerHello.")

            # Step 2.1: Verify ServerHello
            if not client_state.verify_server_hello(server_hello):
                raise Exception("Server authentication failed.")

            # Step 3: Generate Key Share (Kyber Encaps)
            client_key_share = client_state.generate_key_share()
            
            # Step 4: Send ClientKeyShare
            send_message(s, client_key_share)
            print("[TX] Sent ClientKeyShare (Ciphertext).")

            # Step 5: Generate and Send ClientFinished
            client_finished_msg = client_state.generate_client_finished(client_key_share)
            send_message(s, client_finished_msg)
            print("[TX] Sent ClientFinished (Signed Hash).")
        
            # Step 6: Receive ServerFinished
            server_finished_msg = receive_message(s)
            print("\n[RX] Received ServerFinished.")
            
            # Step 7: Verify ServerFinished (Optional, but good practice)
            # For now, we assume if we got here, server accepted our finished.
            
            # Derive Session Key
            session_key = utils.derive_session_key(
                client_state.shared_key,
                client_state.client_nonce,
                client_state.server_hello["server_nonce"],
                client_state.transcript_hash
            )
            print(f"\n[SUCCESS] Session Key Established: {session_key.hex()[:16]}...")
            
            # --- File Transfer Logic ---
            print("\n[Client] Starting Secure File Transfer...")
            
            # Default values
            filename = "secret_message.txt"
            file_content = b"This is a default secret message protected by Kyber and Dilithium!"
            
            # Check for CLI argument
            if len(sys.argv) > 1:
                arg_path = sys.argv[1]
                
                # Check if argument is an existing file
                if os.path.isfile(arg_path):
                    # Check file size (Max 10MB)
                    file_size = os.path.getsize(arg_path)
                    if file_size > 10 * 1024 * 1024: # 10MB in bytes
                        print(f"Error: File '{arg_path}' exceeds the 10MB size limit (Size: {file_size/1024/1024:.2f} MB).", file=sys.stderr)
                        return
                    
                    print(f"[Client] Reading file: {arg_path} ({file_size} bytes)...")
                    filename = os.path.basename(arg_path)
                    with open(arg_path, "rb") as f:
                        file_content = f.read()
                else:
                    # Treat as text message if not a file
                    print("[Client] Argument is not a file, treating as text message.")
                    filename = "cli_message.txt"
                    file_content = " ".join(sys.argv[1:]).encode('utf-8')
            
            # Encrypt
            nonce, ciphertext = utils.encrypt_data(session_key, file_content)
            print(f"[Client] Encrypted '{filename}' ({len(file_content)} bytes) -> Ciphertext ({len(ciphertext)} bytes).")
            
            # Send
            file_msg = {
                "Type": "FileTransfer",
                "Filename": filename,
                "Content": base64.b64encode(ciphertext).decode('utf-8'),
                "Nonce": base64.b64encode(nonce).decode('utf-8')
            }
            send_message(s, file_msg)
            print(f"[TX] Sent FileTransfer message.")
            
        except ConnectionRefusedError:
            print(f"Error: Connection refused. Ensure the server is running on {HOST}:{PORT}.", file=sys.stderr)
        except Exception as e:
            print(f"Handshake failed: {e}", file=sys.stderr)

    print("Client process finished.")

if __name__ == '__main__':
    start_client()
