import socket
import json
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# --- Configuration ---
HOST = '0.0.0.0' # Listen on all network interfaces
PORT = 8888
BUFFER_SIZE = 4096
SERVER_SUBJECT = "Server" 

# --- Academic Output Helpers ---
def print_banner():
    print("\n" + "="*70)
    print("   QUANTUM-RESISTANT SAFE FILE TRANSFER PROTOCOL (Q-SFTP)")
    print("        SERVER-SIDE HANDSHAKE & SECURE CHANNEL")
    print("="*70)
    print("[Crypto] Cipher Suite Initialized:")
    print("    - KEM Algorithm        : CRYSTALS-Kyber-512 (Post-Quantum Key Exchange)")
    print("    - Signature Algorithm  : CRYSTALS-Dilithium-2 (Post-Quantum Auth)")
    print("    - Symmetric Cipher     : AES-256-GCM (Authenticated Encryption)")
    print("    - Hash Function        : SHA3-256")
    print("-" * 70)

def print_phase(phase_num, title):
    print(f"\n[Phase {phase_num}] {title}")
    print("-" * 40)
 

# --- Socket I/O Functions ---

def send_message(conn: socket.socket, message: dict):
    """Sends a JSON message over the established connection."""
    try:
        data = json.dumps(message).encode('utf-8')
        conn.sendall(len(data).to_bytes(4, byteorder='big') + data)
    except Exception as e:
        print(f"Server Error sending data: {e}", file=sys.stderr)
        raise

def receive_message(conn: socket.socket) -> dict:
    """Receives a message, reading the 4-byte length prefix first."""
    try:
        raw_len = conn.recv(4)
        if not raw_len:
            raise ConnectionAbortedError("Connection closed by peer before length received.")
        
        msg_len = int.from_bytes(raw_len, byteorder='big')
        
        chunks = []
        bytes_recd = 0
        while bytes_recd < msg_len:
            chunk = conn.recv(min(msg_len - bytes_recd, BUFFER_SIZE))
            if chunk == b'':
                raise ConnectionAbortedError("Connection closed unexpectedly.")
            chunks.append(chunk)
            bytes_recd += len(chunk)

        data = b"".join(chunks).decode('utf-8')
        return json.loads(data)
    except ConnectionAbortedError:
        raise
    except Exception as e:
        print(f"Server Error receiving data: {e}", file=sys.stderr)
        raise

# --- Handshake State Management ---

class ServerHandshakeState:
    """Manages the server-side state, message handling, and cryptographic operations."""
    def __init__(self, cert_filename: str):
        self.cert_filename = cert_filename
        
        # Load Server Certificate and Dilithium Private Key
        self.server_cert = utils.load_cert(cert_filename)
        self.private_key = utils.load_dilithium_private_key(SERVER_SUBJECT)
        
        # Handshake state variables
        self.client_hello = None
        self.server_hello = None
        self.server_nonce = None
        self.server_timestamp = None
        self.kyber_sk = None # Ephemeral Kyber Secret Key
        self.shared_key = None
        self.transcript_hash = None
        self.session_key = None

    def verify_client_hello(self, client_hello: dict) -> bool:
        """Performs basic checks on the received ClientHello."""
        self.client_hello = client_hello

        # 1. Check basic structure
        if client_hello.get("Type") != "ClientHello" or "client_cert" not in client_hello:
            print("Verification FAILED: Invalid ClientHello structure.")
            return False

        client_cert = client_hello["client_cert"]
        # 2. Check Client Certificate Validity
        if not utils.check_cert_validity(client_cert):
            print("Verification FAILED: Client certificate is not currently valid.")
            return False

        
        # 3. Verify Client Certificate Signature (using pinned CA key)
        ca_pub_key = utils.load_dilithium_public_key("CA") # Load CA public key bytes
        cert_full = client_cert.copy()
        
        cert_signature_b64 = cert_full.pop("Signature", None)
        if not cert_signature_b64:
            print("Verification FAILED: Client certificate missing signature.", file=sys.stderr)
            return False

        message_signed_cert = utils.serialize_for_signing(cert_full)

        if not utils.verify_signature(ca_pub_key, message_signed_cert, cert_signature_b64):
            print("Verification FAILED: Client certificate signature is invalid (CA check).", file=sys.stderr)
            return False
        
        # 4. Check Freshness        
        client_ts_str = client_hello.get("client_timestamp")
        try:
            client_ts = datetime.strptime(client_ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - client_ts > timedelta(seconds=30):
                print("Verification FAILED: ClientHello timestamp is too old (Replay risk).")
                return False
        except Exception:
            print("Verification FAILED: Invalid client_timestamp format.")
            return False

        print(f"[P1.4] Received ClientHello from Subject: {client_cert.get('Subject')}")
        print("Verification PASSED: ClientHello is valid and fresh.")
        return True

    def generate_server_hello(self) -> dict:
        """Generates the ServerHello message, including Kyber public key and Dilithium signature."""
        
        # Step 1: Generate Ephemeral Kyber Keypair
        print("[P1.4] Generating Kyber Ephemeral Keys...")
        pk, sk = Kyber512.keygen()
        self.kyber_sk = sk
        kyber_pk_b64 = base64.b64encode(pk).decode('utf-8')

        # Step 2: Generate Server Nonce and Timestamp
        self.server_nonce = uuid.uuid4().hex
        self.server_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Step 3: Prepare the message to be signed
        cleaned_server_cert = utils.clean_cert(self.server_cert)
        cleaned_client_cert = utils.clean_cert(self.client_hello.get("client_cert", {}))
        
        # Hash the client's certificate
        client_cert_data_for_hash = utils.serialize_for_signing(cleaned_client_cert)
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(client_cert_data_for_hash)
        client_cert_hash_hex = h.finalize().hex()
        
        message_to_sign = {
            "Type": "ServerHello",
            "server_cert": cleaned_server_cert,
            "server_key_share": kyber_pk_b64, # Ephemeral Kyber PK
            "server_nonce": self.server_nonce,
            "server_timestamp": self.server_timestamp,
            "CipherSuite": "KYBER512_DILITHIUM2",
            "client_cert_hash": client_cert_hash_hex,
            "client_nonce": self.client_hello.get("client_nonce"),
        }

        # Step 4: Sign the message with Dilithium
        # Step 4: Sign the message with Dilithium
        serialized_msg = utils.serialize_for_signing(message_to_sign)
        sig_server_b64 = utils.sign_message(self.private_key, serialized_msg)
        
        print("[P1.4] Server successfully signed the handshake transcript.")

        # Step 5: Construct the final ServerHello message
        self.server_hello = message_to_sign
        self.server_hello["Signature"] = sig_server_b64
        
        return self.server_hello
                
    def receive_key_share(self, client_key_share: dict) -> bool:
        """Phase 2: Receives client's Kyber ciphertext and decapsulates."""
        if client_key_share.get("Type") != "ClientKeyShare" or "client_ciphertext" not in client_key_share:
            print("Decapsulation FAILED: Invalid ClientKeyShare message.", file=sys.stderr)
            return False

        # 1. Load client's ciphertext
        ciphertext_b64 = client_key_share["client_ciphertext"]
        ciphertext = base64.b64decode(ciphertext_b64)

        # 2. Decapsulate -> Shared Secret
        if not self.kyber_sk:
             raise Exception("Kyber Secret Key not initialized.")
             
        self.shared_key = Kyber512.decaps(self.kyber_sk, ciphertext)
        print(f"[P2.3] Shared Key computed (Size: {len(self.shared_key)} bytes).")
        
        return True

    def verify_client_finished(self, client_finished: dict, client_key_share: dict) -> bool:
        """Phase 3: Verifies the client's signature over the transcript."""
        # 1. Re-calculate Transcript Hash
        self.transcript_hash = utils.calculate_transcript_hash(
            self.client_hello, self.server_hello, client_key_share
        )
        transcript_hash_hex = self.transcript_hash.hex()
        print(f"[P3.3] Transcript Hash computed: {transcript_hash_hex[:12]}...")

        # 2. Verify Transcript Hash
        if client_finished.get("transcript_hash") != transcript_hash_hex:
            print("Verification FAILED: Transcript hash mismatch.", file=sys.stderr)
            return False
            
        # 3. Verify Client Signature
        sig_client_finish_b64 = client_finished.get("Signature")
        if not sig_client_finish_b64:
            print("Verification FAILED: Client finished message missing signature.", file=sys.stderr)
            return False

        # Get Client's Public Key from their certificate
        client_cert = self.client_hello["client_cert"]
        client_pub_key = utils.get_public_key_from_cert(client_cert)
        
        # Verify the signature
        if not utils.verify_signature(client_pub_key, self.transcript_hash, sig_client_finish_b64):
            print("Verification FAILED: Client signature verification failed.", file=sys.stderr)
            return False
            
        print("    [Auth] Client Signature      : ✅ VERIFIED (Proof of Possession)")
        return True

    def generate_server_finished(self) -> dict:
        """Phase 3: Signs the transcript hash and derives the session key."""
        # 1. Derive Final Session Key
        client_nonce = self.client_hello["client_nonce"]
        server_nonce = self.server_nonce
        
        self.session_key = utils.derive_session_key(
            self.shared_key, client_nonce, server_nonce, self.transcript_hash
        )
        sk_fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sk_fingerprint.update(self.session_key)
        print_phase(4, "Secure Channel Establishment")
        print(f"    [KeyInfo] Session Key Derived : {len(self.session_key)*8} bits")
        print(f"    [KeyInfo] Key Fingerprint     : {sk_fingerprint.finalize().hex()[:16]}... (Safe Metadata)")

        # 2. Sign the Hash with Dilithium
        sig_server_final_b64 = utils.sign_message(self.private_key, self.transcript_hash)
        
        # 3. Prepare message
        server_finished_msg = {
            "Type": "ServerFinished",
            "Signature": sig_server_final_b64,
            "transcript_hash": self.transcript_hash.hex()
        }
        return server_finished_msg
                
# --- Main Server Logic ---


# --- Main Server Logic ---

def start_server(cert_filename: str = "server_cert.json"):
    print("="*70)
    print(" Q-SFTP SERVER: QUANTUM-SAFE FILE TRANSFER")
    print("="*70)
    print(f"[*] Binding to           : {HOST}:{PORT}")
    print(f"[*] Server Subject       : {SERVER_SUBJECT}")
    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[*] System Time          : {current_time}")
    print("-" * 70)
    print(f"[*] Identity Loaded      : {SERVER_SUBJECT}")
    print("[*] Ready for PQC Handshake...")
    
    try:
        server_state = ServerHandshakeState(cert_filename)
        # print(f"[Init] Server ready with Subject: {server_state.server_cert['Subject']}")
    except SystemExit:
        print("\nFATAL: Server setup failed.", file=sys.stderr)
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print("Waiting for a client connection...\n")
        
        conn, addr = s.accept()
        with conn:
            print(f"[New Connection] {addr[0]}:{addr[1]}")
            print("-" * 70)
            
            try:
                t_start_handshake = time.time()
                # Step 1: Receive ClientHello
                client_hello = receive_message(conn)
                
                # Step 2: Verify ClientHello & Send ServerHello
                if not server_state.verify_client_hello(client_hello):
                    raise Exception("Client authentication failed.")
                
                server_hello_msg = server_state.generate_server_hello()
                
                # Print Client Details
                client_cert = client_hello["client_cert"]
                print(f"[Client] Subject             : {client_cert.get('Subject')}")
                print(f"[Client] Issuer              : {client_cert.get('Issuer')}")
                print(f"[Client] Cipher Suite        : {server_hello_msg['CipherSuite']}")
                
                send_message(conn, server_hello_msg)
                # Calculate size of sent message
                sent_len = len(json.dumps(server_hello_msg).encode('utf-8')) + 4
                print(f"[TX] ServerHello Sent ({sent_len} bytes).")
                
                print(f"\n[Phase 2] Post-Quantum Key Exchange")
                print("-" * 70)
                
                # Step 3: Receive ClientKeyShare
                client_key_share = receive_message(conn)
                
                # Calculate size of received message
                recv_len = len(json.dumps(client_key_share).encode('utf-8')) + 4
                print(f"[RX] ClientKeyShare Received ({recv_len} bytes).")
                
                # Step 4: Process KeyShare
                if not server_state.receive_key_share(client_key_share):
                     raise Exception("Key exchange failed.")

                # Step 5: Receive ClientFinished
                client_finished_msg = receive_message(conn)
                print("[RX] Received ClientFinished.")
                
                print("\n--- DEBUG: Transcript Hash Calculation ---")
                print("--- END DEBUG ---\n")
                
                # Step 6: Verify ClientFinished
                if not server_state.verify_client_finished(client_finished_msg, client_key_share):
                    raise Exception("Mutual authentication failed.")
                    
                print(f"\n[Phase 3] Mutual Authentication")
                print("-" * 70)
                    
                # Step 7: Generate and Send ServerFinished
                server_finished_msg = server_state.generate_server_finished()
                send_message(conn, server_finished_msg)
                print("[TX] ServerFinished Sent (Signed Transcript Hash).")
                print("[Crypto] Signature Algorithm : CRYSTALS-Dilithium-2")
            
                t_end_handshake = time.time()
                # print(f"\n✅ HANDSHAKE COMPLETE. Session Key K_s established.")
                
                print(f"\n[Phase 4] Secure Channel Established")
                print("-" * 70)
                
                sk_fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
                sk_fingerprint.update(server_state.session_key)
                
                print(f"[KeyInfo] Session Key Fingerprint : {sk_fingerprint.finalize().hex()[:16]}...")
                print(f"[KeyInfo] Session Key Length      : {len(server_state.session_key)*8} bits")
                print("[Security Guarantees]")
                print(" - Mutual Authentication      : ✅ (Verified Client Signature)")
                print(" - Quantum-Resistant Key Exch : ✅ (Kyber-512 Decapsulation)")
                print(" - Integrity Protected        : ✅ (Dilithium-2)")
                
                # --- File Transfer Logic ---
                print("\n[Phase 5] Encrypted File Transfer")
                print("-" * 70)
                print("[Server] Waiting for incoming encrypted stream...")
                file_msg = receive_message(conn)
                
                if file_msg.get("Type") == "FileTransfer":
                    print("[RX] Incoming FileTransfer Message.")
                    print(f"[File] Filename              : {file_msg.get('Filename')}")
                    print(f"[Crypto] Symmetric Cipher    : AES-256-GCM")
                    
                    # Decrypt
                    content_b64 = file_msg["Content"]
                    nonce_b64 = file_msg["Nonce"]
                    
                    content = base64.b64decode(content_b64)
                    nonce = base64.b64decode(nonce_b64)
                    
                    print(f"[File] Encrypted Size        : {len(content)} bytes")
                    
                    t_dec_start = time.perf_counter()
                    plaintext = utils.decrypt_data(server_state.session_key, nonce, content)
                    t_dec_end = time.perf_counter()
                    
                    print(f"[File] Decrypted Size        : {len(plaintext)} bytes")
                    print(f"[Perf] Decryption Time       : {(t_dec_end - t_dec_start)*1000:.2f} ms")
                    
                    # Throughput calculation (bits/sec -> Mbps)
                    throughput = (len(content) * 8) / ((t_dec_end - t_dec_start) * 1e6) if (t_dec_end - t_dec_start) > 0 else 0
                    print(f"[Perf] Throughput            : {throughput:.2f} Mbps")
                    
                    try:
                        # Try to print as text if small
                        if len(plaintext) < 1000:
                            # Note: The image shows "[Data] Content : [Binary/Large Data...]" for PDF, 
                            # but for text it might show content. User Prompt image shows PDF example. 
                            # I will implement logic to show content if text, else binary indicator.
                            # Actually, the user image shows: "[Data] Content : [Binary/Large Data - 122217 bytes]"
                            # I'll stick to that if it's large or binary.
                            decoded_text = plaintext.decode('utf-8')
                            if len(decoded_text) < 100:
                                print(f"[Data] Content               : {decoded_text}")
                            else:
                                 print(f"[Data] Content               : [Text Data - {len(plaintext)} bytes]")
                        else:
                            print(f"[Data] Content               : [Binary/Large Data - {len(plaintext)} bytes]")
                    except:
                        print(f"[Data] Content               : [Binary/Large Data - {len(plaintext)} bytes]")
                    
                    # Save file
                    save_path = os.path.abspath(f"received_{file_msg['Filename']}")
                    with open(save_path, "wb") as f:
                        f.write(plaintext)
                    print(f"[IO] File saved to           : {save_path}")
                    
                    print("=" * 70)
                    print("              TRANSFER COMPLETE")
                    print("=" * 70)
                else:
                    print(f"[Server] Unexpected message type: {file_msg.get('Type')}")
                    
            except Exception as e:
                print(f"Handshake failed: {e}", file=sys.stderr)
            
            print("Server process finished.")

if __name__ == '__main__':
    start_server()