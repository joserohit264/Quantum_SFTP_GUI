import socket
import json
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
import os
import base64
import secrets

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
        
        self.client_hello = None
        self.server_hello = None
        self.server_nonce = None
        self.server_timestamp = None
        self.kyber_sk = None 
        self.shared_key = None
        self.transcript_hash = None
        self.session_key = None

    def verify_client_hello(self, client_hello: dict) -> bool:
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
        ca_pub_key = utils.load_dilithium_public_key("CA") 
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
        print("[P1.4] Generating Kyber Ephemeral Keys...")
        pk, sk = Kyber512.keygen()
        self.kyber_sk = sk
        kyber_pk_b64 = base64.b64encode(pk).decode('utf-8')

        self.server_nonce = secrets.token_hex(16)
        self.server_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        cleaned_server_cert = utils.clean_cert(self.server_cert)
        cleaned_client_cert = utils.clean_cert(self.client_hello.get("client_cert", {}))
        
        client_cert_data_for_hash = utils.serialize_for_signing(cleaned_client_cert)
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(client_cert_data_for_hash)
        client_cert_hash_hex = h.finalize().hex()
        
        message_to_sign = {
            "Type": "ServerHello",
            "server_cert": cleaned_server_cert,
            "server_key_share": kyber_pk_b64,
            "server_nonce": self.server_nonce,
            "server_timestamp": self.server_timestamp,
            "CipherSuite": "KYBER512_DILITHIUM2",
            "client_cert_hash": client_cert_hash_hex,
            "client_nonce": self.client_hello.get("client_nonce"),
        }

        serialized_msg = utils.serialize_for_signing(message_to_sign)
        sig_server_b64 = utils.sign_message(self.private_key, serialized_msg)
        
        print("[P1.4] Server successfully signed the handshake transcript.")

        self.server_hello = message_to_sign
        self.server_hello["Signature"] = sig_server_b64
        
        return self.server_hello
                
    def receive_key_share(self, client_key_share: dict) -> bool:
        if client_key_share.get("Type") != "ClientKeyShare" or "client_ciphertext" not in client_key_share:
            print("Decapsulation FAILED: Invalid ClientKeyShare message.", file=sys.stderr)
            return False

        ciphertext_b64 = client_key_share["client_ciphertext"]
        ciphertext = base64.b64decode(ciphertext_b64)

        if not self.kyber_sk:
             raise Exception("Kyber Secret Key not initialized.")
             
        self.shared_key = Kyber512.decaps(self.kyber_sk, ciphertext)
        print(f"[P2.3] Shared Key computed (Size: {len(self.shared_key)} bytes).")
        return True

    def verify_client_finished(self, client_finished: dict, client_key_share: dict) -> bool:
        self.transcript_hash = utils.calculate_transcript_hash(
            self.client_hello, self.server_hello, client_key_share
        )
        transcript_hash_hex = self.transcript_hash.hex()
        print(f"[P3.3] Transcript Hash computed: {transcript_hash_hex[:12]}...")

        if client_finished.get("transcript_hash") != transcript_hash_hex:
            print("Verification FAILED: Transcript hash mismatch.", file=sys.stderr)
            return False
            
        sig_client_finish_b64 = client_finished.get("Signature")
        if not sig_client_finish_b64:
            print("Verification FAILED: Client finished message missing signature.", file=sys.stderr)
            return False

        client_cert = self.client_hello["client_cert"]
        client_pub_key = utils.get_public_key_from_cert(client_cert)
        
        if not utils.verify_signature(client_pub_key, self.transcript_hash, sig_client_finish_b64):
            print("Verification FAILED: Client signature verification failed.", file=sys.stderr)
            return False
            
        print("    [Auth] Client Signature      : ✅ VERIFIED (Proof of Possession)")
        return True

    def generate_server_finished(self) -> dict:
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

        sig_server_final_b64 = utils.sign_message(self.private_key, self.transcript_hash)
        
        server_finished_msg = {
            "Type": "ServerFinished",
            "Signature": sig_server_final_b64,
            "transcript_hash": self.transcript_hash.hex()
        }
        return server_finished_msg


# --- Main Handler ---



# --- RBAC Helper ---
from auth_manager import auth_db

from file_validator import FileValidator

def handle_client(conn, addr, server_state):
    print(f"[New Connection] {addr[0]}:{addr[1]}")
    print("-" * 70)
    
    # Setup Storage Root (BASE)
    GLOBAL_STORAGE_ROOT = os.path.abspath("ServerStorage")
    if not os.path.exists(GLOBAL_STORAGE_ROOT):
        os.makedirs(GLOBAL_STORAGE_ROOT)
    
    # Setup Shared Storage (accessible to all users)
    SHARED_STORAGE_ROOT = os.path.join(GLOBAL_STORAGE_ROOT, "shared")
    if not os.path.exists(SHARED_STORAGE_ROOT):
        os.makedirs(SHARED_STORAGE_ROOT)
    
    try:
        t_start_handshake = time.time()
        # Step 1: Receive ClientHello
        client_hello = receive_message(conn)
        
        # Step 2: Verify ClientHello & Send ServerHello
        if not server_state.verify_client_hello(client_hello):
            raise Exception("Client authentication failed.")
        
        # User Lookup & Context
        cert_subject = client_hello["client_cert"].get("Subject")
        user = auth_db.get_user_by_subject(cert_subject)
        if not user:
            print(f"[Auth] No user found for subject: {cert_subject}")
            raise Exception("Unauthorized: Certificate not registered to any user.")
        
        print(f"[Auth] User Authenticated: {user.username} (Role: {user.role})")

        # Directory Isolation
        USER_STORAGE_ROOT = os.path.join(GLOBAL_STORAGE_ROOT, user.username)
        if not os.path.exists(USER_STORAGE_ROOT):
            os.makedirs(USER_STORAGE_ROOT)
        
        server_hello_msg = server_state.generate_server_hello()
        
        client_cert = client_hello["client_cert"]
        print_phase(1, f"Handshake Initiated with {client_cert['Subject']}")
        
        send_message(conn, server_hello_msg)
        print("[TX] ServerHello Sent (Signed & Kyber PK).")
        
        # Step 3: Receive Client Key Share (Kyber Encapsulation)
        client_key_share = receive_message(conn)
        if not server_state.receive_key_share(client_key_share):
            raise Exception("Key exchange failed.")
        print_phase(2, "Key Exchange (Kyber-512)")
        
        # Step 4: Receive ClientFinished
        client_finished_msg = receive_message(conn)
        
        # Step 6: Verify ClientFinished
        if not server_state.verify_client_finished(client_finished_msg, client_key_share):
            raise Exception("Mutual authentication failed.")
            
        print(f"\n[Phase 3] Mutual Authentication")
        print("-" * 70)
            
        # Step 7: Generate and Send ServerFinished
        server_finished_msg = server_state.generate_server_finished()
        send_message(conn, server_finished_msg)
        print("[TX] ServerFinished Sent.")
    
        t_end_handshake = time.time()
        print(f"\n[Phase 4] Secure Channel Established")
        print("-" * 70)
        
        sk_fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sk_fingerprint.update(server_state.session_key)
        
        print(f"[KeyInfo] Session Key Fingerprint : {sk_fingerprint.finalize().hex()[:16]}...")
        print("[Security Guarantees]")
        print(" - Mutual Authentication      : ✅")
        print(" - Quantum-Resistant Key Exch : ✅")
        print(" - Integrity Protected        : ✅")
        
        # --- Command Loop ---
        print("\n[Phase 5] Secure Command Loop")
        print("-" * 70)

        while True:
            print("[Server] Waiting for encrypted command...")
            try:
                msg = receive_message(conn)
            except (ConnectionAbortedError, ConnectionResetError):
                print("[Server] Client disconnected.")
                break
            except Exception as e:
                print(f"[Server] Error receiving message: {e}")
                break
                
            msg_type = msg.get("Type")
            
            if msg_type == "ListFiles":
                if not auth_db.check_permission(user.username, 'READ'):
                    send_message(conn, {"Type": "Error", "Message": "Permission Denied: READ access required."})
                    continue

                path = msg.get("Path", "")
                
                # Determine if this is a shared folder path
                is_shared_path = (path == "shared" or path.startswith("shared/"))
                
                if is_shared_path:
                    # Resolve against shared storage
                    relative = path[len("shared"):].lstrip("/")
                    target_dir = os.path.normpath(os.path.join(SHARED_STORAGE_ROOT, relative))
                    if not target_dir.startswith(SHARED_STORAGE_ROOT): target_dir = SHARED_STORAGE_ROOT
                else:
                    target_dir = os.path.normpath(os.path.join(USER_STORAGE_ROOT, path))
                    if not target_dir.startswith(USER_STORAGE_ROOT): target_dir = USER_STORAGE_ROOT
                
                print(f"[RX] Command: ListFiles (Path: /{path}, Shared: {is_shared_path})")
                
                files = []
                try:
                    if os.path.exists(target_dir) and os.path.isdir(target_dir):
                        for f in os.listdir(target_dir):
                            full_path = os.path.join(target_dir, f)
                            stats = os.stat(full_path)
                            is_dir = os.path.isdir(full_path)
                            files.append({
                                "name": f,
                                "type": "dir" if is_dir else "file",
                                "size": stats.st_size if not is_dir else 0,
                                "modified": datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            })
                except Exception as e:
                    print(f"[Error] Listing failed: {e}")
                
                # Inject virtual 'shared' folder into root listing
                if not path or path == "" or path == "/":
                    # Check if 'shared' is not already in the list (shouldn't be in user dir)
                    if not any(f['name'] == 'shared' for f in files):
                        files.insert(0, {
                            "name": "shared",
                            "type": "dir",
                            "size": 0,
                            "modified": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "shared": True
                        })

                response = {"Type": "FileList", "Files": files, "CurrentPath": path}
                send_message(conn, response)
                print(f"[TX] Sent FileList ({len(files)} items).")

            elif msg_type == "FileTransfer":
                if not auth_db.check_permission(user.username, 'WRITE'):
                    send_message(conn, {"Type": "Error", "Message": "Permission Denied: WRITE access required."})
                    continue

                filename = msg.get('Filename')
                path = msg.get("Path", "")
                print(f"[RX] Incoming FileTransfer: {filename}")
                
                content_b64 = msg["Content"]
                nonce_b64 = msg["Nonce"]
                
                content = base64.b64decode(content_b64)
                nonce = base64.b64decode(nonce_b64)
                
                try:
                    plaintext = utils.decrypt_data(server_state.session_key, nonce, content)
                    
                    # --- SECURITY CHECK: Malicious File Protection ---
                    is_valid, reason = FileValidator.validate(filename, plaintext)
                    if not is_valid:
                        print(f"[Security] MALICIOUS FILE BLOCKED: {filename} Reason: {reason}")
                        ack = {"Type": "ActionAck", "Status": "Error", "Message": f"Security Violation: {reason}"}
                        send_message(conn, ack)
                        continue
                    # -------------------------------------------------
                    
                    # Determine if uploading to shared folder
                    is_shared_path = (path == "shared" or path.startswith("shared/"))
                    
                    if is_shared_path:
                        relative = path[len("shared"):].lstrip("/")
                        target_dir = os.path.normpath(os.path.join(SHARED_STORAGE_ROOT, relative))
                        if not target_dir.startswith(SHARED_STORAGE_ROOT): target_dir = SHARED_STORAGE_ROOT
                    else:
                        target_dir = os.path.normpath(os.path.join(USER_STORAGE_ROOT, path))
                        if not target_dir.startswith(USER_STORAGE_ROOT): target_dir = USER_STORAGE_ROOT
                    
                    if not os.path.exists(target_dir): os.makedirs(target_dir)
                    
                    save_path = os.path.join(target_dir, filename)
                    with open(save_path, 'wb') as f:
                        f.write(plaintext)
                    
                    ack = {"Type": "ActionAck", "Status": "Success"}
                    send_message(conn, ack)
                    print(f"[TX] File Saved: {save_path}")
                except Exception as e:
                    print(f"[Error] Decryption/Save failed: {e}")
                    ack = {"Type": "ActionAck", "Status": "Error", "Message": str(e)}
                    send_message(conn, ack)

            elif msg_type == "DownloadFile":
                if not auth_db.check_permission(user.username, 'READ'):
                    send_message(conn, {"Type": "Error", "Message": "Permission Denied: READ access required."})
                    continue

                filename = msg.get('Filename')
                path = msg.get("Path", "")
                print(f"[RX] Download Request: {filename}")
                
                # Determine if downloading from shared folder
                is_shared_path = (path == "shared" or path.startswith("shared/"))
                
                if is_shared_path:
                    relative = path[len("shared"):].lstrip("/")
                    target_path = os.path.normpath(os.path.join(SHARED_STORAGE_ROOT, relative, filename))
                    allowed_root = SHARED_STORAGE_ROOT
                else:
                    target_path = os.path.normpath(os.path.join(USER_STORAGE_ROOT, path, filename))
                    allowed_root = USER_STORAGE_ROOT
                
                if not target_path.startswith(allowed_root):
                    send_message(conn, {"Type": "Error", "Message": "Permission Denied"})
                elif os.path.exists(target_path):
                    with open(target_path, 'rb') as f:
                        content = f.read()
                    
                    nonce, ciphertext = utils.encrypt_data(server_state.session_key, content)
                    file_msg = {
                        "Type": "FileTransfer",
                        "Filename": filename,
                        "Content": base64.b64encode(ciphertext).decode('utf-8'),
                        "Nonce": base64.b64encode(nonce).decode('utf-8')
                    }
                    send_message(conn, file_msg)
                    print(f"[TX] Sent File: {filename}")
                else:
                    send_message(conn, {"Type": "Error", "Message": "File not found"})

            elif msg_type == "CreateDir":
                if not auth_db.check_permission(user.username, 'WRITE'):
                    send_message(conn, {"Type": "Error", "Message": "Permission Denied: WRITE access required."})
                    continue

                name = msg.get('Name')
                path = msg.get("ParentPath", "")
                print(f"[RX] CreateDir: {name}")
                
                # Determine if creating in shared folder
                is_shared_path = (path == "shared" or path.startswith("shared/"))
                
                if is_shared_path:
                    relative = path[len("shared"):].lstrip("/")
                    target_dir = os.path.normpath(os.path.join(SHARED_STORAGE_ROOT, relative, name))
                    allowed_root = SHARED_STORAGE_ROOT
                else:
                    target_dir = os.path.normpath(os.path.join(USER_STORAGE_ROOT, path, name))
                    allowed_root = USER_STORAGE_ROOT
                
                if target_dir.startswith(allowed_root):
                    if not os.path.exists(target_dir):
                        os.makedirs(target_dir)
                        send_message(conn, {"Type": "ActionAck", "Status": "Success"})
                    else:
                        send_message(conn, {"Type": "ActionAck", "Status": "Exists"})
                else:
                    send_message(conn, {"Type": "ActionAck", "Status": "Error"})

            elif msg_type == "DeletePath":
                if not auth_db.check_permission(user.username, 'DELETE'):
                    send_message(conn, {"Type": "Error", "Message": "Permission Denied: DELETE access required."})
                    continue

                path_to_del = msg.get('Path')
                print(f"[RX] DeletePath: {path_to_del}")
                
                # Determine if deleting from shared folder
                is_shared_path = (path_to_del == "shared" or path_to_del.startswith("shared/"))
                
                # Prevent deleting the shared root itself
                if path_to_del.rstrip("/") == "shared":
                    send_message(conn, {"Type": "ActionAck", "Status": "Error", "Message": "Cannot delete the shared folder root"})
                    continue
                
                if is_shared_path:
                    relative = path_to_del[len("shared"):].lstrip("/")
                    target_path = os.path.normpath(os.path.join(SHARED_STORAGE_ROOT, relative))
                    allowed_root = SHARED_STORAGE_ROOT
                else:
                    target_path = os.path.normpath(os.path.join(USER_STORAGE_ROOT, path_to_del))
                    allowed_root = USER_STORAGE_ROOT
                
                if target_path.startswith(allowed_root) and os.path.exists(target_path):
                     try:
                        if os.path.isdir(target_path):
                            import shutil
                            shutil.rmtree(target_path)
                        else:
                            os.remove(target_path)
                        send_message(conn, {"Type": "ActionAck", "Status": "Success"})
                     except Exception as e:
                        send_message(conn, {"Type": "ActionAck", "Status": "Error", "Message": str(e)})
                else:
                    send_message(conn, {"Type": "ActionAck", "Status": "Error", "Message": "Invalid Path"})

            elif msg_type == "ChunkUpload":
                # ── Resumable chunked upload ───────────────────────
                if not auth_db.check_permission(user.username, 'WRITE'):
                    send_message(conn, {"Type": "Error", "Message": "Permission Denied: WRITE access required."})
                    continue

                filename = msg.get('Filename')
                path = msg.get("Path", "")
                offset = msg.get("Offset", 0)
                total_size = msg.get("TotalSize", 0)
                is_final = msg.get("IsFinal", False)
                content_b64 = msg["Content"]
                nonce_b64 = msg["Nonce"]

                print(f"[RX] ChunkUpload: {filename} offset={offset} final={is_final}")

                try:
                    content = base64.b64decode(content_b64)
                    nonce = base64.b64decode(nonce_b64)
                    plaintext = utils.decrypt_data(server_state.session_key, nonce, content)

                    # Security check on first chunk only
                    if offset == 0:
                        is_valid, reason = FileValidator.validate(filename, plaintext)
                        if not is_valid:
                            print(f"[Security] MALICIOUS FILE BLOCKED: {filename} Reason: {reason}")
                            send_message(conn, {"Type": "ChunkAck", "Status": "Error", "Message": f"Security: {reason}"})
                            continue

                    # Determine target directory
                    is_shared_path = (path == "shared" or path.startswith("shared/"))
                    if is_shared_path:
                        relative = path[len("shared"):].lstrip("/")
                        target_dir = os.path.normpath(os.path.join(SHARED_STORAGE_ROOT, relative))
                        if not target_dir.startswith(SHARED_STORAGE_ROOT): target_dir = SHARED_STORAGE_ROOT
                    else:
                        target_dir = os.path.normpath(os.path.join(USER_STORAGE_ROOT, path))
                        if not target_dir.startswith(USER_STORAGE_ROOT): target_dir = USER_STORAGE_ROOT

                    if not os.path.exists(target_dir):
                        os.makedirs(target_dir)

                    part_path = os.path.join(target_dir, filename + ".part")
                    final_path = os.path.join(target_dir, filename)

                    # Write chunk at offset
                    mode = 'r+b' if os.path.exists(part_path) else 'wb'
                    with open(part_path, mode) as f:
                        f.seek(offset)
                        f.write(plaintext)

                    new_offset = offset + len(plaintext)

                    # If final chunk, rename .part to final file
                    if is_final:
                        if os.path.exists(final_path):
                            os.remove(final_path)
                        os.rename(part_path, final_path)
                        print(f"[TX] Chunked file complete: {final_path}")

                    send_message(conn, {
                        "Type": "ChunkAck",
                        "Status": "Success",
                        "BytesReceived": new_offset,
                        "Complete": is_final
                    })

                except Exception as e:
                    print(f"[Error] ChunkUpload failed: {e}")
                    send_message(conn, {"Type": "ChunkAck", "Status": "Error", "Message": str(e)})

            elif msg_type == "ChunkDownload":
                # ── Resumable chunked download ─────────────────────
                if not auth_db.check_permission(user.username, 'READ'):
                    send_message(conn, {"Type": "Error", "Message": "Permission Denied: READ access required."})
                    continue

                filename = msg.get('Filename')
                path = msg.get("Path", "")
                offset = msg.get("Offset", 0)
                chunk_size = msg.get("ChunkSize", 256 * 1024)

                print(f"[RX] ChunkDownload: {filename} offset={offset}")

                is_shared_path = (path == "shared" or path.startswith("shared/"))
                if is_shared_path:
                    relative = path[len("shared"):].lstrip("/")
                    target_path = os.path.normpath(os.path.join(SHARED_STORAGE_ROOT, relative, filename))
                    allowed_root = SHARED_STORAGE_ROOT
                else:
                    target_path = os.path.normpath(os.path.join(USER_STORAGE_ROOT, path, filename))
                    allowed_root = USER_STORAGE_ROOT

                if not target_path.startswith(allowed_root):
                    send_message(conn, {"Type": "Error", "Message": "Permission Denied"})
                elif os.path.exists(target_path):
                    total_size = os.path.getsize(target_path)

                    with open(target_path, 'rb') as f:
                        f.seek(offset)
                        chunk_data = f.read(chunk_size)

                    is_final = (offset + len(chunk_data)) >= total_size

                    nonce, ciphertext = utils.encrypt_data(server_state.session_key, chunk_data)
                    send_message(conn, {
                        "Type": "ChunkData",
                        "Filename": filename,
                        "Content": base64.b64encode(ciphertext).decode('utf-8'),
                        "Nonce": base64.b64encode(nonce).decode('utf-8'),
                        "Offset": offset,
                        "ChunkSize": len(chunk_data),
                        "TotalSize": total_size,
                        "IsFinal": is_final
                    })
                    print(f"[TX] ChunkData: {filename} offset={offset} size={len(chunk_data)} final={is_final}")
                else:
                    send_message(conn, {"Type": "Error", "Message": "File not found"})

            elif msg_type == "Disconnect":
                print("[RX] Disconnect.")
                break
            
            else:
                print(f"[Server] Unknown Type: {msg_type}")
                print(f"[Server] Unknown Type: {msg_type}")

    except Exception as e:
        print(f"Session Error: {e}", file=sys.stderr)
    
    print("Session ended.")


def start_server(cert_filename: str = "server_cert.json"):
    print_banner()
    print(f"[*] Binding to           : {HOST}:{PORT}")
    print(f"[*] Server Subject       : {SERVER_SUBJECT}")
    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[*] System Time          : {current_time}")
    
    # Retry logic for binding
    bind_retries = 3
    for attempt in range(bind_retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((HOST, PORT))
                s.listen(5)
                print(f"[*] Waiting for client connections on {HOST}:{PORT}...\n")
                
                while True:
                    try:
                        conn, addr = s.accept()
                        # Handling client in main thread (blocking) for simplicity, 
                        # but supports sequential reconnections.
                        server_state = ServerHandshakeState(cert_filename)
                        handle_client(conn, addr, server_state)
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                         print(f"[Server] Accept Error: {e}")
            break # Exit retry loop if successful
        except OSError as e:
             if e.errno == 10048: # Address in use
                 print(f"Port {PORT} in use, retrying in 1s...")
                 time.sleep(1)
             else:
                 raise e
        except KeyboardInterrupt:
            print("\nServer stopping...")
            break

if __name__ == '__main__':
    start_server()