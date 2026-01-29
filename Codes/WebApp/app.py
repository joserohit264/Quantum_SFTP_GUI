import os
import sys
import json
import threading
import logging
from flask import Flask, render_template, jsonify, request, send_from_directory, session

# Configure paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
handshake_dir = os.path.join(project_root, 'Handshake')

# Import Handshake Client Logic
sys.path.append(handshake_dir)
sys.path.append(current_dir) # Add WebApp dir for user_manager

try:
    import utils
    from handshake_client import ClientHandshakeState, send_message, receive_message, Kyber512
    from user_manager import user_manager
    from activity_logger import activity_logger
    from privacy_manager import privacy_manager
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

import socket
import base64
import time
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'quantum_sftp_secret_key' # Replace with a real secret in production

# --- Global State ---
CLIENT_STATE = {
    "socket": None,
    "connected": False,
    "handshake_state": None,
    "current_dir": os.path.expanduser("~"), 
    "remote_path": "", 
    "transfer_queue": [], 
    "session_key": None,
    "username": "Guest"
}

# --- Utils ---
def get_file_info(path):
    try:
        stats = os.stat(path)
        is_dir = os.path.isdir(path)
        return {
            "name": os.path.basename(path),
            "size": stats.st_size if not is_dir else 0,
            "type": "dir" if is_dir else "file",
            "modified": datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            "path": path
        }
    except Exception:
        return None

# --- Routes ---

@app.route('/')
def index():
    if not session.get('logged_in'):
        return render_template('login.html')
    return render_template('index.html', username=session.get('username', 'Guest'), role=session.get('role', 'Geust'))

@app.route('/login')
def login_page():
    if session.get('logged_in'):
        return render_template('index.html', username=session.get('username'), role=session.get('role'))
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    valid, result = user_manager.validate_user(username, password)
    
    if valid:
        user = result
        session['logged_in'] = True
        session['username'] = user['username'] if 'username' in user else username
        session['role'] = user['role']
        session['certificate_cn'] = user['certificate']
        
        # Update Global State for UI sync
        CLIENT_STATE["username"] = username
        
        # Log successful login
        activity_logger.log_login(username, success=True, ip_address=request.remote_addr)
        
        return jsonify({"success": True, "redirect": "/"})
    else:
        # Log failed login
        activity_logger.log_login(username, success=False, ip_address=request.remote_addr)
        return jsonify({"success": False, "message": result}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        s = CLIENT_STATE["socket"]
        if s:
            try:
                send_message(s, {"Type": "Disconnect"})
            except: 
                pass
            s.close()
    except:
        pass
    
    # Log logout before clearing session
    if session.get('username'):
        activity_logger.log_logout(session['username'], ip_address=request.remote_addr)
    
    # Reset State
    CLIENT_STATE["socket"] = None
    CLIENT_STATE["connected"] = False
    CLIENT_STATE["session_key"] = None
    CLIENT_STATE["remote_path"] = ""
    CLIENT_STATE["username"] = "Guest"
    
    session.clear()
    
    return jsonify({"status": "Disconnected", "redirect": "/login"})

@app.route('/api/status')
def status():
    return jsonify({
        "connected": CLIENT_STATE["connected"],
        "remote_path": CLIENT_STATE.get("remote_path", ""),
        "username": session.get("username", "Guest")
    })

@app.route('/api/connect', methods=['POST'])
def connect_server():
    if not session.get('logged_in'):
        return jsonify({"error": "User not logged in"}), 401

    data = request.json
    host = data.get('ip', '127.0.0.1')
    try:
        port = int(data.get('port', 8888))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid port number"}), 400

    if CLIENT_STATE["connected"] and CLIENT_STATE["socket"]:
        return jsonify({"status": "Already connected", "connected": True})

    try:
        # PQC Handshake
        original_cwd = os.getcwd()
        os.chdir(handshake_dir)
        
        # Determine Certificate based on logged-in user
        cn_name = session.get('certificate_cn')
        if not cn_name:
            # Fallback for legacy/dev support if no cert mapped
            cn_name = "GuestClient" 
            
        cert_filename = f"{cn_name}_cert.json"
        
        # Check if cert exists in certs dir
        certs_dir = os.path.join("certs") 
        full_cert_path = os.path.join(certs_dir, cert_filename)
        
        if not os.path.exists(full_cert_path) and not os.path.exists(cert_filename):
             # Try simple path if not in certs subdir (fallback)
             full_cert_path = cert_filename

        # If it's in certs dir, use that relative path for ClientHandshakeState
        # But wait, utils.py and handshake clients have specific assumptions about paths.
        # ClientHandshakeState takes `cert_filename`. 
        # Inside ClientHandshakeState: `with open(cert_filename, 'r') ...`
        # Inside `start_client`: it assumes files are local or provided via path.
        
        # We are chdir'd into handshake_dir.
        # Certs are usually in `handshake_dir/certs/`.
        
        if os.path.exists(os.path.join("certs", cert_filename)):
             cert_path_to_use = os.path.join("certs", cert_filename)
        elif os.path.exists(cert_filename):
             cert_path_to_use = cert_filename
        else:
             os.chdir(original_cwd)
             return jsonify({"error": f"Certificate for user '{cn_name}' not found: {cert_filename}"}), 500

        # Create Client Instance with specific user identity
        # Key Subject is also 'cn_name' as per our create_user convention
        try:
            client_state_logic = ClientHandshakeState(cert_path_to_use, cn_name)
        except Exception as e:
            os.chdir(original_cwd)
            return jsonify({"error": f"Failed to load user identity: {str(e)}"}), 500

        client_hello = client_state_logic.generate_client_hello()
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(600) 
        s.connect((host, port))
        
        send_message(s, client_hello)
        server_hello = receive_message(s)
        
        if not client_state_logic.verify_server_hello(server_hello):
            s.close()
            os.chdir(original_cwd)
            return jsonify({"error": "Server authentication failed"}), 403
            
        client_key_share = client_state_logic.generate_key_share()
        send_message(s, client_key_share)
        
        client_finished = client_state_logic.generate_client_finished(client_key_share)
        send_message(s, client_finished)
        
        _ = receive_message(s) # ServerFinished
        
        session_key = utils.derive_session_key(
            client_state_logic.shared_key,
            client_state_logic.client_nonce,
            client_state_logic.server_hello["server_nonce"],
            client_state_logic.transcript_hash
        )
        
        CLIENT_STATE["socket"] = s
        CLIENT_STATE["connected"] = True
        CLIENT_STATE["session_key"] = session_key
        CLIENT_STATE["remote_path"] = ""
        CLIENT_STATE["username"] = session.get('username')
        
        os.chdir(original_cwd)
        
        return jsonify({"status": "Handshake Successful", "connected": True})

    except Exception as e:
        os.chdir(original_cwd)
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/files')
def list_remote_files():
    if not CLIENT_STATE["connected"]:
         return jsonify({"error": "Not connected"}), 400
         
    path_arg = request.args.get('path', '')
    
    # Send ListFiles Command
    req = {
        "Type": "ListFiles",
        "Path": path_arg
    }
    
    try:
        s = CLIENT_STATE["socket"]
        send_message(s, req)
        res = receive_message(s)
        
        if res.get("Type") == "FileList":
            CLIENT_STATE["remote_path"] = res.get("CurrentPath", "")
            return jsonify({
                "current_path": res.get("CurrentPath", ""),
                "files": res.get("Files", [])
            })
        else:
            return jsonify({"error": res.get("Message", "Failed to list files")}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/mkdir', methods=['POST'])
def remote_mkdir():
    if not CLIENT_STATE["connected"]:
         return jsonify({"error": "Not connected"}), 400
    
    data = request.json
    name = data.get('name')
    parent = data.get('parent_path', '')
    
    req = {
        "Type": "CreateDir",
        "Name": name,
        "ParentPath": parent
    }
    
    try:
        s = CLIENT_STATE["socket"]
        send_message(s, req)
        res = receive_message(s)
        
        if res.get("Type") == "ActionAck" and res.get("Status") == "Success":
            # Log successful directory creation
            activity_logger.log_directory_create(
                session.get('username', 'unknown'),
                name,
                request.remote_addr
            )
            return jsonify({"success": True})
        else:
            return jsonify({"error": res.get("Message")}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/delete', methods=['POST'])
def remote_delete():
    if not CLIENT_STATE["connected"]:
         return jsonify({"error": "Not connected"}), 400
    
    data = request.json
    path_to_del = data.get('path')
    
    req = {
        "Type": "DeletePath",
        "Path": path_to_del
    }
    
    try:
        s = CLIENT_STATE["socket"]
        send_message(s, req)
        res = receive_message(s)
        
        if res.get("Type") == "ActionAck" and res.get("Status") == "Success":
            # Log successful deletion
            activity_logger.log_file_delete(
                session.get('username', 'unknown'),
                path_to_del,
                request.remote_addr
            )
            return jsonify({"success": True})
        else:
            return jsonify({"error": res.get("Message")}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/read', methods=['POST'])
def remote_read():
    if not CLIENT_STATE["connected"]:
        return jsonify({"error": "Not connected"}), 400
        
    data = request.json
    file_path = data.get('path')
    
    try:
        from hash_verifier import compute_data_hash, get_file_hash, compare_hashes
        
        s = CLIENT_STATE["socket"]
        
        # Request file download
        req = {
            "Type": "DownloadFile",
            "Filename": os.path.basename(file_path),
            "Path": os.path.dirname(file_path) or CLIENT_STATE["remote_path"]
        }
        send_message(s, req)
        
        res = receive_message(s)
        
        if res.get("Type") == "Error":
            return jsonify({"error": res.get("Message")}), 404
            
        if res.get("Type") == "FileTransfer":
            # Decrypt
            content_b64 = res["Content"]
            nonce_b64 = res["Nonce"]
            
            content = base64.b64decode(content_b64)
            nonce = base64.b64decode(nonce_b64)
            
            plaintext = utils.decrypt_data(CLIENT_STATE["session_key"], nonce, content)
            
            # HASH VERIFICATION: Compute current hash of downloaded file
            current_hash = compute_data_hash(plaintext)
            logger.info(f"Download hash for {os.path.basename(file_path)}: {current_hash[:16]}...")
            
            # Get stored hash from registry (construct full server path)
            username = session.get('username', 'unknown')
            remote_path = CLIENT_STATE["remote_path"]
            server_storage_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'ServerStorage',
                username, remote_path, os.path.basename(file_path)
            )
            server_storage_path = os.path.normpath(server_storage_path)
            
            stored_hash_entry = get_file_hash(server_storage_path)
            verification_status = "UNTRACKED"  # Default if not in registry
            
            if stored_hash_entry:
                stored_hash = stored_hash_entry.get('hash_sha256')
                if stored_hash and compare_hashes(current_hash, stored_hash):
                    verification_status = "VERIFIED"
                    logger.info(f"✓ Download verified: hash matches registry")
                else:
                    verification_status = "TAMPERED"
                    logger.warning(f"⚠ File tampering detected!")
                    logger.warning(f"  Current hash:  {current_hash}")
                    logger.warning(f"  Stored hash:   {stored_hash}")
                    
                    # Log security event
                    activity_logger.log_security_event(
                        username,
                        'download_hash_mismatch',
                        f"File: {os.path.basename(file_path)}, Current: {current_hash[:16]}..., Stored: {stored_hash[:16]}...",
                        request.remote_addr
                    )
            else:
                logger.info(f"File not in hash registry (uploaded before Phase 2): {os.path.basename(file_path)}")
            
            # Log successful download
            activity_logger.log_file_download(
                username,
                os.path.basename(file_path),
                request.remote_addr
            )
            
            # Return base64-encoded content with hash verification info
            return jsonify({
                "success": True,
                "content": base64.b64encode(plaintext).decode('utf-8'),
                "hash": current_hash,
                "stored_hash": stored_hash_entry.get('hash_sha256') if stored_hash_entry else None,
                "hash_algorithm": "SHA-256",
                "verification_status": verification_status,
                "file_size": len(plaintext)
            })
        else:
            return jsonify({"error": "Unexpected response"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/download', methods=['POST'])
def download_file():
    if not CLIENT_STATE["connected"]:
         return jsonify({"error": "Not connected"}), 400
         
    data = request.json
    filename = data.get('filename')
    
    try:
        s = CLIENT_STATE["socket"]
        req = {
            "Type": "DownloadFile",
            "Filename": filename,
            "Path": CLIENT_STATE["remote_path"]
        }
        send_message(s, req)
        
        res = receive_message(s)
        
        if res.get("Type") == "Error":
             return jsonify({"error": res.get("Message")}), 404
             
        if res.get("Type") == "FileTransfer":
             # Decrypt
            content_b64 = res["Content"]
            nonce_b64 = res["Nonce"]
            
            content = base64.b64decode(content_b64)
            nonce = base64.b64decode(nonce_b64)
            
            plaintext = utils.decrypt_data(CLIENT_STATE["session_key"], nonce, content)
            
            # Log successful download
            activity_logger.log_file_download(
                session.get('username', 'unknown'),
                filename,
                request.remote_addr
            )
            
            # Save to temporary download folder or stream back?
            # Flask send_file can stream bytes
            import io
            return flask_send_file(io.BytesIO(plaintext), as_attachment=True, download_name=filename)
            
    except Exception as e:
         return jsonify({"error": str(e)}), 500

# Helper for download
from flask import send_file as flask_send_file

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if not CLIENT_STATE["connected"]:
         return jsonify({"error": "Not connected"}), 400

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        from hash_verifier import compute_data_hash, compare_hashes, register_file_hash
        
        filename = file.filename
        original_content = file.read()
        
        # HASH VERIFICATION: Get client-provided hash
        client_hash = request.form.get('file_hash', None)
        
        # Compute server-side hash of original content (before scrubbing)
        server_hash_original = compute_data_hash(original_content) if client_hash else None
        
        # Verify hash match if client provided one
        if client_hash:
            if not compare_hashes(client_hash, server_hash_original):
                # Hash mismatch - file corrupted during transfer
                logger.error(f"Upload hash mismatch for {filename}")
                logger.error(f"  Client hash: {client_hash}")
                logger.error(f"  Server hash: {server_hash_original}")
                
                # Log security event
                activity_logger.log_security_event(
                    session.get('username', 'unknown'),
                    'upload_hash_mismatch',
                    f"File: {filename}, Client: {client_hash[:16]}..., Server: {server_hash_original[:16]}...",
                    request.remote_addr
                )
                
                return jsonify({
                    "error": "File integrity check failed. Upload rejected.",
                    "details": "Hash mismatch detected - file may be corrupted"
                }), 400
            else:
                logger.info(f"✓ Upload hash verified for {filename}: {client_hash[:16]}...")
        
        # Privacy: Scrub metadata from file
        try:
            scrubbed_content, metadata_removed = privacy_manager.scrub_file_metadata(
                original_content,
                filename
            )
        except Exception as scrub_err:
            # If scrubbing fails, use original content and log the error
            print(f"[WARNING] Metadata scrubbing failed for {filename}: {scrub_err}")
            scrubbed_content = original_content
            metadata_removed = {"error": str(scrub_err)}
        
        # Use scrubbed content for upload
        content = scrubbed_content
        
        # Compute hash of final content (after scrubbing) for registry
        final_hash = compute_data_hash(content)
            
        nonce, ciphertext = utils.encrypt_data(CLIENT_STATE["session_key"], content)
        
        file_msg = {
            "Type": "FileTransfer",
            "Filename": filename,
            "Path": CLIENT_STATE["remote_path"],
            "Content": base64.b64encode(ciphertext).decode('utf-8'),
            "Nonce": base64.b64encode(nonce).decode('utf-8')
        }
        
        s = CLIENT_STATE["socket"]
        send_message(s, file_msg)
        
        ack = receive_message(s)
        if ack.get("Status") == "Success":
            # Construct server storage path
            username = session.get('username', 'unknown')
            remote_path = CLIENT_STATE["remote_path"]
            server_storage_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'ServerStorage', 
                username, remote_path, filename
            )
            server_storage_path = os.path.normpath(server_storage_path)
            
            # Register hash in database (using post-scrubbing hash)
            try:
                file_id = register_file_hash(
                    filepath=server_storage_path,
                    hash_value=final_hash,
                    username=username,
                    filename=filename,
                    file_size=len(content),
                    algorithm='sha256'
                )
                logger.info(f"✓ Registered file hash: {file_id}")
            except Exception as hash_err:
                logger.warning(f"Failed to register hash: {hash_err}")
            
            # Log successful upload
            activity_logger.log_file_upload(
                username, 
                filename, 
                len(content),
                request.remote_addr
            )
            
            # Log metadata scrubbing if any was removed (with error handling)
            try:
                if metadata_removed and not metadata_removed.get('error'):
                    logger.info(f"Metadata scrubbed from {filename}: {metadata_removed}")
            except Exception as log_err:
                # Don't fail upload if logging fails
                print(f"Warning: Failed to log metadata scrubbing: {log_err}")
            
            return jsonify({
                "success": True,
                "hash": final_hash,
                "hash_verified": client_hash is not None
            })
        else:
            return jsonify({"error": ack.get("Message", "Upload failed")}), 500

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Upload error: {str(e)}"}), 500

# --- Admin Panel Routes ---

def admin_required(f):
    """Decorator to restrict routes to Administrator role only."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in') or session.get('role') != 'Administrator':
            return jsonify({"error": "Access denied. Administrator privileges required."}), 403
        return f(*args, **kwargs)
    return decorated_function

def create_user_programmatically(username, password, role, cn_name):
    """
    Programmatically creates a user with quantum certificate and database entries.
    Mirrors the logic from create_user.py script.
    """
    import base64
    from datetime import timezone
    from dilithium_py.dilithium import Dilithium2
    from auth_manager import auth_db
    
    try:
        # 1. Generate Dilithium Keys
        pk, sk = Dilithium2.keygen()
        
        # Correct paths: project_root is already at 'Codes' level
        keys_dir = os.path.join(project_root, 'CA', 'keys')
        certs_dir = os.path.join(handshake_dir, 'certs')
        
        sk_filename = os.path.join(keys_dir, f"{cn_name}_private.bin")
        pk_filename = os.path.join(keys_dir, f"{cn_name}_public.bin")
        
        with open(sk_filename, 'wb') as f:
            f.write(sk)
        with open(pk_filename, 'wb') as f:
            f.write(pk)
        
        # 2. Create Certificate
        pub_key_b64 = base64.b64encode(pk).decode('utf-8')
        subject = f"CN={cn_name},O=QuantumSFTP"
        
        cert = {
            "SerialNumber": utils.generate_serial(),
            "Subject": subject,
            "Issuer": "CN=Quantum-CA",
            "PublicKeyAlgorithm": "CRYSTALS-Dilithium-2",
            "Public_Key": pub_key_b64,
            "Validity_Not_Before": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Validity_Not_After": "2030-12-31T23:59:59Z"
        }
        
        # 3. Sign Certificate with CA Key
        ca_priv_key = utils.load_dilithium_private_key("CA")
        msg_to_sign = utils.serialize_for_signing(cert)
        signature = utils.sign_message(ca_priv_key, msg_to_sign)
        cert["Signature"] = signature
        
        cert_filename = os.path.join(certs_dir, f"{cn_name}_cert.json")
        with open(cert_filename, 'w') as f:
            json.dump(cert, f, indent=4)
        
        # 4. Register in Server DB
        auth_db.add_user(username, role, cert_subject=subject)
        
        # 5. Register in Client User Manager
        user_manager.add_user(username, password, cn_name, role)
        
        # 6. Create user storage directory (Codes/../ServerStorage = Q_SFTP/ServerStorage)
        storage_dir = os.path.join(project_root, '..', 'ServerStorage', username)
        os.makedirs(storage_dir, exist_ok=True)
        
        return True, "User created successfully"
    
    except Exception as e:
        return False, str(e)

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = user_manager.list_all_users()
    return render_template('admin.html', users=users)

@app.route('/admin/create_user', methods=['POST'])
@admin_required
def admin_create_user():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role = data.get('role', 'Guest')
    
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    
    if user_manager.user_exists(username):
        return jsonify({"success": False, "message": "Username already exists"}), 400
    
    # Generate certificate name
    cn_name = f"{username.capitalize()}Client"
    
    success, msg = create_user_programmatically(username, password, role, cn_name)
    
    if success:
        # Log admin action
        activity_logger.log_user_created(
            session.get('username'),
            username,
            role,
            request.remote_addr
        )
        return jsonify({"success": True, "message": msg})
    else:
        return jsonify({"success": False, "message": msg}), 500

@app.route('/admin/delete_user/<username>', methods=['DELETE'])
@admin_required
def admin_delete_user(username):
    if username == session.get('username'):
        return jsonify({"success": False, "message": "Cannot delete your own account"}), 400
    
    success, msg = user_manager.delete_user(username)
    
    if success:
        # Log admin action
        activity_logger.log_user_deleted(
            session.get('username'),
            username,
            request.remote_addr
        )
        return jsonify({"success": True, "message": msg})
    else:
        return jsonify({"success": False, "message": msg}), 404

@app.route('/admin/update_role/<username>', methods=['POST'])
@admin_required
def admin_update_role(username):
    data = request.json
    new_role = data.get('role')
    
    if not new_role or new_role not in ['Administrator', 'Standard', 'Guest']:
        return jsonify({"success": False, "message": "Invalid role"}), 400
    
    success, msg = user_manager.update_user_role(username, new_role)
    
    if success:
        # Log admin action
        activity_logger.log_role_change(
            session.get('username'),
            username,
            new_role,
            request.remote_addr
        )
        return jsonify({"success": True, "message": msg})
    else:
        return jsonify({"success": False, "message": msg}), 404

# Activity Logs API

@app.route('/api/admin/logs', methods=['GET'])
@admin_required
def get_activity_logs():
    """Get activity logs with optional filters."""
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    username_filter = request.args.get('username', None)
    action_filter = request.args.get('action', None)
    
    logs = activity_logger.get_logs(
        limit=limit,
        offset=offset,
        username_filter=username_filter,
        action_filter=action_filter
    )
    
    return jsonify({"success": True, "logs": logs})

@app.route('/api/admin/user_stats/<username>', methods=['GET'])
@admin_required
def get_user_stats(username):
    """Get statistics for a specific user."""
    stats = activity_logger.get_user_statistics(username)
    return jsonify({"success": True, "stats": stats})

@app.route('/admin/reset_password/<username>', methods=['POST'])
@admin_required
def admin_reset_password(username):
    """Reset a user's password."""
    data = request.json
    new_password = data.get('password', '').strip()
    
    if not new_password:
        return jsonify({"success": False, "message": "Password is required"}), 400
    
    if len(new_password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"}), 400
    
    success, msg = user_manager.reset_password(username, new_password)
    
    if success:
        # Log admin action
        activity_logger.log_role_change(
            session.get('username'),
            username,
            'password_reset',
            request.remote_addr
        )
        return jsonify({"success": True, "message": msg})
    else:
        return jsonify({"success": False, "message": msg}), 404

# Integrity Checker API (Phase 4)

@app.route('/api/admin/integrity/status', methods=['GET'])
@admin_required
def get_integrity_status():
    """Get current integrity checker status."""
    try:
        from integrity_checker import get_checker_status
        status = get_checker_status()
        return jsonify({"success": True, "status": status})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/admin/integrity/check', methods=['POST'])
@admin_required
def trigger_integrity_check():
    """Manually trigger an integrity check."""
    try:
        from integrity_checker import trigger_manual_check
        
        # Run check in background thread to avoid blocking
        import threading
        
        def run_check():
            results = trigger_manual_check()
            logger.info(f"Manual integrity check completed: {results}")
        
        thread = threading.Thread(target=run_check)
        thread.start()
        
        return jsonify({
            "success": True,
            "message": "Integrity check started in background"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/admin/integrity/stats', methods=['GET'])
@admin_required
def get_integrity_stats():
    """Get hash registry statistics."""
    try:
        from hash_verifier import hash_verifier
        stats = hash_verifier.get_registry_stats()
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == '__main__':
    # Start integrity monitoring in background
    try:
        from integrity_checker import start_integrity_monitoring
        start_integrity_monitoring()
        logger.info("✓ Integrity monitoring started")
    except Exception as e:
        logger.warning(f"Failed to start integrity monitoring: {e}")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
