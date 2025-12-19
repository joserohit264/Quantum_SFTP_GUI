import os
import sys
import json
import threading
import logging
from flask import Flask, render_template, jsonify, request, send_from_directory

# Configure paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
handshake_dir = os.path.join(project_root, 'Handshake')

# Import Handshake Client Logic
sys.path.append(handshake_dir)

# Attempt to import client logic. 
# We might need to refactor handshake_client.py slightly or use it as is if it's modular enough.
# Looking at the file, 'ClientHandshakeState' and 'utils' are available.
try:
    import utils
    from handshake_client import ClientHandshakeState, send_message, receive_message, Kyber512
except ImportError as e:
    print(f"Error importing Handshake modules: {e}")
    sys.exit(1)

import socket
import base64
import time
from datetime import datetime

app = Flask(__name__)

# --- Global State (Simple Single-User for Demo) ---
CLIENT_STATE = {
    "socket": None,
    "connected": False,
    "handshake_state": None,
    "current_dir": os.path.expanduser("~"), # Default to user home
    "transfer_queue": [], # List of transfer structs
    "session_key": None
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
    return render_template('index.html')

@app.route('/api/local/files')
def list_local_files():
    directory = request.args.get('path', CLIENT_STATE["current_dir"])
    
    # Validation/Security check (Basic)
    if not os.path.exists(directory):
        return jsonify({"error": "Directory not found"}), 404

    try:
        items = os.listdir(directory)
        files_data = []
        for item in items:
            full_path = os.path.join(directory, item)
            info = get_file_info(full_path)
            if info:
                files_data.append(info)
        
        # Sort: Directories first, then files
        files_data.sort(key=lambda x: (x['type'] != 'dir', x['name'].lower()))
        
        CLIENT_STATE["current_dir"] = directory
        return jsonify({
            "current_path": directory,
            "files": files_data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/connect', methods=['POST'])
def connect_server():
    data = request.json
    host = data.get('ip', '127.0.0.1')
    try:
        port = int(data.get('port', 8888))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid port number"}), 400

    if CLIENT_STATE["connected"] and CLIENT_STATE["socket"]:
        return jsonify({"status": "Already connected", "connected": True})

    try:
        # Load logic similar to start_client() in handshake_client.py
        # We need to ensure we run from the correct directory or find the certs
        # The certs are in Codes/Handshake, but we are running from Codes/WebApp
        # We need to change cwd or provide absolute paths to ClientHandshakeState
        
        cert_path = os.path.join(handshake_dir, "client_cert.json")
        # key_subject logic in handshake_client loads from 'keys/' based on subject name
        # utils.load_dilithium_private_key uses 'keys/{subject}_priv.key'
        # We need to make sure 'utils' looks in the right place. 
        # utils.py seems to use relative paths. Let's see if we need to chdir.
        
        # HACK: Change CWD to Handshake dir for the duration of the init, or update utils?
        # Better: run this app from project root, or let's try setting CWD for now.
        original_cwd = os.getcwd()
        os.chdir(handshake_dir)
        
        client_state_logic = ClientHandshakeState("client_cert.json", "Client")
        client_hello = client_state_logic.generate_client_hello()
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10) # 10s timeout
        s.connect((host, port))
        
        # 1. Send ClientHello
        send_message(s, client_hello)
        
        # 2. Recv ServerHello
        server_hello = receive_message(s)
        
        # 2.1 Verify
        if not client_state_logic.verify_server_hello(server_hello):
            s.close()
            os.chdir(original_cwd)
            return jsonify({"error": "Server authentication failed (Signature/Cert Invalid)"}), 403
            
        # 3. Encaps (Kyber)
        client_key_share = client_state_logic.generate_key_share()
        send_message(s, client_key_share)
        
        # 5. ClientFinished
        client_finished = client_state_logic.generate_client_finished(client_key_share)
        send_message(s, client_finished)
        
        # 6. Recv ServerFinished
        _ = receive_message(s)
        
        # Derive Session Key
        session_key = utils.derive_session_key(
            client_state_logic.shared_key,
            client_state_logic.client_nonce,
            client_state_logic.server_hello["server_nonce"],
            client_state_logic.transcript_hash
        )
        
        # Restore CWD
        os.chdir(original_cwd)
        
        # Update State
        CLIENT_STATE["socket"] = s
        CLIENT_STATE["connected"] = True
        CLIENT_STATE["handshake_state"] = client_state_logic
        CLIENT_STATE["session_key"] = session_key
        
        return jsonify({
            "status": "Handshake Successful",
            "connected": True,
            "security": {
                 "kem": "Kyber-512",
                 "auth": "Dilithium-2",
                 "session_key_fingerprint": session_key[:4].hex() # Just a snippet
            }
        })

    except Exception as e:
        # Cleanup
        os.chdir(original_cwd) # Ensure we switch back
        if 's' in locals() and s:
            s.close()
        logging.exception("Connection failed")
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/files')
def list_remote_files():
    if not CLIENT_STATE["connected"]:
        return jsonify({"error": "Not connected"}), 400

    try:
        s = CLIENT_STATE["socket"]
        # Send ListFiles Encrypted Command
        # For now, simplistic structure based on server update
        req = {"Type": "ListFiles"}
        send_message(s, req)
        
        # Wait for Response
        # NOTE: This is synchronous and blocks the flask worker. 
        # In a real app we'd use async or queues. For demo it's fine.
        response = receive_message(s)
        
        if response.get("Type") == "FileList":
            return jsonify({"files": response.get("Files", [])})
        else:
            return jsonify({"error": f"Unexpected response: {response.get('Type')}"}), 500

    except Exception as e:
        CLIENT_STATE["connected"] = False
        return jsonify({"error": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if not CLIENT_STATE["connected"]:
         return jsonify({"error": "Not connected"}), 400
         
    data = request.json
    local_path = data.get('path')
    
    if not local_path or not os.path.exists(local_path):
        return jsonify({"error": "File not found"}), 404
        
    try:
        # Read File
        filename = os.path.basename(local_path)
        with open(local_path, "rb") as f:
            content = f.read()
            
        # Encrypt
        nonce, ciphertext = utils.encrypt_data(CLIENT_STATE["session_key"], content)
        
        # Send
        file_msg = {
            "Type": "FileTransfer",
            "Filename": filename,
            "Content": base64.b64encode(ciphertext).decode('utf-8'),
            "Nonce": base64.b64encode(nonce).decode('utf-8')
        }
        
        s = CLIENT_STATE["socket"]
        send_message(s, file_msg)
        
        # Wait for Ack
        ack = receive_message(s)
        if ack.get("Type") == "TransferAck":
            return jsonify({"status": "File Sent", "filename": filename})
        else:
            return jsonify({"error": "No Ack received"}), 500
        
    except Exception as e:
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

@app.route('/api/status')
def status():
    return jsonify({
        "connected": CLIENT_STATE["connected"],
        "server": f"{CLIENT_STATE['socket'].getpeername()[0]}" if CLIENT_STATE["connected"] else None
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
