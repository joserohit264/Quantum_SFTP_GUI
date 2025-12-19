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
    "current_dir": os.path.expanduser("~"), # Local dir
    "remote_path": "", # Remote dir relative to Storage Root
    "transfer_queue": [], 
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
    if not CLIENT_STATE["connected"]:
        return render_template('login.html')
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        s = CLIENT_STATE["socket"]
        if s:
            try:
                # Optional: Send disconnect message to server
                send_message(s, {"Type": "Disconnect"})
            except: 
                pass
            s.close()
    except:
        pass
    
    # Reset State
    CLIENT_STATE["socket"] = None
    CLIENT_STATE["connected"] = False
    CLIENT_STATE["session_key"] = None
    CLIENT_STATE["remote_path"] = ""
    
    return jsonify({"status": "Disconnected"})



@app.route('/api/local/files')
def list_local_files():
    directory = request.args.get('path', CLIENT_STATE["current_dir"])
    
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
        # PQC Handshake (Same as before)
        cert_path = os.path.join(handshake_dir, "client_cert.json")
        original_cwd = os.getcwd()
        os.chdir(handshake_dir)
        
        client_state_logic = ClientHandshakeState("client_cert.json", "Client")
        client_hello = client_state_logic.generate_client_hello()
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10) 
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
        
        os.chdir(original_cwd)
        
        CLIENT_STATE["socket"] = s
        CLIENT_STATE["connected"] = True
        CLIENT_STATE["handshake_state"] = client_state_logic
        CLIENT_STATE["session_key"] = session_key
        CLIENT_STATE["remote_path"] = "" # Reset to root
        
        return jsonify({
            "status": "Handshake Successful",
            "connected": True,
            "security": {
                 "kem": "Kyber-512",
                 "auth": "Dilithium-2",
                 "session_key_fingerprint": session_key[:4].hex()
            }
        })

    except Exception as e:
        os.chdir(original_cwd)
        if 's' in locals() and s:
            s.close()
        logging.exception("Connection failed")
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/files')
def list_remote_files():
    if not CLIENT_STATE["connected"]:
        return jsonify({"error": "Not connected"}), 400
        
    path = request.args.get('path', CLIENT_STATE["remote_path"])

    try:
        s = CLIENT_STATE["socket"]
        req = {
            "Type": "ListFiles",
            "Path": path
        }
        send_message(s, req)
        
        response = receive_message(s)
        
        if response.get("Type") == "FileList":
            CLIENT_STATE["remote_path"] = path # Update state on success
            return jsonify({
                "files": response.get("Files", []),
                "current_path": path
            })
        else:
            return jsonify({"error": f"Unexpected response: {response.get('Type')}"}), 500

    except Exception as e:
        CLIENT_STATE["connected"] = False
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/mkdir', methods=['POST'])
def create_remote_dir():
    if not CLIENT_STATE["connected"]:
        return jsonify({"error": "Not connected"}), 400
        
    data = request.json
    name = data.get('name')
    if not name: return jsonify({"error": "Name required"}), 400
    
    try:
        s = CLIENT_STATE["socket"]
        req = {
            "Type": "CreateDir",
            "Foldername": name,
            "Path": CLIENT_STATE["remote_path"]
        }
        send_message(s, req)
        
        ack = receive_message(s)
        if ack.get("Type") == "ActionAck" and ack.get("Status") == "Success":
             return jsonify({"status": "Created"})
        elif ack.get("Status") == "Exists":
             return jsonify({"error": "Folder already exists"}), 400
        else:
             return jsonify({"error": ack.get("Message", "Unknown Error")}), 500
             
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
        # Request Download
        req = {
            "Type": "DownloadFile",
            "Filename": filename,
            "Path": CLIENT_STATE["remote_path"]
        }
        send_message(s, req)
        
        # Wait for FileTransfer
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
            
            # Save to Local Current Dir
            save_path = os.path.join(CLIENT_STATE["current_dir"], filename)
            with open(save_path, "wb") as f:
                f.write(plaintext)
            
            return jsonify({"status": "Downloaded", "path": save_path})
        else:
             return jsonify({"error": "Unexpected response"}), 500
             
    except Exception as e:
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
        filename = os.path.basename(local_path)
        with open(local_path, "rb") as f:
            content = f.read()
            
        nonce, ciphertext = utils.encrypt_data(CLIENT_STATE["session_key"], content)
        
        # Send with Path
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
        if ack.get("Type") == "TransferAck":
            return jsonify({"status": "File Sent", "filename": filename})
        else:
            return jsonify({"error": "No Ack received"}), 500
        
    except Exception as e:
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

@app.route('/api/remote/delete', methods=['POST'])
def delete_remote_item():
    if not CLIENT_STATE["connected"]:
        return jsonify({"error": "Not connected"}), 400
        
    data = request.json
    filename = data.get('filename')
    if not filename: return jsonify({"error": "File selection required"}), 400
    
    try:
        s = CLIENT_STATE["socket"]
        req = {
            "Type": "DeletePath",
            "Filename": filename,
            "Path": CLIENT_STATE["remote_path"]
        }
        send_message(s, req)
        
        ack = receive_message(s)
        if ack.get("Type") == "ActionAck" and ack.get("Status") == "Success":
             return jsonify({"status": "Deleted"})
        else:
             return jsonify({"error": ack.get("Message", "Delete failed")}), 500
             
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/status')
def status():
    return jsonify({
        "connected": CLIENT_STATE["connected"],
        "server": f"{CLIENT_STATE['socket'].getpeername()[0]}" if CLIENT_STATE["connected"] else None
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
