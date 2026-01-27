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
    if not CLIENT_STATE["connected"]:
        return render_template('login.html')
    return render_template('index.html', username=CLIENT_STATE["username"])

@app.route('/login')
def login_page():
    return render_template('login.html')

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
    
    # Reset State
    CLIENT_STATE["socket"] = None
    CLIENT_STATE["connected"] = False
    CLIENT_STATE["session_key"] = None
    CLIENT_STATE["remote_path"] = ""
    CLIENT_STATE["username"] = "Guest"
    
    return jsonify({"status": "Disconnected"})

@app.route('/api/status')
def status():
    return jsonify({
        "connected": CLIENT_STATE["connected"],
        "remote_path": CLIENT_STATE.get("remote_path", ""),
        "username": CLIENT_STATE.get("username", "Guest")
    })

@app.route('/api/connect', methods=['POST'])
def connect_server():
    data = request.json
    host = data.get('ip', '127.0.0.1')
    username = data.get('username', 'User')
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
        
        # Dynamically determine the subject from the certificate file name or content attempt
        # Ideally, ClientHandshakeState should extract it from the loaded cert.
        # But looking at ClientHandshakeState init, it takes (cert_file, subject).
        # Let's inspect the cert file first to get the Subject.
        with open("client_cert.json", "r") as f:
            cert_data = json.load(f)
            # Subject format: "CN=Client,O=QuantumSFTP" OR just "Client"
            full_subject = cert_data.get("Subject", "Client")
            
            if "=" in full_subject:
                 # Assume standard DN format: CN=Name,...
                 cn_part = full_subject.split(",")[0]
                 current_subject_cn = cn_part.split("=")[1]
            else:
                 # Assume simple format: Name
                 current_subject_cn = full_subject

        client_state_logic = ClientHandshakeState("client_cert.json", current_subject_cn)
        client_hello = client_state_logic.generate_client_hello()
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(600) # Increased timeout for large file uploads
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
        CLIENT_STATE["username"] = username
        
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
            return jsonify({"success": True})
        else:
            return jsonify({"error": res.get("Message")}), 500
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
        filename = file.filename
        content = file.read()
            
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
            return jsonify({"success": True})
        else:
            return jsonify({"error": ack.get("Message", "Upload failed")}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
