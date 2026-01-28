import sys
import os
import json
import base64
import argparse
from datetime import datetime, timezone

# Add path for utils and user_manager
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'Codes', 'Handshake')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'Codes', 'WebApp')))

import utils
from auth_manager import auth_db
from user_manager import user_manager
from dilithium_py.dilithium import Dilithium2

KEYS_DIR = os.path.join('Codes', 'CA', 'keys')
CERTS_DIR = os.path.join('Codes', 'Handshake', 'certs')

def create_user(username, role, cn_name, password):
    print(f"[*] Creating user '{username}' with role '{role}'...")
    
    # 1. Generate Dilithium Keys for the User
    pk, sk = Dilithium2.keygen()
    
    # Save Private Key (Simulating client storage)
    # utils.py expects keys in CA/keys with .bin extension
    sk_filename = os.path.join(KEYS_DIR, f"{cn_name}_private.bin")
    pk_filename = os.path.join(KEYS_DIR, f"{cn_name}_public.bin")
    
    with open(sk_filename, 'wb') as f:
        f.write(sk)
    with open(pk_filename, 'wb') as f:
        f.write(pk)
        
    print(f"    [KeyGen] Keys saved to {sk_filename}")

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
    
    cert_filename = os.path.join(CERTS_DIR, f"{cn_name}_cert.json")
    with open(cert_filename, 'w') as f:
        json.dump(cert, f, indent=4)
        
    print(f"    [Cert] Certificate signed and saved to {cert_filename}")
    
    # 4. Register in Server DB (for Handshake Server verification)
    success, msg = auth_db.add_user(username, role, cert_subject=subject)
    if success:
        print(f"    [ServerDB] User registered successfully: {msg}")
    else:
        print(f"    [ServerDB] Registration warning: {msg}")

    # 5. Register in Client User Manager (for Web Login)
    if password:
        # Map the login to the Certificate Common Name (or Subject)
        # user_manager expects the certificate 'key' name used by utils to load keys, which is the "CN" part usually if strictly following utils.load_dilithium_private_key
        # utils.load_dilithium_private_key(subject) -> loads "{subject}_private.bin"
        # We saved keys as "{cn_name}_private.bin". So we must pass `cn_name` as the certificate identifier.
        
        success, msg = user_manager.add_user(username, password, cn_name, role)
        if success:
             print(f"    [ClientDB] Web login created for user '{username}'.")
        else:
             print(f"    [ClientDB] Failed to create web login: {msg}")
    else:
        print("    [ClientDB] Skipped web login creation (no password provided).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a Q-SFTP User")
    parser.add_argument("username", help="Username for login")
    parser.add_argument("role", help="Role (Administrator, Standard, Guest)")
    parser.add_argument("cn_name", help="Common Name for Certificate (e.g., GuestClient)")
    parser.add_argument("--password", help="Password for Web Login", required=False)
    
    args = parser.parse_args()
    
    create_user(args.username, args.role, args.cn_name, args.password)
