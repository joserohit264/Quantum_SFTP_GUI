import sys
import os
import json
import base64
from datetime import datetime, timezone

# Add path for utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'Codes', 'Handshake')))
import utils
from auth_manager import auth_db
from dilithium_py.dilithium import Dilithium2

KEYS_DIR = os.path.join('Codes', 'CA', 'keys')
CERTS_DIR = os.path.join('Codes', 'Handshake', 'certs')

def create_user(username, role, cn_name):
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
    
    # 4. Register in DB
    # We strip CN=... for the subject match in auth_manager if we implemented strict checking,
    # but based on my earlier code in handshake_server.py: 
    # cert_subject = client_hello["client_cert"].get("Subject")
    # user = auth_db.get_user_by_subject(cert_subject)
    
    # So we must register the FULL subject "CN=...,O=..."
    
    success, msg = auth_db.add_user(username, role, cert_subject=subject)
    if success:
        print(f"    [DB] User registered successfully: {msg}")
    else:
        print(f"    [DB] Registration warning: {msg}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_user.py <username> <role> [common_name]")
        print("Roles: Administrator, Standard, Guest")
        sys.exit(1)
        
    u = sys.argv[1]
    r = sys.argv[2]
    cn = sys.argv[3] if len(sys.argv) > 3 else u.capitalize()
    
    create_user(u, r, cn)
