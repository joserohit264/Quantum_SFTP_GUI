import sys
import os
import shutil

CERTS_DIR = os.path.join('Codes', 'Handshake', 'certs')
CLIENT_CERT_PATH = os.path.join('Codes', 'Handshake', 'client_cert.json')

def switch_user(cn_name):
    src_cert = os.path.join(CERTS_DIR, f"{cn_name}_cert.json")
    
    if not os.path.exists(src_cert):
        print(f"Error: Certificate for '{cn_name}' not found at {src_cert}")
        return
        
    print(f"Switching active user to '{cn_name}'...")
    shutil.copy(src_cert, CLIENT_CERT_PATH)
    print(f"Success! {CLIENT_CERT_PATH} updated.")
    print("Restart the client application to log in as this user.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python switch_user.py <common_name>")
        print("Example: python switch_user.py GuestClient")
        sys.exit(1)
        
    switch_user(sys.argv[1])
