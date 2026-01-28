# Q-SFTP: Quantum-Safe Secure File Transfer Protocol

## 1. Problem Statement
Traditional secure file transfer protocols (like SFTP/SCP) rely on classical cryptographic algorithms such as RSA and Diffie-Hellman, which are vulnerable to future quantum computer attacks (Shor's Algorithm). **Q-SFTP** addresses this by implementing a **Post-Quantum Cryptography (PQC)** handshake, ensuring long-term data security against "Harvest Now, Decrypt Later" threats.

## 2. Tech Stack
*   **Language**: Python 3.x
*   **Web Framework**: Flask (for Web GUI)
*   **Key Encapsulation (KEM)**: [Kyber512](https://pypi.org/project/kyber-py/) (NIST PQC Winner)
*   **Digital Signatures**: [Dilithium2](https://pypi.org/project/dilithium-py/) (NIST PQC Winner)
*   **Symmetric Encryption**: AES-256-GCM
*   **Frontend**: HTML5, CSS3 (Variables for Theming), Vanilla JavaScript

## 3. Key Features
*   **Quantum-Safe Security**: Kyber512 for key exchange + Dilithium2 for authentication.
*   **Web GUI Dashboard**:
    *   **Dual-Pane Interface**: Familiar Local vs. Remote file browser.
    *   **Secure Login**: Authenticated session management.
    *   **File Operations**: Upload, Download, Create Folder, and **Secure Delete**.
    *   **Premium Themes**: toggle between professional **Dark** and **Light** modes.
*   **Encrypted Storage**: Files are encrypted in transit and can be stored securely.
*   **Cross-Platform**: Works on Windows, Linux, and via LAN.

## 4. Quick Start (Windows)
The easiest way to run the application is using the included batch script:

1.  **Double-click `start_q_sftp.bat`** in the project root.
2.  This will:
    *   Start the Secure Server.
    *   Start the Web Client.
    *   Open your browser to the Login Page (`http://127.0.0.1:5000`).
3.  **Login**:
    *   Host: `127.0.0.1` (or server IP)
    *   Port: `8888`

## 5. Manual Setup & Usage

### Prerequisites
*   Python 3.8+
*   `pip install -r requirements.txt`

### Running Manually
**1. Start the Server:**
```bash
python Codes/Handshake/handshake_server.py
```

**2. Start the Web Client:**
```bash
python Codes/WebApp/app.py
```

**3. Access the Interface:**
Open your browser and navigate to: `http://127.0.0.1:5000`

## 6. Project Structure
*   `Codes/Handshake/`: Core PQC protocol server & client logic.
*   `Codes/WebApp/`: Flask application, templates (Login/Dashboard), and static assets.
*   `Codes/CA/`: Certificate Authority tools.
*   `ServerStorage/`: Designated root directory for secure server file storage.


## 8. New Security Features
*   **Multi-User Access Control**:
    *   **Role-Based Access Control (RBAC)**: Supports roles like `Administrator` (Full Access), `Standard` (Read/Write), and `Guest` (Read-Only).
    *   **Directory Isolation**: Each user has a private storage directory (`ServerStorage/<username>`).
*   **Malicious File Protection**:
    *   **Pre-Storage Validation**: Uploads are scanned for dangerous extensions and magic number mismatches before being saved.

## 8. Privacy & Anti-Linkability Features

Q-SFTP implements privacy-enhancing features to prevent user tracking and protect metadata while maintaining security audit capabilities.

### Metadata Privacy
-   **Automatic Metadata Scrubbing**: Removes identifying information from uploaded files
    -   **Images** (JPG, PNG, GIF): Strips EXIF data (camera info, GPS, timestamps)
    -   **PDFs**: Removes author, creator, producer, and dates
    -   **Word Documents**: Removes author, company, last modified by
-   **Anonymized Statistics**: Aggregate analytics without individual tracking
-   **Configurable**: Enable/disable via `privacy_config.json`

### Network Privacy
-   **IP Address Hashing**: Network privacy with daily rotating salts
    -   Hashes IP addresses before storage in activity logs
    -   Daily salt rotation prevents long-term tracking
    -   Pattern detection possible within 24 hours only
    -   Original IP addresses never stored

### User Privacy Controls
-   **Dual-Layer Logging**: Full audit trail for security + anonymized stats for privacy
-   **Session Unlinkability**: Cryptographically secure session rotation
-   **File Categorization**: Privacy-preserving file type classification

### Testing Privacy Features
Run the comprehensive privacy test suite:
```bash
python test_privacy_features.py
```

Expected output:
```
✅ PASS - Configuration
✅ PASS - IP Hashing
✅ PASS - File Categorization
✅ PASS - Image Metadata
✅ PASS - PDF Metadata
✅ PASS - Word Metadata
```

### Privacy Configuration
Edit `Codes/WebApp/privacy_config.json`:
```json
{
  "metadata_scrubbing": {
    "enabled": true,
    "file_types": ["jpg", "jpeg", "png", "gif", "pdf", "docx"]
  },
  "ip_anonymization": {
    "enabled": true,
    "hash_length": 16
  }
}
```

### Compliance
These features protect against metadata harvesting and user behavior profiling while maintaining security compliance (GDPR, CCPA ready).

## 9. User Management & Demo
The system includes tools to manage users and demonstrate RBAC.

### Create a New User
Use `create_user.py` to generate credentials (keys/certs) and register a user.
```bash
# Usage: python create_user.py <username> <role> <Certificate_Name>
python3 create_user.py guest_user Guest GuestClient
```
*   **Roles**: `Administrator`, `Standard`, `Guest`.

### Switch Active User (Client)
To simulate inserting a different user's "Smart Card", use `switch_user.py`.
```bash
# Switch to Guest
python3 switch_user.py GuestClient

# Switch back to Standard User
python3 switch_user.py Client
```
*   **Note**: You must restart the application (`start_q_sftp.sh`) after switching users for changes to take effect.
