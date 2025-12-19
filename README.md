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

## 7. CLI Usage (Optional)
You can still use the command line for headless operations:
```bash
# Send a file
python Codes/Handshake/handshake_client.py "my_secret.txt"
```
