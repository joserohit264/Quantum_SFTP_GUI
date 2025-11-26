# Q-SFTP: Quantum-Safe Secure File Transfer Protocol

## 1. Problem Statement
Traditional secure file transfer protocols (like SFTP/SCP) rely on classical cryptographic algorithms such as RSA and Diffie-Hellman. These algorithms are vulnerable to attacks from future large-scale quantum computers (Shor's Algorithm). As quantum computing advances, data encrypted today using these classical methods could be decrypted in the future ("Harvest Now, Decrypt Later").

**Q-SFTP** addresses this threat by implementing a **Post-Quantum Cryptography (PQC)** handshake. It replaces classical key exchange and signatures with quantum-resistant algorithms to ensure long-term security for sensitive file transfers.

## 2. Tech Stack
*   **Language**: Python 3.x
*   **Key Encapsulation Mechanism (KEM)**: [Kyber512](https://pypi.org/project/kyber-py/) (NIST PQC Winner for KEM)
*   **Digital Signatures**: [Dilithium2](https://pypi.org/project/dilithium-py/) (NIST PQC Winner for Signatures)
*   **Symmetric Encryption**: AES-256-GCM (for file encryption)
*   **Networking**: Python `socket` (TCP/IP)
*   **Environment**: Windows / WSL (Ubuntu) / Linux

## 3. Features
*   **Quantum-Safe Handshake**: Uses **Kyber512** for establishing a shared secret and **Dilithium2** for mutual authentication (Client & Server).
*   **Secure File Transfer**: Files are encrypted using **AES-GCM** with a session key derived from the quantum-safe handshake.
*   **Integrity & Authenticity**: Every handshake message is signed and verified. File integrity is ensured by AES-GCM authentication tags.
*   **Cross-Device Support**: Works over Local Area Network (LAN) between different devices.
*   **CLI Interface**: Simple command-line tools for server and client.
*   **File Support**: Supports transferring text, images, PDFs, and binary files (up to 10MB).

## 4. Installation & Setup

### Prerequisites
*   Python 3.8+
*   Virtual Environment (Recommended)

### Setup Steps
1.  **Clone/Navigate to the project root:**
    ```bash
    git clone https://github.com/joserohit264/Q_SFTP.git
    cd Q_SFTP
    ```

2.  **Create and Activate Virtual Environment:**
    *   **Linux/WSL:**
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```
    *   **Windows (PowerShell):**
        ```powershell
        python -m venv venv
        .\venv\Scripts\Activate.ps1
        ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 5. Usage Commands

### Scenario A: Same Device (Two Terminal Tabs)
Use this for local testing and development.

**Terminal 1 (Server):**
```bash
cd Codes/Handshake
python handshake_server.py
```

**Terminal 2 (Client):**
You can send a text message or a file.
```bash
cd Codes/Handshake

# Send a text message
python handshake_client.py "Hello Quantum World!"

# Send a file (Relative Path)
python handshake_client.py my_document.pdf

# Send a file (Absolute Path - WSL Example)
python handshake_client.py "/mnt/c/Users/ADMIN/Pictures/image.jpg"
```

---

### Scenario B: Across Different Devices (LAN)
Use this to transfer files between two computers on the same Wi-Fi/Network.

**Device 1 (Server):**
1.  Find your Local IP Address:
    *   **Windows**: `ipconfig` (Look for IPv4 Address, e.g., `192.168.1.10`)
    *   **Linux/WSL**: `ip addr` or `hostname -I`
2.  Start the Server:
    ```bash
    cd Codes/Handshake
    python handshake_server.py
    ```

**Device 2 (Client):**
1.  Set the `SERVER_IP` environment variable to Device 1's IP address.
2.  Run the client.

*   **Linux / macOS / WSL:**
    ```bash
    export SERVER_IP="192.168.1.10"  # Replace with Server's IP
    python handshake_client.py "secret_file.txt"
    ```

*   **Windows (PowerShell):**
    ```powershell
    $env:SERVER_IP="192.168.1.10"
    python handshake_client.py "secret_file.txt"
    ```

*   **Windows (CMD):**
    ```cmd
    set SERVER_IP=192.168.1.10
    python handshake_client.py "secret_file.txt"
    ```

## 6. Project Structure
*   `Codes/Handshake/`: Contains the core protocol logic (`handshake_server.py`, `handshake_client.py`, `utils.py`).
*   `Codes/CA/`: Certificate Authority tools for generating Dilithium keys and certificates.
*   `keys/` & `certs/`: Stores the generated cryptographic assets.
