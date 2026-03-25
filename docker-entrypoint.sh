#!/bin/bash
set -e

echo "==================================================="
echo "  Q-SFTP: Quantum-Safe Secure File Transfer"
echo "==================================================="
echo ""

# Ensure data directories exist
mkdir -p /app/Codes/Data/ca_keys
mkdir -p /app/Codes/Data/certs
mkdir -p /app/ServerStorage/shared

# Auto-Initialization Check
if [ ! -f "/app/Codes/Data/ca_keys/CA_private.bin" ]; then
    echo "[!] First run detected. Initializing Quantum-Safe Environment..."
    
    # Generate CA and Server Certificates
    cd Codes/CA
    echo " -> Generating Certificate Authority (CA) keys..."
    python ca_tool.py gen-keys CA
    
    echo " -> Generating Server keys and compiling CSR..."
    python ca_tool.py gen-keys Server
    python ca_tool.py init-csr server_csr.json --subject "Server"
    
    echo " -> Signing Server Certificate..."
    python ca_tool.py sign server_csr.json server_cert.json
    cd ../..
    
    # Create the default admin user
    echo " -> Creating default 'admin' user (Password: admin)..."
    python create_user.py admin Administrator "Admin" --password admin
    
    echo "Initialization Complete!"
    echo "---------------------------------------------------"
fi

# Start PQC Server in background
echo "[1/2] Starting PQC Handshake Server (Port 8888)..."
python Codes/Handshake/handshake_server.py &
SERVER_PID=$!

# Wait for server to initialize
sleep 2

# Start Flask WebApp in foreground
echo "[2/2] Starting Web Application (Port 5000)..."
echo ""
echo "  Access the interface at: http://localhost:5000"
echo "  Default login: admin / admin"
echo ""
python Codes/WebApp/app.py &
APP_PID=$!

# Handle graceful shutdown mapping signals
trap "echo 'Shutting down...'; kill -TERM $SERVER_PID $APP_PID 2>/dev/null; wait $SERVER_PID $APP_PID 2>/dev/null; exit 0" SIGTERM SIGINT

# Wait for either process to exit
wait -n $SERVER_PID $APP_PID
EXIT_CODE=$?

echo "A process exited with code $EXIT_CODE. Shutting down remaining processes..."
kill -TERM $SERVER_PID $APP_PID 2>/dev/null
wait $SERVER_PID $APP_PID 2>/dev/null

exit $EXIT_CODE
