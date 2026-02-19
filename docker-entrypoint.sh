#!/bin/bash
set -e

echo "==================================================="
echo "  Q-SFTP: Quantum-Safe Secure File Transfer"
echo "==================================================="
echo ""

# Ensure shared directory exists
mkdir -p /app/ServerStorage/shared

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

# Handle graceful shutdown
trap "echo 'Shutting down...'; kill $SERVER_PID $APP_PID 2>/dev/null; exit 0" SIGTERM SIGINT

# Wait for either process to exit
wait -n $SERVER_PID $APP_PID
EXIT_CODE=$?

# If one process exits, kill the other
kill $SERVER_PID $APP_PID 2>/dev/null
exit $EXIT_CODE
