#!/bin/bash
echo "Starting Q-SFTP in WSL..."
source venv/bin/activate

echo "Cleaning up old processes..."
# Kill process on port 8888 (Server) and 5000 (Flask) if they exist
fuser -k 8888/tcp > /dev/null 2>&1
fuser -k 5000/tcp > /dev/null 2>&1

echo "1. Starting Server..."
python3 Codes/Handshake/handshake_server.py &
SERVER_PID=$!

sleep 2

echo "2. Starting Flask App..."
python3 Codes/WebApp/app.py &
APP_PID=$!

sleep 3

echo "System Running. PIDs: Server=$SERVER_PID, App=$APP_PID"
echo "Access at http://127.0.0.1:5000"
echo "Press any key to stop..."
read -n 1 -s

kill $SERVER_PID
kill $APP_PID
echo "Stopped."
