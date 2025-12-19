@echo off
echo ===================================================
echo   Starting Q-SFTP Quantum-Safe File Transfer System
echo ===================================================
echo.

echo 1. Starting Server (Phase 5 Protocol)...
start "Q-SFTP Server" python Codes/Handshake/handshake_server.py

:: Wait for server to initialize
timeout /t 2 >nul

echo 2. Starting Web Application (Flask)...
start "Q-SFTP WebClient" python Codes/WebApp/app.py

:: Wait for Flask to start
timeout /t 3 >nul

echo 3. Launching Interface...
start http://127.0.0.1:5000

echo.
echo System Running. 
echo Close the command windows to stop the servers.
pause
