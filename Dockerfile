FROM python:3.11-slim

LABEL maintainer="joserohit264"
LABEL description="Q-SFTP: Quantum-Safe Secure File Transfer Protocol"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (Docker cache optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project
COPY . .

# Create necessary directories
RUN mkdir -p ServerStorage/shared \
    && mkdir -p Codes/Data \
    && mkdir -p Codes/Handshake/certs

# Fix line endings and make entrypoint executable
RUN sed -i 's/\r$//' docker-entrypoint.sh && chmod +x docker-entrypoint.sh

# Expose ports: 8888 (PQC Server), 5000 (Flask WebApp)
EXPOSE 8888 5000

ENTRYPOINT ["./docker-entrypoint.sh"]
