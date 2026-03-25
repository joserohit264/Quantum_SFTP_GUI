FROM python:3.11-slim as builder

LABEL maintainer="joserohit264"
LABEL description="Q-SFTP: Quantum-Safe Secure File Transfer Protocol"

# System dependencies for building cryptography and PQC libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels -r requirements.txt

# Final Stage
FROM python:3.11-slim
WORKDIR /app

# Copy built wheels and install
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache /wheels/* \
    && rm -rf /wheels

# Copy application source code
COPY . .

# Create necessary directories and symlinks to persist state in /app/Codes/Data
# This consolidates all DBs and Certs into a single mounted volume.
RUN mkdir -p /app/Codes/Data/ca_keys \
    && mkdir -p /app/Codes/Data/certs \
    && mkdir -p /app/ServerStorage/shared \
    && rm -rf /app/Codes/CA/keys \
    && ln -s /app/Codes/Data/ca_keys /app/Codes/CA/keys \
    && rm -rf /app/Codes/CA/certs \
    && ln -s /app/Codes/Data/certs /app/Codes/CA/certs \
    && rm -rf /app/Codes/Handshake/certs \
    && ln -s /app/Codes/Data/certs /app/Codes/Handshake/certs \
    && ln -s /app/Codes/Data/users.db /app/Codes/Handshake/users.db \
    && ln -s /app/Codes/Data/users.json /app/Codes/WebApp/users.json \
    && ln -s /app/Codes/Data/activity_logs.db /app/Codes/WebApp/activity_logs.db

# Fix line endings and permissions
RUN sed -i 's/\r$//' docker-entrypoint.sh && chmod +x docker-entrypoint.sh

# Expose ports
EXPOSE 8888 5000

# Set environment
ENV FLASK_ENV=production

ENTRYPOINT ["./docker-entrypoint.sh"]
