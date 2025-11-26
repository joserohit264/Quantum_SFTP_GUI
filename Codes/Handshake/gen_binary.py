import os
import hashlib

def generate_binary_file(filename, size_mb):
    size_bytes = size_mb * 1024 * 1024
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_bytes))
    print(f"Generated {filename} ({size_mb} MB)")

def get_checksum(filename):
    with open(filename, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

if __name__ == "__main__":
    filename = "test_binary.bin"
    generate_binary_file(filename, 1) # 1 MB binary file
    print(f"SHA256: {get_checksum(filename)}")
