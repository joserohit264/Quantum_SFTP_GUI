"""
File Integrity & Hash Verification Module for Q-SFTP

Provides cryptographic hash functions for ensuring file integrity throughout
upload, storage, and download operations. Uses SHA-256 (quantum-resistant
for collision attacks) as the primary algorithm.

Author: Q-SFTP Development Team
Created: 2026-01-29
"""

import hashlib
import hmac
import os
import json
import uuid
from datetime import datetime
from typing import Dict, Optional, Tuple, Any
import logging

logger = logging.getLogger(__name__)

# Constants
DEFAULT_ALGORITHM = 'sha256'
CHUNK_SIZE = 8192  # 8KB chunks for large file processing
HASH_REGISTRY_PATH = os.path.join(os.path.dirname(__file__), '..', 'Data', 'hash_registry.json')
HASH_HISTORY_PATH = os.path.join(os.path.dirname(__file__), '..', 'Data', 'hash_history.json')
HASH_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'hash_config.json')


class HashVerifier:
    """Core hash verification and integrity checking system"""
    
    def __init__(self, config_path: str = HASH_CONFIG_PATH):
        """Initialize hash verifier with configuration"""
        self.config = self._load_config(config_path)
        self.registry_path = HASH_REGISTRY_PATH
        self.history_path = HASH_HISTORY_PATH
        self._ensure_data_directories()
        
    def _load_config(self, config_path: str) -> Dict:
        """Load hash verification configuration"""
        default_config = {
            "enabled": True,
            "algorithm": "SHA-256",
            "verify_on_upload": True,
            "verify_on_download": True,
            "reject_on_mismatch": True,
            "integrity_checks": {
                "enabled": True,
                "interval_hours": 24,
                "alert_admin": True,
                "auto_quarantine": False
            },
            "version_control": {
                "enabled": True,
                "max_versions": 10
            }
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load config, using defaults: {e}")
                return default_config
        else:
            # Create default config
            try:
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to create config file: {e}")
            return default_config
    
    def _ensure_data_directories(self):
        """Ensure Data directory and registry files exist"""
        data_dir = os.path.dirname(self.registry_path)
        os.makedirs(data_dir, exist_ok=True)
        
        # Initialize registry if doesn't exist
        if not os.path.exists(self.registry_path):
            self._save_registry({
                "files": {},
                "metadata": {
                    "total_files": 0,
                    "last_check": None,
                    "corrupted_count": 0,
                    "missing_count": 0
                }
            })
        
        # Initialize history if doesn't exist
        if not os.path.exists(self.history_path):
            with open(self.history_path, 'w') as f:
                json.dump({}, f, indent=2)
    
    def compute_file_hash(self, filepath: str, algorithm: str = DEFAULT_ALGORITHM) -> Optional[str]:
        """
        Compute cryptographic hash of a file using chunked reading.
        
        Args:
            filepath: Absolute path to file
            algorithm: Hash algorithm ('sha256' or 'sha3_256')
            
        Returns:
            Hexadecimal hash string, or None if file doesn't exist
        """
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return None
        
        try:
            # Select hash algorithm
            if algorithm.lower() == 'sha256':
                hasher = hashlib.sha256()
            elif algorithm.lower() == 'sha3_256':
                hasher = hashlib.sha3_256()
            else:
                logger.error(f"Unsupported algorithm: {algorithm}")
                return None
            
            # Read file in chunks to handle large files
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
            
            hash_value = hasher.hexdigest()
            logger.debug(f"Computed {algorithm} hash for {filepath}: {hash_value[:16]}...")
            return hash_value
            
        except Exception as e:
            logger.error(f"Error computing hash for {filepath}: {e}")
            return None
    
    def compute_data_hash(self, data: bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
        """
        Compute hash of data in memory (for uploaded file data).
        
        Args:
            data: Bytes to hash
            algorithm: Hash algorithm
            
        Returns:
            Hexadecimal hash string
        """
        try:
            if algorithm.lower() == 'sha256':
                hasher = hashlib.sha256()
            elif algorithm.lower() == 'sha3_256':
                hasher = hashlib.sha3_256()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            hasher.update(data)
            return hasher.hexdigest()
            
        except Exception as e:
            logger.error(f"Error computing data hash: {e}")
            raise
    
    def compare_hashes(self, hash1: str, hash2: str) -> bool:
        """
        Constant-time hash comparison to prevent timing attacks.
        
        Args:
            hash1: First hash (hex string)
            hash2: Second hash (hex string)
            
        Returns:
            True if hashes match, False otherwise
        """
        # Use hmac.compare_digest for constant-time comparison
        # Convert to bytes first to ensure consistent comparison
        return hmac.compare_digest(hash1.encode(), hash2.encode())
    
    def verify_file_hash(self, filepath: str, expected_hash: str, 
                        algorithm: str = DEFAULT_ALGORITHM) -> Tuple[bool, str]:
        """
        Verify file integrity against expected hash.
        
        Args:
            filepath: Path to file
            expected_hash: Expected hash value
            algorithm: Hash algorithm
            
        Returns:
            (is_valid, current_hash) tuple
        """
        current_hash = self.compute_file_hash(filepath, algorithm)
        
        if current_hash is None:
            return (False, "")
        
        is_valid = self.compare_hashes(current_hash, expected_hash)
        return (is_valid, current_hash)
    
    def _load_registry(self) -> Dict:
        """Load hash registry from disk"""
        try:
            with open(self.registry_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading registry: {e}")
            return {"files": {}, "metadata": {}}
    
    def _save_registry(self, registry: Dict):
        """Save hash registry to disk"""
        try:
            with open(self.registry_path, 'w') as f:
                json.dump(registry, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving registry: {e}")
    
    def register_file_hash(self, filepath: str, hash_value: str, 
                          username: str, filename: str = None,
                          file_size: int = None, algorithm: str = DEFAULT_ALGORITHM) -> str:
        """
        Register a file's hash in the database.
        
        Args:
            filepath: Absolute path to file
            hash_value: Computed hash
            username: User who uploaded file
            filename: Original filename (optional, extracted from path if not provided)
            file_size: File size in bytes (optional, computed if not provided)
            algorithm: Hash algorithm used
            
        Returns:
            Unique file ID
        """
        registry = self._load_registry()
        
        # Generate unique ID
        file_id = str(uuid.uuid4())
        
        # Extract metadata
        if filename is None:
            filename = os.path.basename(filepath)
        
        if file_size is None and os.path.exists(filepath):
            file_size = os.path.getsize(filepath)
        
        # Create entry
        entry = {
            "filename": filename,
            "filepath": filepath,
            f"hash_{algorithm.lower()}": hash_value,
            "hash_algorithm": algorithm.upper(),
            "file_size": file_size,
            "uploaded_by": username,
            "upload_timestamp": datetime.now().isoformat(),
            "last_verified": datetime.now().isoformat(),
            "verification_status": "VALID",
            "version": 1
        }
        
        registry["files"][file_id] = entry
        registry["metadata"]["total_files"] = len(registry["files"])
        
        self._save_registry(registry)
        logger.info(f"Registered hash for {filename} (ID: {file_id})")
        
        return file_id
    
    def get_file_hash(self, filepath: str) -> Optional[Dict]:
        """
        Retrieve hash entry for a file by filepath.
        
        Args:
            filepath: Path to file
            
        Returns:
            Hash entry dict or None if not found
        """
        registry = self._load_registry()
        
        for file_id, entry in registry["files"].items():
            if entry["filepath"] == filepath:
                entry["file_id"] = file_id
                return entry
        
        return None
    
    def update_verification_status(self, file_id: str, status: str):
        """
        Update verification status for a file.
        
        Args:
            file_id: Unique file ID
            status: New status (VALID, CORRUPTED, MISSING, TAMPERED)
        """
        registry = self._load_registry()
        
        if file_id in registry["files"]:
            registry["files"][file_id]["verification_status"] = status
            registry["files"][file_id]["last_verified"] = datetime.now().isoformat()
            
            # Update metadata counts
            corrupted = sum(1 for f in registry["files"].values() 
                          if f["verification_status"] == "CORRUPTED")
            missing = sum(1 for f in registry["files"].values() 
                        if f["verification_status"] == "MISSING")
            
            registry["metadata"]["corrupted_count"] = corrupted
            registry["metadata"]["missing_count"] = missing
            registry["metadata"]["last_check"] = datetime.now().isoformat()
            
            self._save_registry(registry)
            logger.info(f"Updated status for {file_id}: {status}")
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """
        Get integrity statistics from registry.
        
        Returns:
            Statistics dict with counts and status
        """
        registry = self._load_registry()
        
        files = registry["files"]
        valid_count = sum(1 for f in files.values() if f["verification_status"] == "VALID")
        corrupted_count = sum(1 for f in files.values() if f["verification_status"] == "CORRUPTED")
        missing_count = sum(1 for f in files.values() if f["verification_status"] == "MISSING")
        tampered_count = sum(1 for f in files.values() if f["verification_status"] == "TAMPERED")
        
        return {
            "total_files": len(files),
            "valid": valid_count,
            "corrupted": corrupted_count,
            "missing": missing_count,
            "tampered": tampered_count,
            "last_check": registry["metadata"].get("last_check"),
            "health_percentage": (valid_count / len(files) * 100) if len(files) > 0 else 100.0
        }
    
    def get_user_files(self, username: str) -> list:
        """
        Get all files uploaded by a specific user.
        
        Args:
            username: Username to filter by
            
        Returns:
            List of file entries
        """
        registry = self._load_registry()
        user_files = []
        
        for file_id, entry in registry["files"].items():
            if entry["uploaded_by"] == username:
                entry["file_id"] = file_id
                user_files.append(entry)
        
        return sorted(user_files, key=lambda x: x["upload_timestamp"], reverse=True)


# Global instance
hash_verifier = HashVerifier()


# Convenience functions for easy import
def compute_file_hash(filepath: str, algorithm: str = DEFAULT_ALGORITHM) -> Optional[str]:
    """Compute hash of a file"""
    return hash_verifier.compute_file_hash(filepath, algorithm)


def compute_data_hash(data: bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Compute hash of data in memory"""
    return hash_verifier.compute_data_hash(data, algorithm)


def verify_file_hash(filepath: str, expected_hash: str, algorithm: str = DEFAULT_ALGORITHM) -> Tuple[bool, str]:
    """Verify file against expected hash"""
    return hash_verifier.verify_file_hash(filepath, expected_hash, algorithm)


def compare_hashes(hash1: str, hash2: str) -> bool:
    """Constant-time hash comparison"""
    return hash_verifier.compare_hashes(hash1, hash2)


def register_file_hash(filepath: str, hash_value: str, username: str, **kwargs) -> str:
    """Register file hash in database"""
    return hash_verifier.register_file_hash(filepath, hash_value, username, **kwargs)


def get_file_hash(filepath: str) -> Optional[Dict]:
    """Get hash entry for file"""
    return hash_verifier.get_file_hash(filepath)
