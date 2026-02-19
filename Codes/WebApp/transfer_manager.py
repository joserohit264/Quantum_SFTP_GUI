"""
Transfer Manager for Q-SFTP — Persistent Resumable Transfers

Tracks upload/download progress in transfer_log.json so that
interrupted transfers can resume from the last confirmed byte offset.

Author: Q-SFTP Development Team
Created: 2026-02-19
"""

import os
import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

logger = logging.getLogger(__name__)

TRANSFER_LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'Data', 'transfer_log.json')
CHUNK_SIZE = 256 * 1024  # 256 KB
STALE_HOURS = 24


class TransferManager:
    """Persistent transfer state manager for resumable uploads/downloads."""

    def __init__(self, log_path: str = TRANSFER_LOG_PATH):
        self.log_path = log_path
        self._ensure_log_file()

    # ── persistence ──────────────────────────────────────────────

    def _ensure_log_file(self):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        if not os.path.exists(self.log_path):
            self._save({"transfers": {}})

    def _load(self) -> Dict:
        try:
            with open(self.log_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {"transfers": {}}

    def _save(self, data: Dict):
        try:
            with open(self.log_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save transfer log: {e}")

    # ── public API ───────────────────────────────────────────────

    def init_transfer(self, filename: str, total_size: int,
                      file_hash: str, username: str,
                      remote_path: str, direction: str = "upload") -> Dict:
        """
        Create a new transfer session or return an existing one for resume.

        Returns dict with transfer_id, chunk_size, resume_offset.
        """
        data = self._load()

        # Check for an existing incomplete transfer of the same file
        for tid, entry in data["transfers"].items():
            if (entry["filename"] == filename and
                entry["username"] == username and
                entry["remote_path"] == remote_path and
                entry["direction"] == direction and
                entry["status"] == "active"):
                resume_offset = entry["bytes_transferred"]
                logger.info(f"Resuming transfer {tid} from offset {resume_offset}")
                return {
                    "transfer_id": tid,
                    "chunk_size": CHUNK_SIZE,
                    "resume_offset": resume_offset,
                    "total_size": entry["total_size"],
                    "resumed": True,
                }

        # Create new session
        tid = str(uuid.uuid4())
        data["transfers"][tid] = {
            "filename": filename,
            "total_size": total_size,
            "bytes_transferred": 0,
            "chunk_size": CHUNK_SIZE,
            "status": "active",
            "direction": direction,
            "file_hash": file_hash,
            "username": username,
            "remote_path": remote_path,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
        }
        self._save(data)
        logger.info(f"New {direction} transfer {tid}: {filename} ({total_size} bytes)")

        return {
            "transfer_id": tid,
            "chunk_size": CHUNK_SIZE,
            "resume_offset": 0,
            "total_size": total_size,
            "resumed": False,
        }

    def update_progress(self, transfer_id: str, bytes_transferred: int):
        """Update bytes_transferred after a successful chunk."""
        data = self._load()
        entry = data["transfers"].get(transfer_id)
        if entry:
            entry["bytes_transferred"] = bytes_transferred
            entry["updated_at"] = datetime.now().isoformat()
            self._save(data)

    def complete_transfer(self, transfer_id: str):
        """Mark transfer as complete."""
        data = self._load()
        entry = data["transfers"].get(transfer_id)
        if entry:
            entry["status"] = "complete"
            entry["updated_at"] = datetime.now().isoformat()
            self._save(data)
            logger.info(f"Transfer {transfer_id} complete")

    def fail_transfer(self, transfer_id: str, reason: str = ""):
        """Mark transfer as failed."""
        data = self._load()
        entry = data["transfers"].get(transfer_id)
        if entry:
            entry["status"] = "failed"
            entry["error"] = reason
            entry["updated_at"] = datetime.now().isoformat()
            self._save(data)

    def get_transfer(self, transfer_id: str) -> Optional[Dict]:
        """Get transfer entry by ID."""
        data = self._load()
        return data["transfers"].get(transfer_id)

    def cleanup_stale(self):
        """Remove transfers older than STALE_HOURS."""
        data = self._load()
        cutoff = datetime.now() - timedelta(hours=STALE_HOURS)
        to_remove = []

        for tid, entry in data["transfers"].items():
            try:
                updated = datetime.fromisoformat(entry["updated_at"])
                if updated < cutoff and entry["status"] in ("active", "failed"):
                    to_remove.append(tid)
            except Exception:
                to_remove.append(tid)

        for tid in to_remove:
            logger.info(f"Cleaning stale transfer: {tid}")
            del data["transfers"][tid]

        if to_remove:
            self._save(data)

        return len(to_remove)

    def get_active_transfers(self, username: str = None) -> list:
        """List active transfers, optionally filtered by username."""
        data = self._load()
        result = []
        for tid, entry in data["transfers"].items():
            if entry["status"] == "active":
                if username is None or entry["username"] == username:
                    entry["transfer_id"] = tid
                    result.append(entry)
        return result


# Global instance
transfer_manager = TransferManager()
