"""
Periodic Integrity Checker for Q-SFTP

Runs automated background checks on all files in the hash registry
to detect tampering, corruption, or missing files. Runs every 24 hours
by default (configurable).

Features:
- Scheduled periodic checks
- Manual trigger via API
- Status updates in registry
- Admin alerts on detection
- Detailed logging

Author: Q-SFTP Development Team
Created: 2026-01-29
"""

import os
import time
import threading
import logging
from datetime import datetime
from typing import Dict, List
import schedule

# Import hash verification functions
from hash_verifier import hash_verifier, compute_file_hash, compare_hashes

logger = logging.getLogger(__name__)


class IntegrityChecker:
    """Background integrity verification system"""
    
    def __init__(self):
        self.is_running = False
        self.last_check_time = None
        self.check_results = {
            'total_files': 0,
            'verified': 0,
            'corrupted': 0,
            'missing': 0,
            'errors': 0
        }
        self.scheduler_thread = None
        
        # Load config
        config = hash_verifier.config.get('integrity_checks', {})
        self.enabled = config.get('enabled', True)
        self.interval_hours = config.get('interval_hours', 24)
        self.alert_admin = config.get('alert_admin', True)
        
    def verify_all_files(self) -> Dict:
        """
        Verify integrity of all files in the hash registry.
        
        Returns:
            Results dictionary with counts and details
        """
        logger.info("="*60)
        logger.info("Starting periodic integrity check...")
        logger.info("="*60)
        
        self.is_running = True
        start_time = time.time()
        
        # Reset results
        results = {
            'total_files': 0,
            'verified': 0,
            'corrupted': 0,
            'missing': 0,
            'errors': 0,
            'details': []
        }
        
        try:
            # Load registry
            registry = hash_verifier._load_registry()
            files = registry.get('files', {})
            results['total_files'] = len(files)
            
            logger.info(f"Checking {results['total_files']} files...")
            
            # Check each file
            for file_id, entry in files.items():
                filepath = entry.get('filepath')
                stored_hash = entry.get('hash_blake2b') or entry.get('hash_sha256')
                filename = entry.get('filename', 'unknown')
                
                logger.info(f"Checking: {filename}")
                
                try:
                    # Check if file exists
                    if not os.path.exists(filepath):
                        logger.warning(f"  ⚠ File missing: {filepath}")
                        hash_verifier.update_verification_status(file_id, 'MISSING')
                        results['missing'] += 1
                        results['details'].append({
                            'filename': filename,
                            'status': 'MISSING',
                            'path': filepath
                        })
                        continue
                    
                    # Compute current hash
                    current_hash = compute_file_hash(filepath)
                    
                    if current_hash is None:
                        logger.error(f"  ✗ Error computing hash: {filepath}")
                        results['errors'] += 1
                        continue
                    
                    # Compare hashes
                    if compare_hashes(current_hash, stored_hash):
                        logger.info(f"  ✓ Verified: {filename}")
                        hash_verifier.update_verification_status(file_id, 'VALID')
                        results['verified'] += 1
                        results['details'].append({
                            'filename': filename,
                            'status': 'VALID',
                            'hash': current_hash[:16] + '...'
                        })
                    else:
                        logger.warning(f"  ✗ CORRUPTED: {filename}")
                        logger.warning(f"    Current:  {current_hash}")
                        logger.warning(f"    Expected: {stored_hash}")
                        hash_verifier.update_verification_status(file_id, 'CORRUPTED')
                        results['corrupted'] += 1
                        results['details'].append({
                            'filename': filename,
                            'status': 'CORRUPTED',
                            'current_hash': current_hash[:16] + '...',
                            'stored_hash': stored_hash[:16] + '...'
                        })
                        
                        # Alert admin if enabled
                        if self.alert_admin:
                            self._send_corruption_alert(filename, filepath, current_hash, stored_hash)
                
                except Exception as e:
                    logger.error(f"  ✗ Error checking {filename}: {e}")
                    results['errors'] += 1
            
            # Update last check time
            self.last_check_time = datetime.now().isoformat()
            self.check_results = results
            
            # Calculate duration
            duration = time.time() - start_time
            
            logger.info("="*60)
            logger.info("Integrity check complete!")
            logger.info(f"  Total files: {results['total_files']}")
            logger.info(f"  ✓ Verified: {results['verified']}")
            logger.info(f"  ✗ Corrupted: {results['corrupted']}")
            logger.info(f"  ⚠ Missing: {results['missing']}")
            logger.info(f"  Errors: {results['errors']}")
            logger.info(f"  Duration: {duration:.2f}s")
            logger.info("="*60)
            
            return results
            
        except Exception as e:
            logger.error(f"Fatal error during integrity check: {e}")
            import traceback
            traceback.print_exc()
            return results
        finally:
            self.is_running = False
    
    def _send_corruption_alert(self, filename: str, filepath: str, 
                               current_hash: str, stored_hash: str):
        """
        Send alert to admin about corrupted file.
        
        Args:
            filename: Name of corrupted file
            filepath: Full path to file
            current_hash: Current computed hash
            stored_hash: Hash from registry
        """
        logger.critical("="*60)
        logger.critical("🚨 FILE CORRUPTION DETECTED 🚨")
        logger.critical(f"File: {filename}")
        logger.critical(f"Path: {filepath}")
        logger.critical(f"Current hash:  {current_hash}")
        logger.critical(f"Expected hash: {stored_hash}")
        logger.critical("Action required: Investigate immediately!")
        logger.critical("="*60)
        
        # Here you could add:
        # - Email notification
        # - Slack/Discord webhook
        # - SMS alert
        # - Dashboard notification
    
    def start_scheduler(self):
        """Start the background scheduler thread"""
        if not self.enabled:
            logger.info("Periodic integrity checks disabled in configuration")
            return
        
        logger.info(f"Starting integrity checker (interval: {self.interval_hours}h)")
        
        # Schedule periodic checks
        schedule.every(self.interval_hours).hours.do(self.verify_all_files)
        
        # Run scheduler in background thread
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        
        self.scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        logger.info("✓ Integrity checker started successfully")
    
    def trigger_manual_check(self) -> Dict:
        """
        Manually trigger an integrity check (for API endpoint).
        
        Returns:
            Check results dictionary
        """
        logger.info("Manual integrity check triggered")
        return self.verify_all_files()
    
    def get_status(self) -> Dict:
        """
        Get current status of integrity checker.
        
        Returns:
            Status information
        """
        return {
            'enabled': self.enabled,
            'is_running': self.is_running,
            'interval_hours': self.interval_hours,
            'last_check': self.last_check_time,
            'last_results': self.check_results
        }


# Global instance
integrity_checker = IntegrityChecker()


def start_integrity_monitoring():
    """Start the integrity monitoring system (call from app.py)"""
    integrity_checker.start_scheduler()


def trigger_manual_check():
    """Trigger manual integrity check (for API endpoint)"""
    return integrity_checker.trigger_manual_check()


def get_checker_status():
    """Get integrity checker status (for API endpoint)"""
    return integrity_checker.get_status()
