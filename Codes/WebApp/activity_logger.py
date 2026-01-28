import sqlite3
import os
from datetime import datetime
import threading
import json
import hashlib

DB_FILE = 'activity_logs.db'

class ActivityLogger:
    def __init__(self, db_path=None):
        if db_path is None:
            # Store in WebApp directory
            db_path = os.path.join(os.path.dirname(__file__), DB_FILE)
        
        self.db_path = db_path
        self.lock = threading.Lock()
        self.ip_anonymization_enabled = True  # Can be configured
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)
    
    def _get_daily_salt(self):
        """Generate salt based on current date (rotates at midnight UTC)."""
        date_str = datetime.utcnow().strftime('%Y-%m-%d')
        return hashlib.sha256(f"Q-SFTP-SALT-{date_str}".encode()).hexdigest()
    
    def anonymize_ip(self, ip_address):
        """Hash IP address with daily rotating salt."""
        if not self.ip_anonymization_enabled or not ip_address:
            return ip_address
        
        salt = self._get_daily_salt()
        return hashlib.sha256(f"{ip_address}{salt}".encode()).hexdigest()[:16]

    def _init_db(self):
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    status TEXT NOT NULL,
                    ip_address TEXT,
                    file_size INTEGER,
                    details TEXT
                )
            ''')
            
            # Create index for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_username ON activity_logs(username)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_action ON activity_logs(action)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON activity_logs(timestamp)
            ''')
            
            conn.commit()
            conn.close()

    def _log(self, username, action, target=None, status='success', ip_address=None, file_size=None, details=None):
        """Internal method to log an activity."""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            # Anonymize IP address before storing
            if ip_address:
                ip_address = self.anonymize_ip(ip_address)
            
            details_json = json.dumps(details) if details else None
            
            cursor.execute('''
                INSERT INTO activity_logs (username, action, target, status, ip_address, file_size, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, action, target, status, ip_address, file_size, details_json))
            
            conn.commit()
            conn.close()

    # Public logging methods
    
    def log_login(self, username, success=True, ip_address=None):
        """Log a login attempt."""
        status = 'success' if success else 'failed'
        self._log(username, 'login', status=status, ip_address=ip_address)

    def log_logout(self, username, ip_address=None):
        """Log a logout event."""
        self._log(username, 'logout', status='success', ip_address=ip_address)

    def log_file_upload(self, username, filename, file_size=0, ip_address=None):
        """Log a file upload."""
        self._log(username, 'upload', target=filename, status='success', 
                  ip_address=ip_address, file_size=file_size)

    def log_file_download(self, username, filename, ip_address=None):
        """Log a file download."""
        self._log(username, 'download', target=filename, status='success', ip_address=ip_address)

    def log_file_delete(self, username, filename, ip_address=None):
        """Log a file deletion."""
        self._log(username, 'delete', target=filename, status='success', ip_address=ip_address)

    def log_directory_create(self, username, dir_name, ip_address=None):
        """Log directory creation."""
        self._log(username, 'create_dir', target=dir_name, status='success', ip_address=ip_address)

    def log_user_created(self, admin_username, created_username, role, ip_address=None):
        """Log user creation by admin."""
        details = {'created_user': created_username, 'role': role}
        self._log(admin_username, 'user_create', target=created_username, 
                  status='success', ip_address=ip_address, details=details)

    def log_user_deleted(self, admin_username, deleted_username, ip_address=None):
        """Log user deletion by admin."""
        self._log(admin_username, 'user_delete', target=deleted_username, 
                  status='success', ip_address=ip_address)

    def log_role_change(self, admin_username, target_username, new_role, ip_address=None):
        """Log role change by admin."""
        details = {'new_role': new_role}
        self._log(admin_username, 'role_change', target=target_username, 
                  status='success', ip_address=ip_address, details=details)

    # Query methods
    
    def get_logs(self, limit=100, username_filter=None, action_filter=None, offset=0):
        """
        Retrieve activity logs with optional filters.
        Returns list of dicts.
        """
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            query = 'SELECT * FROM activity_logs WHERE 1=1'
            params = []
            
            if username_filter:
                query += ' AND username = ?'
                params.append(username_filter)
            
            if action_filter:
                query += ' AND action = ?'
                params.append(action_filter)
            
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            
            columns = [desc[0] for desc in cursor.description]
            logs = []
            for row in cursor.fetchall():
                log_dict = dict(zip(columns, row))
                # Parse details JSON if present
                if log_dict.get('details'):
                    try:
                        log_dict['details'] = json.loads(log_dict['details'])
                    except:
                        pass
                logs.append(log_dict)
            
            conn.close()
            return logs

    def get_user_statistics(self, username):
        """Get statistics for a specific user."""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            stats = {}
            
            # Total logins
            cursor.execute('''
                SELECT COUNT(*) FROM activity_logs 
                WHERE username = ? AND action = 'login' AND status = 'success'
            ''', (username,))
            stats['total_logins'] = cursor.fetchone()[0]
            
            # Files uploaded
            cursor.execute('''
                SELECT COUNT(*) FROM activity_logs 
                WHERE username = ? AND action = 'upload'
            ''', (username,))
            stats['files_uploaded'] = cursor.fetchone()[0]
            
            # Files downloaded
            cursor.execute('''
                SELECT COUNT(*) FROM activity_logs 
                WHERE username = ? AND action = 'download'
            ''', (username,))
            stats['files_downloaded'] = cursor.fetchone()[0]
            
            # Files deleted
            cursor.execute('''
                SELECT COUNT(*) FROM activity_logs 
                WHERE username = ? AND action = 'delete'
            ''', (username,))
            stats['files_deleted'] = cursor.fetchone()[0]
            
            # Last login
            cursor.execute('''
                SELECT timestamp FROM activity_logs 
                WHERE username = ? AND action = 'login' AND status = 'success'
                ORDER BY timestamp DESC LIMIT 1
            ''', (username,))
            result = cursor.fetchone()
            stats['last_login'] = result[0] if result else None
            
            # Total storage used (sum of uploaded file sizes)
            cursor.execute('''
                SELECT SUM(file_size) FROM activity_logs 
                WHERE username = ? AND action = 'upload'
            ''', (username,))
            result = cursor.fetchone()
            stats['storage_used_bytes'] = result[0] if result[0] else 0
            
            conn.close()
            return stats

    def cleanup_old_logs(self, days=30):
        """Delete logs older than specified days."""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM activity_logs 
                WHERE timestamp < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            return deleted

# Singleton instance
activity_logger = ActivityLogger()
