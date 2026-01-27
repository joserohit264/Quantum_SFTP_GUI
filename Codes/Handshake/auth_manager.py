import sqlite3
import os
import hashlib
import binascii
from datetime import datetime
import threading

# Configuration
DB_FILE = 'users.db'

class User:
    def __init__(self, id, username, role, cert_subject=None, created_at=None):
        self.id = id
        self.username = username
        self.role = role
        self.cert_subject = cert_subject
        self.created_at = created_at

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

class AuthManager:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            # Roles Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    permissions TEXT
                )
            ''')
            
            # Users Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    role_id INTEGER NOT NULL,
                    cert_subject TEXT UNIQUE,
                    password_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (role_id) REFERENCES roles (id)
                )
            ''')
            
            # Insert Default Roles if not exist
            cursor.execute("INSERT OR IGNORE INTO roles (name, permissions) VALUES ('Administrator', 'ALL')")
            cursor.execute("INSERT OR IGNORE INTO roles (name, permissions) VALUES ('Standard', 'READ,WRITE,DELETE')")
            cursor.execute("INSERT OR IGNORE INTO roles (name, permissions) VALUES ('Guest', 'READ')")
            
            # Seed default 'Client' user for the demo
            # We assume the default client cert subject is 'Client'
            cursor.execute("SELECT id FROM roles WHERE name = 'Standard'")
            std_role_id = cursor.fetchone()[0]
            cursor.execute("INSERT OR IGNORE INTO users (username, role_id, cert_subject) VALUES (?, ?, ?)", 
                           ('demo_user', std_role_id, 'Client'))

            conn.commit()
            conn.close()

    def add_user(self, username, role_name="Standard", cert_subject=None, password=None):
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            try:
                # Get Role ID
                cursor.execute("SELECT id FROM roles WHERE name = ?", (role_name,))
                role_row = cursor.fetchone()
                if not role_row:
                    return False, f"Role '{role_name}' does not exist."
                role_id = role_row[0]
                
                # Check if user exists
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    return False, "Username already exists."
                
                # Check if cert subject is already bound
                if cert_subject:
                    cursor.execute("SELECT id FROM users WHERE cert_subject = ?", (cert_subject,))
                    if cursor.fetchone():
                        return False, "Certificate Subject is already bound to a user."

                pwd_hash = None
                if password:
                    # Basic salt+hash for future web admin use
                    salt = os.urandom(32)
                    pwd_hash = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)).decode()
                    # Store as salt$hash
                    pwd_hash = f"{binascii.hexlify(salt).decode()}${pwd_hash}"

                cursor.execute('''
                    INSERT INTO users (username, role_id, cert_subject, password_hash)
                    VALUES (?, ?, ?, ?)
                ''', (username, role_id, cert_subject, pwd_hash))
                
                conn.commit()
                return True, "User created successfully."
            except Exception as e:
                return False, str(e)
            finally:
                conn.close()

    def get_user_by_subject(self, cert_subject):
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT u.id, u.username, r.name, u.cert_subject, u.created_at
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.cert_subject = ?
            ''', (cert_subject,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return User(id=row[0], username=row[1], role=row[2], cert_subject=row[3], created_at=row[4])
            return None

    def get_user_by_username(self, username):
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT u.id, u.username, r.name, u.cert_subject, u.created_at
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.username = ?
            ''', (username,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return User(id=row[0], username=row[1], role=row[2], cert_subject=row[3], created_at=row[4])
            return None

    def list_users(self):
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT u.username, r.name, u.cert_subject 
                FROM users u 
                JOIN roles r ON u.role_id = r.id
            ''')
            rows = cursor.fetchall()
            conn.close()
            return rows

    def check_permission(self, username, required_perm):
        """
        Checks if the user has the required permission.
        Permissions in DB are comma-separated strings (e.g., 'READ,WRITE,DELETE') or 'ALL'.
        """
        user = self.get_user_by_username(username)
        if not user:
            return False
            
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('SELECT permissions FROM roles WHERE name = ?', (user.role,))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return False
                
            perms_str = row[0]
            if perms_str == 'ALL':
                return True
                
            perms = [p.strip() for p in perms_str.split(',')]
            return required_perm in perms

# Singleton instance for easy import
auth_db = AuthManager(os.path.join(os.path.dirname(__file__), DB_FILE))

if __name__ == "__main__":
    # Test script
    print("Initializing DB...")
    print(auth_db.add_user("admin", "Administrator", cert_subject="CN=Admin,O=QuantumSFTP", password="admin"))
    print(auth_db.add_user("alice", "Standard", cert_subject="CN=Alice,O=QuantumSFTP"))
    
    u = auth_db.get_user_by_subject("CN=Alice,O=QuantumSFTP")
    print(f"Found User: {u}")
