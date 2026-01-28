import json
import os
import bcrypt
from datetime import datetime

USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.json')

class UserManager:
    def __init__(self, users_file=USERS_FILE):
        self.users_file = users_file
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump({}, f)

    def _load_users(self):
        with open(self.users_file, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}

    def _save_users(self, users):
        with open(self.users_file, 'w') as f:
            json.dump(users, f, indent=4)

    def add_user(self, username, password, certificate_subject, role="Standard"):
        users = self._load_users()
        
        if username in users:
            return False, "User already exists"

        # Hash password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        users[username] = {
            "password_hash": hashed,
            "certificate": certificate_subject,
            "role": role,
            "created_at": datetime.now().isoformat()
        }
        
        self._save_users(users)
        return True, "User created successfully"

    def validate_user(self, username, password):
        users = self._load_users()
        user = users.get(username)
        
        if not user:
            return False, "User not found"
            
        stored_hash = user.get("password_hash")
        if not stored_hash:
            return False, "Invalid account state"

        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            return True, user
        else:
            return False, "Invalid password"

    def get_user(self, username):
        users = self._load_users()
        return users.get(username)

    def list_all_users(self):
        """Returns list of all users with their details (excludes password hash)."""
        users = self._load_users()
        user_list = []
        for username, data in users.items():
            user_list.append({
                'username': username,
                'role': data.get('role', 'Guest'),
                'certificate': data.get('certificate', ''),
                'created_at': data.get('created_at', '')
            })
        return user_list

    def delete_user(self, username):
        """Deletes a user from the database."""
        users = self._load_users()
        if username not in users:
            return False, "User not found"
        
        del users[username]
        self._save_users(users)
        return True, "User deleted successfully"

    def update_user_role(self, username, new_role):
        """Updates a user's role."""
        users = self._load_users()
        if username not in users:
            return False, "User not found"
        
        users[username]['role'] = new_role
        self._save_users(users)
        return True, f"Role updated to {new_role}"

    def user_exists(self, username):
        """Checks if a user exists."""
        users = self._load_users()
        return username in users
    
    def reset_password(self, username, new_password):
        """Reset a user's password."""
        users = self._load_users()
        
        if username not in users:
            return False, "User not found"
        
        # Hash new password
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        users[username]['password_hash'] = hashed_pw.decode('utf-8')
        
        self._save_users(users)
        return True, "Password reset successfully"

# Singleton
user_manager = UserManager()
