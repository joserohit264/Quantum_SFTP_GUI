import sys
import os
import unittest
import json
import base64
import time

# Add Handshake dir to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'Codes', 'Handshake')))

# We need to mock the socket connection to test the server logic without full network stack if possible, 
# OR we can write a client that connects. Writing a client is better for integration testing.
# However, we need to bypass the interactive parts.

# Let's try to unit test the components first, then integration.

from auth_manager import auth_db
from file_validator import FileValidator

class TestSecurityComponents(unittest.TestCase):
    
    def test_validator(self):
        """Verifies that FileValidator correctly accepts safe files and rejects malicious ones."""
        # Allow txt
        valid, _ = FileValidator.validate("test.txt", b"Hello World")
        self.assertTrue(valid)
        
        # Block malicious extension
        valid, reason = FileValidator.validate("malware.exe", b"MZ...")
        self.assertFalse(valid)
        self.assertIn("extension", reason)
        
        # Block magic mismatch
        valid, reason = FileValidator.validate("fake.jpg", b"Not A JPG Header")
        self.assertFalse(valid)
        self.assertIn("signature mismatch", reason)
        
        # Allow legit JPG
        valid, _ = FileValidator.validate("test.jpg", b"\xFF\xD8\xFFImage")
        self.assertTrue(valid)

    def test_rbac(self):
        """Verifies that AuthManager correctly enforces role-based permissions (READ/WRITE/DELETE)."""
        # Create test users
        if not auth_db.get_user_by_username("test_admin"):
            auth_db.add_user("test_admin", "Administrator", "CN=TestAdmin")
        if not auth_db.get_user_by_username("test_user"):
            auth_db.add_user("test_user", "Standard", "CN=TestUser")
            
        # Check Admin Permissions
        self.assertTrue(auth_db.check_permission("test_admin", "READ"))
        self.assertTrue(auth_db.check_permission("test_admin", "DELETE"))
        
        # Check Standard Permissions (assuming Standard has READ, WRITE, DELETE from default init)
        # Wait, default "Standard" in auth_manager.py is 'READ,WRITE,DELETE'
        self.assertTrue(auth_db.check_permission("test_user", "WRITE"))
        
        # Test Guest (READ only)
        if not auth_db.get_user_by_username("test_guest"):
            auth_db.add_user("test_guest", "Guest", "CN=TestGuest")
            
        self.assertTrue(auth_db.check_permission("test_guest", "READ"))
        self.assertFalse(auth_db.check_permission("test_guest", "WRITE"))
        self.assertFalse(auth_db.check_permission("test_guest", "DELETE"))

if __name__ == '__main__':
    print("\nRunning Security Component Tests...")
    print("===================================")
    unittest.main(verbosity=2)
