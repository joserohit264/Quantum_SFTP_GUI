import os

class FileValidator:
    ALLOWED_EXTENSIONS = {
        '.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.csv', '.json', '.xml', '.md'
    }

    # Common magic numbers (first few bytes of file)
    MAGIC_NUMBERS = {
        '.jpg': b'\xFF\xD8\xFF',
        '.jpeg': b'\xFF\xD8\xFF',
        '.png': b'\x89PNG\r\n\x1a\n',
        '.gif': b'GIF8',
        '.pdf': b'%PDF',
        '.zip': b'PK\x03\x04',
    }

    @staticmethod
    def validate(filename, content):
        """
        Validates the file based on extension and magic numbers.
        Returns (True, None) if valid, or (False, reason) if invalid.
        """
        _, ext = os.path.splitext(filename.lower())
        
        if ext not in FileValidator.ALLOWED_EXTENSIONS:
            return False, f"File extension '{ext}' is not allowed."
            
        # Magic Number Check
        if ext in FileValidator.MAGIC_NUMBERS:
            magic = FileValidator.MAGIC_NUMBERS[ext]
            if not content.startswith(magic):
                return False, f"File signature mismatch for extension '{ext}'."
        
        # Additional checks can go here (e.g. max size, though that's usually done before buffering)
        
        return True, None
