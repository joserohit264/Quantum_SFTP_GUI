import os

class FileValidator:
    # Block only dangerous executable/system file types
    BLOCKED_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.com', '.msi', '.cmd',
        '.vbs', '.vbe', '.wsf', '.wsh', '.pif', '.cpl',
        '.inf', '.reg', '.sys', '.drv', '.ocx',
    }

    # Known magic numbers for binary validation
    MAGIC_NUMBERS = {
        '.jpg': b'\xFF\xD8\xFF',
        '.jpeg': b'\xFF\xD8\xFF',
        '.png': b'\x89PNG\r\n\x1a\n',
        '.gif': b'GIF8',
        '.pdf': b'%PDF',
        '.zip': b'PK\x03\x04',
        '.docx': b'PK\x03\x04',
        '.xlsx': b'PK\x03\x04',
        '.pptx': b'PK\x03\x04',
        '.mp3': b'\xFF\xFB',
        '.mp4': b'\x00\x00\x00',
        '.avi': b'RIFF',
        '.mkv': b'\x1A\x45\xDF\xA3',
        '.flac': b'fLaC',
        '.ogg': b'OggS',
        '.rar': b'Rar!\x1A\x07',
        '.7z': b'\x37\x7A\xBC\xAF\x27\x1C',
        '.gz': b'\x1F\x8B',
        '.bmp': b'BM',
        '.wav': b'RIFF',
    }

    @staticmethod
    def validate(filename, content):
        """
        Validates the file based on extension (blacklist) and magic numbers.
        All file types are allowed EXCEPT dangerous executables.
        Returns (True, None) if valid, or (False, reason) if invalid.
        """
        _, ext = os.path.splitext(filename.lower())

        if ext in FileValidator.BLOCKED_EXTENSIONS:
            return False, f"File type '{ext}' is blocked for security reasons."

        # Magic Number Check for known binary formats
        if ext in FileValidator.MAGIC_NUMBERS:
            magic = FileValidator.MAGIC_NUMBERS[ext]
            if not content.startswith(magic):
                return False, f"File signature mismatch for extension '{ext}'."

        return True, None
