import os

class FileValidator:
    ALLOWED_EXTENSIONS = {
        # Documents
        '.txt', '.pdf', '.md', '.rtf', '.csv',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.odt', '.ods', '.odp',
        # Web
        '.html', '.htm', '.css', '.js', '.ts',
        # Data / Config
        '.json', '.xml', '.yaml', '.yml', '.ini', '.cfg', '.toml',
        '.sql', '.log', '.env',
        # Images
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
        '.webp', '.ico', '.tiff', '.tif',
        # Audio
        '.mp3', '.wav', '.flac', '.ogg', '.aac', '.wma', '.m4a',
        # Video
        '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm',
        # Archives
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        # Code
        '.py', '.java', '.c', '.cpp', '.h', '.hpp',
        '.cs', '.go', '.rs', '.rb', '.php', '.swift', '.kt',
        '.sh', '.bat', '.ps1',
        # Misc
        '.ttf', '.otf', '.woff', '.woff2',
    }

    # Common magic numbers (first few bytes of file)
    MAGIC_NUMBERS = {
        '.jpg': b'\xFF\xD8\xFF',
        '.jpeg': b'\xFF\xD8\xFF',
        '.png': b'\x89PNG\r\n\x1a\n',
        '.gif': b'GIF8',
        '.pdf': b'%PDF',
        '.zip': b'PK\x03\x04',
        '.docx': b'PK\x03\x04',    # OOXML (ZIP-based)
        '.xlsx': b'PK\x03\x04',
        '.pptx': b'PK\x03\x04',
        '.odt': b'PK\x03\x04',
        '.ods': b'PK\x03\x04',
        '.odp': b'PK\x03\x04',
        '.mp3': b'\xFF\xFB',       # MP3 frame sync (common)
        '.mp4': b'\x00\x00\x00',   # MP4 box header
        '.avi': b'RIFF',
        '.mkv': b'\x1A\x45\xDF\xA3',
        '.flac': b'fLaC',
        '.ogg': b'OggS',
        '.rar': b'Rar!\x1A\x07',
        '.7z': b'\x37\x7A\xBC\xAF\x27\x1C',
        '.gz': b'\x1F\x8B',
        '.bz2': b'BZ',
        '.bmp': b'BM',
        '.tiff': b'II',            # Little-endian TIFF
        '.tif': b'II',
        '.webp': b'RIFF',
        '.wav': b'RIFF',
        '.mov': b'\x00\x00\x00',
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
            
        # Magic Number Check (only for binary formats with known signatures)
        if ext in FileValidator.MAGIC_NUMBERS:
            magic = FileValidator.MAGIC_NUMBERS[ext]
            if not content.startswith(magic):
                return False, f"File signature mismatch for extension '{ext}'."
        
        return True, None
