import io
import json
import hashlib
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Privacy configuration
CONFIG_FILE = Path(__file__).parent / 'privacy_config.json'

class PrivacyManager:
    def __init__(self):
        self.config = self._load_config()
        self.metadata_log = []
    
    def _load_config(self):
        """Load privacy configuration from JSON file."""
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load privacy config: {e}")
        
        # Default configuration
        return {
            "metadata_scrubbing": {
                "enabled": True,
                "file_types": ["jpg", "jpeg", "png", "gif", "pdf", "docx"],
                "log_scrubbing": True,
                "fail_on_error": False
            },
            "ip_anonymization": {
                "enabled": True,
                "salt_rotation": "daily",
                "hash_length": 16
            }
        }
    
    def scrub_image_metadata(self, file_bytes, filename):
        """Remove EXIF data from images (JPG, PNG, GIF)."""
        try:
            from PIL import Image
            
            # Open image from bytes
            img = Image.open(io.BytesIO(file_bytes))
            
            # Get EXIF data before removal (for logging)
            exif_data = {}
            if hasattr(img, '_getexif') and img._getexif():
                from PIL.ExifTags import TAGS
                exif = img._getexif()
                exif_data = {TAGS.get(k, k): v for k, v in exif.items() if k in TAGS}
            
            # Remove EXIF by creating new image without metadata
            cleaned_img = Image.new(img.mode, img.size)
            cleaned_img.putdata(list(img.getdata()))
            
            # Save to bytes without metadata
            output = io.BytesIO()
            cleaned_img.save(output, format=img.format if img.format else 'PNG')
            cleaned_bytes = output.getvalue()
            
            metadata_removed = {
                "exif_tags": list(exif_data.keys()) if exif_data else [],
                "fields_count": len(exif_data)
            }
            
            logger.info(f"Scrubbed EXIF from {filename}: {len(exif_data)} fields removed")
            return cleaned_bytes, metadata_removed
            
        except ImportError:
            logger.warning("Pillow not installed. Skipping image metadata scrubbing.")
            return file_bytes, {"error": "Pillow not installed"}
        except Exception as e:
            logger.error(f"Failed to scrub image metadata: {e}")
            if self.config['metadata_scrubbing']['fail_on_error']:
                raise
            return file_bytes, {"error": str(e)}
    
    def scrub_pdf_metadata(self, file_bytes):
        """Remove metadata from PDFs (author, creator, producer, dates)."""
        try:
            from PyPDF2 import PdfReader, PdfWriter
            
            # Read PDF
            reader = PdfReader(io.BytesIO(file_bytes))
            writer = PdfWriter()
            
            # Get metadata before removal
            original_metadata = reader.metadata if reader.metadata else {}
            metadata_removed = {
                "author": original_metadata.get('/Author', ''),
                "creator": original_metadata.get('/Creator', ''),
                "producer": original_metadata.get('/Producer', ''),
                "creation_date": original_metadata.get('/CreationDate', ''),
                "mod_date": original_metadata.get('/ModDate', ''),
                "fields_count": len(original_metadata)
            }
            
            # Copy pages without metadata
            for page in reader.pages:
                writer.add_page(page)
            
            # Set minimal metadata (Q-SFTP processing marker)
            writer.add_metadata({
                '/Producer': 'Q-SFTP Privacy System',
                '/CreationDate': ''
            })
            
            # Write to bytes
            output = io.BytesIO()
            writer.write(output)
            cleaned_bytes = output.getvalue()
            
            logger.info(f"Scrubbed PDF metadata: {len(original_metadata)} fields removed")
            return cleaned_bytes, metadata_removed
            
        except ImportError:
            logger.warning("PyPDF2 not installed. Skipping PDF metadata scrubbing.")
            return file_bytes, {"error": "PyPDF2 not installed"}
        except Exception as e:
            logger.error(f"Failed to scrub PDF metadata: {e}")
            if self.config['metadata_scrubbing']['fail_on_error']:
                raise
            return file_bytes, {"error": str(e)}
    
    def scrub_docx_metadata(self, file_bytes):
        """Remove metadata from Word documents (author, company, last modified by)."""
        try:
            from docx import Document
            
            # Load document
            doc = Document(io.BytesIO(file_bytes))
            
            # Get core properties (metadata) before removal
            core_props = doc.core_properties
            metadata_removed = {
                "author": core_props.author or '',
                "last_modified_by": core_props.last_modified_by or '',
                "created": str(core_props.created) if core_props.created else '',
                "modified": str(core_props.modified) if core_props.modified else '',
                "title": core_props.title or '',
                "subject": core_props.subject or '',
                "company": core_props.category or ''
            }
            
            # Clear metadata
            core_props.author = ''
            core_props.last_modified_by = ''
            core_props.title = ''
            core_props.subject = ''
            core_props.category = ''
            core_props.comments = ''
            
            # Save cleaned document
            output = io.BytesIO()
            doc.save(output)
            cleaned_bytes = output.getvalue()
            
            logger.info(f"Scrubbed Word doc metadata: {sum(1 for v in metadata_removed.values() if v)} fields removed")
            return cleaned_bytes, metadata_removed
            
        except ImportError:
            logger.warning("python-docx not installed. Skipping DOCX metadata scrubbing.")
            return file_bytes, {"error": "python-docx not installed"}
        except Exception as e:
            logger.error(f"Failed to scrub DOCX metadata: {e}")
            if self.config['metadata_scrubbing']['fail_on_error']:
                raise
            return file_bytes, {"error": str(e)}
    
    def get_file_category(self, filename):
        """Categorize file for anonymized logging."""
        ext = Path(filename).suffix.lower().lstrip('.')
        
        categories = {
            'document': ['pdf', 'doc', 'docx', 'txt', 'odt', 'rtf'],
            'image': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'],
            'archive': ['zip', 'rar', '7z', 'tar', 'gz'],
            'video': ['mp4', 'avi', 'mkv', 'mov', 'wmv'],
            'audio': ['mp3', 'wav', 'flac', 'aac', 'ogg'],
            'code': ['py', 'js', 'html', 'css', 'java', 'cpp', 'c']
        }
        
        for category, extensions in categories.items():
            if ext in extensions:
                return category
        
        return 'other'
    
    def scrub_file_metadata(self, file_bytes, filename):
        """Auto-detect file type and scrub metadata accordingly."""
        if not self.config['metadata_scrubbing']['enabled']:
            return file_bytes, None
        
        ext = Path(filename).suffix.lower().lstrip('.')
        
        # Check if file type is configured for scrubbing
        if ext not in self.config['metadata_scrubbing']['file_types']:
            logger.info(f"Skipping {filename}: {ext} not in configured file types")
            return file_bytes, None
        
        metadata_removed = None
        cleaned_bytes = file_bytes
        
        try:
            # Route to appropriate scrubbing function
            if ext in ['jpg', 'jpeg', 'png', 'gif']:
                cleaned_bytes, metadata_removed = self.scrub_image_metadata(file_bytes, filename)
            
            elif ext == 'pdf':
                cleaned_bytes, metadata_removed = self.scrub_pdf_metadata(file_bytes)
            
            elif ext in ['docx']:
                cleaned_bytes, metadata_removed = self.scrub_docx_metadata(file_bytes)
            
            # Log scrubbing action
            if metadata_removed and self.config['metadata_scrubbing']['log_scrubbing']:
                self.metadata_log.append({
                    'filename': filename,
                    'timestamp': datetime.now().isoformat(),
                    'metadata_removed': metadata_removed
                })
            
            return cleaned_bytes, metadata_removed
            
        except Exception as e:
            logger.error(f"Metadata scrubbing failed for {filename}: {e}")
            if self.config['metadata_scrubbing']['fail_on_error']:
                raise
            return file_bytes, {"error": str(e)}
    
    def get_daily_salt(self):
        """Generate salt based on current date (rotates at midnight UTC)."""
        date_str = datetime.utcnow().strftime('%Y-%m-%d')
        return hashlib.sha256(f"Q-SFTP-SALT-{date_str}".encode()).hexdigest()
    
    def anonymize_ip(self, ip_address):
        """Hash IP address with daily rotating salt."""
        if not self.config['ip_anonymization']['enabled']:
            return ip_address
        
        salt = self.get_daily_salt()
        hash_full = hashlib.sha256(f"{ip_address}{salt}".encode()).hexdigest()
        hash_length = self.config['ip_anonymization']['hash_length']
        
        return hash_full[:hash_length]
    
    def get_metadata_log(self, username=None):
        """Retrieve metadata scrubbing log (optionally filtered by user)."""
        # This returns the in-memory log
        # In production, this should be persisted to a database
        return self.metadata_log

# Singleton instance
privacy_manager = PrivacyManager()
