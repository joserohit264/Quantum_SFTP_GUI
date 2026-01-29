# Phase 2 Upload Verification - Testing Guide

## ✅ Features Implemented

### Server-Side (`app.py`)
- ✅ Accepts `file_hash` parameter from client
- ✅ Computes SHA-256 of uploaded file
- ✅ Compares client hash with server hash (constant-time)
- ✅ Rejects upload if hashes don't match (400 error)
- ✅ Logs security event on hash mismatch
- ✅ Registers verified files in hash registry
- ✅ Returns hash and verification status to client

### Client-Side (`app.js`)
- ✅ Computes SHA-256 before upload (Web Crypto API)
- ✅ Shows "Computing hash..." status
- ✅ Sends hash with upload via FormData
- ✅ Displays "✓ Verified" on success
- ✅ Logs hash to console for debugging

## 🧪 How to Test

### Test 1: Normal Upload (Hash Verification Success)
1. **Start Q-SFTP**:
   ```bash
   cd c:\Users\ADMIN\Desktop\Quantum_SFTP\Q_SFTP
   start_q_sftp.bat
   ```

2. **Open browser** to http://127.0.0.1:5000

3. **Upload a file**:
   - Click "Choose File" or drag & drop
   - Watch upload status: "Computing hash..." → "Uploading..."→ "✓ Verified"

4. **Check console (F12)**:
   ```
   ✓ Computed hash for test.txt: a3f9b2c1e5d8f4b7...
   ✓ Adding hash to upload: a3f9b2c1e5d8f4b7c2a1d9e8...
   ✅ Upload verified! Hash: a3f9b2c1e5d8f4b7...
   ```

5. **Check server logs**:
   ```
   INFO - ✓ Upload hash verified for test.txt: a3f9b2c1...
   INFO - ✓ Registered file hash: <uuid>
   ```

6. **Verify hash registry**:
   - Check `Codes/Data/hash_registry.json`
   - File should be listed with SHA-256 hash

### Test 2: Corrupted Upload (Hash Mismatch - Simulated)
This requires modifying the JavaScript temporarily:

1. **Edit `app.js` line ~502** to corrupt hash:
   ```javascript
   if (fileHash) {
       // Corrupt hash for testing
       const corruptedHash = 'ffffffffffffffff' + fileHash.substring(16);
       formData.append('file_hash', corruptedHash);
   }
   ```

2. **Upload a file**

3. **Expected result**:
   - Upload rejected with error
   - Status: "Failed (400)"
   - Server logs show hash mismatch:
     ```
     ERROR - Upload hash mismatch for test.txt
     ERROR -   Client hash: ffffffffffffffff...
     ERROR -   Server hash: a3f9b2c1e5d8f4b7...
     ```

4. **Verify security log**:
   - Check `Codes/Logs/` for security event
   - Event type: `upload_hash_mismatch`

5. **Revert the change** after testing

### Test 3: Multiple File Upload with Verification
1. **Select 3-5 files**
2. **Upload all**
3. **Observe**:
   - Each file shows "Computing hash..."
   - All uploads show "✓ Verified"
   - Hash registry updated for all files

### Test 4: Hash Registry Inspection
1. **View registry**:
   ```bash
   cat Codes/Data/hash_registry.json
   ```

2. **Verify structure**:
   ```json
   {
     "files": {
       "uuid-123": {
         "filename": "test.txt",
         "filepath": "ServerStorage/username/test.txt",
         "hash_sha256": "a3f9b2c1...",
         "hash_algorithm": "SHA-256",
         "file_size": 1024,
         "uploaded_by": "username",
         "upload_timestamp": "2026-01-29T...",
         "last_verified": "2026-01-29T...",
         "verification_status": "VALID",
         "version": 1
       }
     },
     "metadata": {
       "total_files": 1,
       "last_check": null,
       "corrupted_count": 0,
       "missing_count": 0
     }
   }
   ```

## ✅ Success Criteria

- [ ] Upload shows "Computing hash..." before transfer
- [ ] Hash computed correctly (matches online SHA-256 calculator)
- [ ] Upload completes with "✓ Verified" status
- [ ] Server logs show hash verification
- [ ] File registered in `hash_registry.json`
- [ ] Corrupted hash is rejected (Test 2)
- [ ] Security event logged on mismatch
- [ ] Multi-file uploads all verified

## 📊 Verification Checklist

### UI Verification
- [ ] Status shows "Computing hash..."
- [ ] Status changes to "Uploading..." during transfer
- [ ] Status shows "✓ Verified" on success
- [ ] Console logs hash (F12 → Console)

### Server Verification
- [ ] Server logs hash verification
- [ ] Hash registry file created (`Codes/Data/hash_registry.json`)
- [ ] Files have valid SHA-256 hashes (64 hex characters)
- [ ] Uploaded timestamp recorded
- [ ] File size matches

### Security Verification
- [ ] Corrupted hash rejected
- [ ] Security event logged
- [ ] Upload fails gracefully (no crash)
- [ ] Error message shown to user

## 🐛 Known Issues / Edge Cases

1. **Large Files**: Hash computation may take time (normal)
2. **Old Browsers**: Web Crypto API requires HTTPS (use localhost exception)
3. **Hash Mismatch**: Very rare unless network corruption
4. **Registry Path**: Windows path normalization may vary

## 🎯 Next Phase

Once Phase 2 is verified:
- **Phase 3**: Download Verification (add hash headers to downloads)
- **Phase 4**: Periodic Integrity Checks (background task)
- **Phase 5**: Admin Dashboard (integrity monitoring UI)

## 📝 Notes

- Hash is computed on **original** uploaded data (before metadata scrubbing)
- Hash stored in registry is **post-scrubbing** (actual stored file)
- This is intentional to verify transfer integrity + store final file hash
- Future: May add both hashes (original + scrubbed) for audit trail
