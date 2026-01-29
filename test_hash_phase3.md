# Phase 3 Download Verification - Testing Guide

## ✅ Features Implemented

### Server-Side (`app.py` - `/api/remote/read`)
- ✅ Computes SHA-256 hash of downloaded file content
- ✅ Looks up stored hash from registry
- ✅ Compares current vs stored hash (constant-time)
- ✅ Returns verification status:
  - **VERIFIED**: Hash matches registry
  - **TAMPERED**: Hash mismatch - file modified!
  - **UNTRACKED**: File not in registry (uploaded pre-Phase 2)
- ✅ Logs security events for tampering detection
- ✅ Returns hash + status in JSON response

### Client-Side (`app.js` - `downloadFile()`)
- ✅ Displays hash and verification status in console
- ✅ Shows ✅ checkmark for verified files
- ✅ Shows �🚨 WARNING for tampered files
- ✅ Displays security warning dialog for tampered files
- ✅ Allows user to cancel download if suspicious
- ✅ Logs detailed verification info

## 🧪 How to Test

### Test 1: Download Verified File
1. **Prerequisites**: Upload a file with Phase 2 active (hash verification enabled)

2. **Download the file**:
   - Click "Download" button on the file
   
3. **Check browser console (F12)**:
   ```
   Download: test.txt
     Hash: a3f9b2c1e5d8f4b7...
     Status: VERIFIED
   ✅ File verified - integrity confirmed
   ✓ Download complete and verified: test.txt
   ```

4. **Check server logs**:
   ```
   INFO - Download hash for test.txt: a3f9b2c1e5d8f4b7...
   INFO - ✓ Download verified: hash matches registry
   ```

5. **Verify**: File downloads normally with no warnings

### Test 2: Download Untracked File (Old File)
1. **Use a file** uploaded before Phase 2 was implemented

2. **Download it**

3. **Expected console output**:
   ```
   Download: old_file.txt
     Hash: 1a2b3c4d5e6f7a8b...
     Status: UNTRACKED
   ℹ️  File not in hash registry (uploaded before verification was enabled)
   ✓ Download complete: old_file.txt
   ```

4. **Verify**: File downloads with info message, no warnings

### Test 3: Tampered File Detection (Simulation Required)
This test requires manually corrupting a file on the server:

**Setup**:
1. Upload a file through the web app (e.g., `important.txt`)
2. Note the hash in `Codes/Data/hash_registry.json`
3. Manually edit the file on server:
   ```bash
   # Navigate to ServerStorage
   cd ServerStorage/<username>/
   
   # Edit the file (add/remove content)
   echo "TAMPERED CONTENT" >> important.txt
   ```

**Test**:
1. Try to download `important.txt`

2. **Expected behavior**:
   - Console shows:
     ```
     Download: important.txt
       Hash: <new_hash>...
       Status: TAMPERED
     🚨 WARNING: File has been tampered with!
       This file's hash does not match the registry.
       DO NOT trust this file's contents!
     ```
   
   - Security warning dialog appears:
     ```
     ⚠️  SECURITY WARNING ⚠️
     
     File: important.txt
     Status: TAMPERED - Hash mismatch detected!
     
     This file may have been modified or corrupted on the server.
     The file's integrity cannot be verified.
     
     Do you still want to download this file?
     [Cancel] [OK]
     ```

3. **Click "Cancel"**:
   - Download cancelled
   - Console: `Download cancelled by user`

4. **Click "OK"**:
   - File downloads despite warning
   - Console: `✓ Download complete: important txt` (no verification checkmark)

5. **Check server logs**:
   ```
   WARNING - ⚠ File tampering detected!
   WARNING -   Current hash:  <actual_hash>
   WARNING -   Stored hash:   <registry_hash>
   ```

6. **Check security log**:
   - Event type: `download_hash_mismatch`
   - Details include both hashes

**Cleanup**: Delete the tampered file and re-upload a clean version

### Test 4: Bulk Download with Verification
1. **Select multiple files** (mix of verified and untracked)

2. **Click "Download" button** in bulk actions

3. **Observe console**:
   - Each file shows verification status
   - Verified files show ✅
   - Untracked files show ℹ️
   - All download sequentially

4. **No warnings** if all files are clean

## ✅ Success Criteria

- [ ] Verified files show "VERIFIED" status in console
- [ ] Verified files show ✅ checkmark
- [ ] Untracked files show "UNTRACKED" with ℹ️
- [ ] Tampered files trigger security warning dialog
- [ ] User can cancel download of tampered files
- [ ] Server logs tampering detection
- [ ] Security event logged for mismatches
- [ ] Bulk download works for all file types

## 📊 Verification Checklist

### Console Output
- [ ] Hash displayed (first 16 chars)
- [ ] Verification status shown
- [ ] ✅ for verified files
- [ ] 🚨 for tampered files
- [ ] ℹ️ for untracked files

### Security Warning Dialog
- [ ] Appears for TAMPERED files only
- [ ] Shows filename
- [ ] Explains hash mismatch
- [ ] Offers Cancel option
- [ ] Allows proceed if user chooses

### Server Logging
- [ ] Hash logged for every download
- [ ] Verification result logged
- [ ] Tampering warnings logged
- [ ] Security events created

### Hash Registry
- [ ] Files added during Phase 2 have hashes
- [ ] Old files marked as untracked
- [ ] Hashes are valid SHA-256 (64 hex chars)

## 🔒 Security Benefits

1. **Tamper  Detection**: Immediately detects if files were modified on server
2. **User Warning**: Prevents users from trusting corrupted/malicious files
3. **Audit Trail**: All downloads logged with verification status
4. **Transparency**: Users see hash and can independently verify
5. **Insider Threat**: Even admins can't modify files undetected

## 📝 Notes

- **Old files**: Files uploaded before Phase 2 will show as "UNTRACKED"
- **Re-upload**: Re-uploading updates the hash in registry
- **Metadata scrubbing**: Hash in registry is post-scrubbing (actual stored file)
- **Client verification**: Currently server-side only; Phase 4+ may add client recomputation

## 🎯 Next Phase

**Phase 4: Periodic Integrity Checks**
- Background task to verify all files every 24 hours
- Detect corruption/tampering automatically
- Email alerts on detection
- Admin dashboard showing integrity status

Ready to implement Phase 4?
