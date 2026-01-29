# Phase 4 Periodic Integrity Checks - Testing Guide

## ✅ Features Implemented

### Core System (`integrity_checker.py`)
- ✅ Background scheduler running every 24 hours (configurable)
- ✅ Verifies all files in hash registry
- ✅ Detects three states:
  - **VALID**: File hash matches registry ✓
  - **CORRUPTED**: Hash mismatch detected 🚨
  - **MISSING**: File deleted from server ⚠️
- ✅ Updates verification status in registry
- ✅ Admin alerts (console logs + critical warnings)
- ✅ Detailed results tracking
- ✅ Thread-safe background execution

### Flask Integration (`app.py`)
- ✅ Auto-starts on app launch
- ✅ Runs in daemon thread (doesn't block shutdown)
- ✅ API endpoints:
  - `GET /api/admin/integrity/status` - Get checker status
  - `POST /api/admin/integrity/check` - Trigger manual check
  - `GET /api/admin/integrity/stats` - Get registry statistics

### Configuration (`hash_config.json`)
```json
{
  "integrity_checks": {
    "enabled": true,
    "interval_hours": 24,
    "alert_admin": true,
    "auto_quarantine": false
  }
}
```

## 🧪 How to Test

### Test 1: Automatic Startup
1. **Install schedule library**:
   ```bash
   cd c:\Users\ADMIN\Desktop\Quantum_SFTP\Q_SFTP
   pip install schedule
   ```

2. **Start Q-SFTP**:
   ```bash
   start_q_sftp.bat
   ```

3. **Check Flask startup logs**:
   ```
   Starting integrity checker (interval: 24h)
   ✓ Integrity checker started successfully
   ✓ Integrity monitoring started
   ```

4. **Verify**: No errors during startup

### Test 2: Manual Integrity Check (API)
1. **Login as admin** to web app

2. **Open browser console** (F12)

3. **Trigger manual check**:
   ```javascript
   fetch('/api/admin/integrity/check', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' }
   })
   .then(r => r.json())
   .then(d => console.log(d));
   ```

4. **Expected response**:
   ```json
   {
     "success": true,
     "message": "Integrity check started in background"
   }
   ```

5. **Check server logs** (Flask terminal):
   ```
   ============================================================
   Starting periodic integrity check...
   ============================================================
   Checking 3 files...
   Checking: test.txt
     ✓ Verified: test.txt
   Checking: document.pdf
     ✓ Verified: document.pdf
   Checking: image.png
     ✓ Verified: image.png
   ============================================================
   Integrity check complete!
     Total files: 3
     ✓ Verified: 3
     ✗ Corrupted: 0
     ⚠ Missing: 0
     Errors: 0
     Duration: 0.15s
   ============================================================
   ```

### Test 3: Get Checker Status
```javascript
fetch('/api/admin/integrity/status')
    .then(r => r.json())
    .then(d => console.log(d.status));
```

**Expected output**:
```json
{
  "enabled": true,
  "is_running": false,
  "interval_hours": 24,
  "last_check": "2026-01-29T21:15:30.123456",
  "last_results": {
    "total_files": 3,
    "verified": 3,
    "corrupted": 0,
    "missing": 0,
    "errors": 0
  }
}
```

### Test 4: Get Registry Statistics
```javascript
fetch('/api/admin/integrity/stats')
    .then(r => r.json())
    .then(d => console.log(d.stats));
```

**Expected output**:
```json
{
  "total_files": 3,
  "valid": 3,
  "corrupted": 0,
  "missing": 0,
  "tampered": 0,
  "last_check": "2026-01-29T21:15:30.123456",
  "health_percentage": 100.0
}
```

### Test 5: Detect Corrupted File
1. **Upload a file** via web app

2. **Manually corrupt it** on server:
   ```bash
   cd ServerStorage/<username>/
   echo "CORRUPTED" >> important.txt
   ```

3. **Trigger manual check** (see Test 2)

4. **Check server logs**:
   ```
   Checking: important.txt
     ✗ CORRUPTED: important.txt
       Current:  abc123def456...
       Expected: 789xyz012abc...
   ============================================================
   🚨 FILE CORRUPTION DETECTED 🚨
   File: important.txt
   Path: ServerStorage/username/important.txt
   Current hash:  abc123def456789...
   Expected hash: 789xyz012abc345...
   Action required: Investigate immediately!
   ============================================================
   ```

5. **Check registry**:
   ```bash
   cat Codes/Data/hash_registry.json
   ```
   - File status updated to `"CORRUPTED"`
   - `corrupted_count` incremented

6. **Try to download** the file:
   - Client shows tamper warning (Phase 3)

### Test 6: Detect Missing File
1. **Upload a file** via web app

2. **Manually delete** it from server:
   ```bash
   rm ServerStorage/<username>/deleted_file.txt
   ```

3. **Trigger integrity check**

4. **Check logs**:
   ```
   Checking: deleted_file.txt
     ⚠ File missing: ServerStorage/.../deleted_file.txt
   ```

5. **Check registry**:
   - File status: `"MISSING"`
   - `missing_count` incremented

### Test 7: Scheduled Check (24h Wait)
To test the scheduled check without waiting 24 hours:

1. **Modify `integrity_checker.py` temporarily**:
   ```python
   # Line ~163: Change interval to 1 minute for testing
   schedule.every(1).minutes.do(self.verify_all_files)
   ```

2. **Restart Flask app**

3. **Wait 1 minute**

4. **Check logs** - should see automatic check trigger

5. **Revert change** after testing

## ✅ Success Criteria

- [ ] Integrity checker starts automatically with Flask
- [ ] No startup errors
- [ ] Manual check via API works
- [ ] Status endpoint returns correct data
- [ ] Stats endpoint shows registry info
- [ ] Corrupted files detected
- [ ] Missing files detected
- [ ] Alerts logged to console
- [ ] Registry status updated correctly
- [ ] Background thread doesn't block app

## 📊 Verification Checklist

### Startup
- [ ] Log shows "✓ Integrity monitoring started"
- [ ] Log shows "interval: 24h"
- [ ] No import errors
- [ ] Flask runs normally

### Manual Check
- [ ] API returns success immediately
- [ ] Check runs in background (non-blocking)
- [ ] All files verified
- [ ] Results logged with summary
- [ ] Duration calculated

### Detection
- [ ] Corrupted files flagged
- [ ] Missing files flagged
- [ ] Critical alerts logged
- [ ] Registry updated
- [ ] Metadata counts correct

### APIs
- [ ] All 3 endpoints require admin auth
- [ ] Status shows correct state
- [ ] Stats match registry
- [ ] Errors handled gracefully

## 🔒 Security Benefits

1. **Tamper Detection**: Automatic detection of file modifications
2. **Corruption Alerts**: Early warning of disk/filesystem issues
3. **Deletion Tracking**: Know when files go missing
4. **Audit Trail**: All checks logged with timestamps
5. **Proactive Monitoring**: Issues detected before users download

## 📝 Notes

- **First check**: Won't run until 24 hours after startup (or manual trigger)
- **Background thread**: Daemon thread, won't prevent app shutdown
- **Non-blocking**: Manual checks run in separate thread
- **Admin only**: All endpoints require admin authentication
- **Logging**: Detailed logs in Flask console + activity logs

## 🔧 Configuration

Edit `Codes/WebApp/hash_config.json`:

```json
{
  "integrity_checks": {
    "enabled": true,           // Enable/disable feature
    "interval_hours": 24,      // Check frequency (hours)
    "alert_admin": true,       // Log critical alerts
    "auto_quarantine": false   // Future: auto-move corrupted files
  }
}
```

## 🎯 Next Phase

**Phase 5: Admin Dashboard**
- Integrity monitoring panel
- Real-time status display
- Health percentage meter
- File list with verification badges
- Manual check button
- Alert history

Ready to build the admin dashboard UI?
