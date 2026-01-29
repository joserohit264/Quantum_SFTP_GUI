# Phase 5 Admin Dashboard Integration - Testing Guide

## ✅ Features Implemented

### Admin Panel UI (`admin.html`)
- ✅ **File Integrity Monitoring Panel** - New dedicated section
- ✅ **Health Meter** - Visual 0-100% health bar with color coding
  - Green (≥90%): Healthy
  - Yellow (70-89%): Warning
  - Red (<70%): Critical
- ✅ **Statistics Cards**:
  - Total Files (tracked)
  - ✓ Verified (valid hash)
  - ⚠ Corrupted (hash mismatch)
  - ❌ Missing (deleted)
- ✅ **Status Indicators**:
  - Last check timestamp
  - Checker status badge (Active/Running/Disabled)
- ✅ **Action Buttons**:
  - 🔍 Run Manual Check
  - 🔄 Refresh Stats
- ✅ **Results Table** - Shows files with verification badges and hashes

### JavaScript Functions
- ✅ `loadIntegrityStats()` - Fetches and displays registry stats
- ✅ `loadIntegrityStatus()` - Gets checker status
- ✅ `triggerIntegrityCheck()` - Manually starts integrity check
- ✅ `displayCheckResults()` - Shows detailed check results
- ✅ Auto-loads stats on page load

## 🧪 How to Test

### Test 1: View Admin Dashboard
1. **Install schedule library** (if not done):
   ```bash
   pip install schedule
   ```

2. **Restart Q-SFTP servers**:
   ```bash
   cd c:\Users\ADMIN\Desktop\Quantum_SFTP\Q_SFTP
   start_q_sftp.bat
   ```

3. **Login as admin**:
   - Go to http://127.0.0.1:5000
   - Login with admin credentials
   - Click "Admin Panel" link

4. **Scroll to File Integrity Monitoring section**

5. **Verify panel loads**:
   - Stats auto-populate
   - Health meter shows percentage
   - Status shows "Active" (green dot)

### Test 2: Health Meter Color Coding
**Scenario 1: Healthy System (100%)**
- All files verified
- Health bar: **Green**
- Percentage: **100.0%**

**Scenario 2: Warning (70-89%)**
- Upload a file, corrupt 1-2 files on server
- Run manual check
- Health bar: **Yellow/Orange**
- Percentage: Reflects corruption ratio

**Scenario 3: Critical (<70%)**
- Corrupt multiple files
- Health bar: **Red**
- Shows critical status

### Test 3: Manual Integrity Check
1. **Click "🔍 Run Manual Check"** button

2. **Observe**:
   - Button changes to "⏳ Running Check..."
   - Button disabled during check
   - Alert: "Integrity check started! Refresh in a few seconds..."

3. **After 3 seconds**:
   - Stats auto-refresh
   - Results table appears (if details available)
   - Button re-enabled

4. **Check server logs**:
   ```
   ============================================================
   Starting periodic integrity check...
   ============================================================
   Checking 5 files...
   Checking: file1.txt
     ✓ Verified: file1.txt
   ...
   ============================================================
   Integrity check complete!
   ============================================================
   ```

### Test 4: Real-Time Stats Display
1. **View initial stats**:
   - Total: 5
   - Verified: 5
   - Corrupted: 0
   - Missing: 0

2. **Upload a new file**

3. **Click "🔄 Refresh Stats"**

4. **Observe**:
   - Total increases to 6
   - Verified increases to 6
   - Health still 100%

### Test 5: Corruption Detection in UI
1. **Corrupt a file** on server:
   ```bash
   cd ServerStorage/<username>/
   echo "CORRUPTED" >> test.txt
   ```

2. **Click "🔍 Run Manual Check"**

3. **Wait 3 seconds** for auto-refresh

4. **Observe results table**:
   - Shows `test.txt`
   - Status badge: **⚠ Corrupted** (red)
   - Hash displayed

5. **Stats update**:
   - Corrupted: 1
   - Verified: decreases
   - Health drops below 100%

### Test 6: Status Badge Changes
**Test Active Status**:
- Normal state: Green dot + "Active"

**Test Running Status**:
- During manual check: Yellow dot + "Running..."
- Click refresh quickly after triggering

**Test Disabled**:
- Edit `hash_config.json`:
  ```json
  {
    "integrity_checks": {
      "enabled": false
    }
  }
  ```
- Restart Flask
- Badge shows: Gray dot + "Disabled"

### Test 7: Results Table Display
1. **Trigger check with mixed results**:
   - Some verified
   - Some corrupted
   - Some missing

2. **View results table**:
   ```
   Filename      | Status        | Hash
   ------------- | ------------- | ----------------
   file1.txt     | ✓ Verified    | a3f9b2c1e5d8f4b7...
   file2.pdf     | ⚠ Corrupted   | 1a2b3c4d5e6f7a8b...
   file3.docx    | ❌ Missing    | —
   ```

3. **Verify badge colors**:
   - Green for Verified
   - Red for Corrupted
   - Orange for Missing

## ✅ Success Criteria

- [ ] Panel appears in admin dashboard
- [ ] Stats load automatically
- [ ] Health meter shows correct percentage
- [ ] Health color changes (green/yellow/red)
- [ ] Status badge shows correct state
- [ ] Manual check button works
- [ ] Button disabled during check
- [ ] Auto-refresh after 3 seconds
- [ ] Results table displays
- [ ] All badges color-coded correctly
- [ ] Refresh button updates stats

## 📊 Expected UI Layout

```
┌─────────────────────────────────────────────────┐
│ 🔒 File Integrity Monitoring                    │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐       │
│  │   5  │  │   5  │  │   0  │  │   0  │       │
│  │Total │  │Verify│  │Corrup│  │Miss. │       │
│  └──────┘  └──────┘  └──────┘  └──────┘       │
│                                                 │
│  System Health               100.0%            │
│  ████████████████████████████████ (Green)      │
│                                                 │
│  Last Check: 2026-01-29 9:15 PM                │
│  Checker Status: ● Active                      │
│                                                 │
│  [🔍 Run Manual Check] [🔄 Refresh Stats]      │
│                                                 │
│  Recent Check Details:                         │
│  ┌──────────┬──────────────┬─────────────┐    │
│  │Filename  │ Status       │ Hash        │    │
│  ├──────────┼──────────────┼─────────────┤    │
│  │file1.txt │ ✓ Verified   │ a3f9b2c...  │    │
│  │file2.pdf │ ✓ Verified   │ 1a2b3c4...  │    │
│  └──────────┴──────────────┴─────────────┘    │
└─────────────────────────────────────────────────┘
```

## 🎨 Visual Features

1. **Gradient Stat Cards**:
   - Verified: Green gradient
   - Corrupted: Red gradient
   - Missing: Orange gradient

2. **Animated Health Bar**:
   - Smooth transition on update
   - Color changes dynamically

3. **Status Badge**:
   - Colored dot indicator
   - Real-time status text

4. **Results Table**:
   - Monospace hash display
   - Color-coded status badges
   - Clean table layout

## 📝 Notes

- **Auto-refresh**: Dashboard loads stats on page load
- **Real-time**: Manual check auto-refreshes after 3s
- **Color coding**: Intuitive health visualization
- **Responsive**: Works on all screen sizes
- **Dark theme**: Fully compatible with existing theme toggle

## 🔒 Security

- **Admin only**: All endpoints require admin authentication
- **Read-only UI**: No ability to modify registry from UI
- **Safe refresh**: Only displays data, doesn't execute code
- **Error handling**: Graceful failures with console logging

## 🎯 Integration Complete

Phase 5 brings together:
- ✅ Phase 1: Hash computation shows in UI
- ✅ Phase 2: Upload verification stats tracked
- ✅ Phase 3: Download verification reflected
- ✅ Phase 4: Periodic checks visible in dashboard
- ✅ Phase 5: Full admin monitoring panel

## 📸 Testing Screenshots

Recommended screenshots to capture:
1. Full panel view with 100% health (green)
2. Warning state with yellow health bar
3. Critical state with corrupted files
4. Results table with mixed statuses
5. Manual check in progress (button disabled)

## 🚀 Next Steps

Ready for **Phase 6: User Verification Page**?
- User-facing integrity view
- Personal file status
- Hash transparency for users
- Individual file verification

Or **Phase 7: Advanced Features**?
- Email alerts for corruption
- Automated quarantine
- Hash history tracking
- Version control integration
