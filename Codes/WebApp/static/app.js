// State
const CLIENT_STATE = {
    remote_path: "",
    connected: false,
    speedLimit: 0,
    inSharedFolder: false
};

// Init
document.addEventListener('DOMContentLoaded', () => {
    checkConnectionStatus();
    initTheme();
    initUploadDropZone();
});

async function checkConnectionStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();

        if (data.connected) {
            CLIENT_STATE.connected = true;
            CLIENT_STATE.remote_path = data.remote_path || "";
            loadRemoteFiles();
        } else {
            // Session exists but not connected - auto reconnect
            console.log("Session active but not connected. Auto-reconnecting...");
            await autoConnect();
        }
    } catch (e) {
        console.error("Status check failed:", e);
    }
}

async function autoConnect() {
    try {
        const res = await fetch('/api/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip: '127.0.0.1',
                port: 8888
            })
        });

        const data = await res.json();

        if (data.connected || data.status === "Already connected") {
            CLIENT_STATE.connected = true;
            CLIENT_STATE.remote_path = data.remote_path || "";
            loadRemoteFiles();
        } else {
            // Show error in file table
            const tableBody = document.getElementById('file-table-body');
            if (tableBody) {
                tableBody.innerHTML = `
                    <tr class="empty-state-row">
                        <td colspan="5">
                            Connection failed. Please <a href="/login" style="color: var(--accent)">log in again</a>.
                        </td>
                    </tr>
                `;
            }
        }
    } catch (e) {
        console.error("Auto-connect failed:", e);
        const tableBody = document.getElementById('file-table-body');
        if (tableBody) {
            tableBody.innerHTML = `
                <tr class="empty-state-row">
                    <td colspan="5">
                        Connection error. Please refresh or <a href="/login" style="color: var(--accent)">log in again</a>.
                    </td>
                </tr>
            `;
        }
    }
}

// ===== THEME =====
function initTheme() {
    const saved = localStorage.getItem('theme') || 'dark';
    setTheme(saved);
}

function setTheme(theme) {
    if (theme === 'auto') {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
    } else {
        document.documentElement.setAttribute('data-theme', theme);
    }
    localStorage.setItem('theme', theme);

    // Update pill active state
    document.querySelectorAll('.theme-pill').forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.querySelector(`.theme-pill[onclick="setTheme('${theme}')"]`);
    if (activeBtn) activeBtn.classList.add('active');
}

// ===== REMOTE FILES =====
async function loadRemoteFiles(path = null) {
    const tableBody = document.getElementById('file-table-body');
    if (!tableBody) return;

    tableBody.innerHTML = '<tr><td colspan="6" class="loading-cell"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading...</td></tr>';

    let url = '/api/remote/files';
    if (path !== null) {
        url += `?path=${encodeURIComponent(path)}`;
    } else if (CLIENT_STATE.remote_path) {
        url += `?path=${encodeURIComponent(CLIENT_STATE.remote_path)}`;
    }

    try {
        const res = await fetch(url);
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        CLIENT_STATE.remote_path = data.current_path || "";
        CLIENT_STATE.inSharedFolder = (data.current_path === 'shared' || (data.current_path && data.current_path.startsWith('shared/')));
        renderRemoteFiles(data.files, data.current_path);
    } catch (err) {
        console.error(err);
        tableBody.innerHTML = `<tr><td colspan="6" class="loading-cell text-danger">Error: ${err.message}</td></tr>`;
    }
}

// Selection state
const selectedFiles = new Set();

function updateBulkActions() {
    const bulkActions = document.getElementById('bulk-actions');
    const selectedCount = document.getElementById('selected-count');
    const selectAllCheckbox = document.getElementById('select-all-checkbox');

    if (selectedFiles.size > 0) {
        bulkActions.classList.remove('hidden');
        selectedCount.innerText = `${selectedFiles.size} selected`;
    } else {
        bulkActions.classList.add('hidden');
        selectAllCheckbox.checked = false;
    }
}

function toggleFileSelection(checkbox, filePath, fileName) {
    if (checkbox.checked) {
        selectedFiles.add(JSON.stringify({ path: filePath, name: fileName }));
    } else {
        selectedFiles.delete(JSON.stringify({ path: filePath, name: fileName }));
    }
    updateBulkActions();
}

function toggleSelectAll(checkbox) {
    const fileCheckboxes = document.querySelectorAll('.file-checkbox');
    selectedFiles.clear();

    fileCheckboxes.forEach(cb => {
        cb.checked = checkbox.checked;
        if (checkbox.checked) {
            const filePath = cb.dataset.path;
            const fileName = cb.dataset.name;
            selectedFiles.add(JSON.stringify({ path: filePath, name: fileName }));
        }
    });

    updateBulkActions();
}

function renderRemoteFiles(files, currentPath) {
    const tableBody = document.getElementById('file-table-body');
    const pathDisplay = document.getElementById('current-path-display');
    const tableTitle = document.getElementById('table-title');

    tableBody.innerHTML = '';
    selectedFiles.clear(); // Clear selection when loading new directory
    updateBulkActions();

    // Update breadcrumb and title
    pathDisplay.innerText = currentPath || "Root";
    tableTitle.innerText = `Contents of: ${currentPath || "/"}`;

    // Determine if we're inside the shared folder
    const isInSharedFolder = (currentPath === 'shared' || (currentPath && currentPath.startsWith('shared/')));
    const isGuest = (typeof USER_ROLE !== 'undefined' && USER_ROLE === 'Guest');
    const isReadOnly = isGuest && isInSharedFolder;

    // Hide/show upload and create dir cards based on context
    const actionCards = document.querySelector('.card-grid');
    if (actionCards) {
        if (isGuest) {
            actionCards.style.display = 'none';
        } else {
            actionCards.style.display = '';
        }
    }

    // "Up" Row
    if (currentPath && currentPath !== '/' && currentPath !== '') {
        const upRow = document.createElement('tr');
        upRow.style.cursor = 'pointer';
        upRow.innerHTML = `
            <td></td>
            <td><i class="fa-solid fa-folder-open text-primary" style="margin-right:0.5rem;"></i> .. (Parent Directory)</td>
            <td>dir</td>
            <td>-</td>
            <td>-</td>
            <td></td>
        `;
        upRow.onclick = () => {
            const parts = currentPath.split('/').filter(p => p);
            parts.pop();
            const parent = parts.join('/') || '';
            loadRemoteFiles(parent);
        };
        tableBody.appendChild(upRow);
    }

    if (files.length === 0) {
        const emptyRow = document.createElement('tr');
        emptyRow.innerHTML = '<td colspan="6" class="loading-cell text-muted">Empty directory</td>';
        tableBody.appendChild(emptyRow);
        return;
    }

    // Sort: folders first
    files.sort((a, b) => {
        if (a.type === b.type) return a.name.localeCompare(b.name);
        return a.type === 'dir' ? -1 : 1;
    });

    files.forEach(file => {
        const tr = document.createElement('tr');
        const isDir = file.type === 'dir';
        const isSharedEntry = file.shared === true;
        const icon = isSharedEntry ? 'fa-folder-open text-warning' : (isDir ? 'fa-folder text-primary' : 'fa-file-lines text-muted');
        const displayName = isSharedEntry ? `${file.name} (Shared)` : file.name;
        const sizeText = isDir ? '-' : formatSize(file.size);
        const fullPath = currentPath ? `${currentPath}/${file.name}` : file.name;

        // Determine if actions should be hidden (Guest in shared, or shared root entry)
        const hideDeleteBtn = isReadOnly || isSharedEntry;
        const hideCheckbox = isReadOnly;

        tr.innerHTML = `
            <td>
                ${(!isDir && !hideCheckbox) ? `<input type="checkbox" class="file-checkbox" data-path="${fullPath}" data-name="${file.name}" onchange="toggleFileSelection(this, '${fullPath}', '${file.name}')">` : ''}
            </td>
            <td>
                <i class="fa-solid ${icon}" style="margin-right:0.5rem;"></i>
                <span class="${isDir ? 'folder-name' : ''}">${displayName}</span>
            </td>
            <td>${file.type}</td>
            <td>${sizeText}</td>
            <td>${file.modified || '-'}</td>
            <td>
                <div class="action-btn-group">
                    ${(!isDir && !isSharedEntry) ? `<button class="btn-action-dl" onclick="downloadFile('${file.name}')">Download</button>` : ''}
                    ${(!hideDeleteBtn && !isSharedEntry) ? `<button class="btn-action-del" onclick="deleteRemoteItem('${file.name}')">Delete</button>` : ''}
                </div>
            </td>
        `;

        // Folder navigation
        if (isDir) {
            const folderSpan = tr.querySelector('.folder-name');
            if (folderSpan) {
                folderSpan.onclick = (e) => {
                    e.stopPropagation();
                    let newPath = currentPath ? `${currentPath}/${file.name}` : file.name;
                    if (currentPath === '/') newPath = file.name;
                    loadRemoteFiles(newPath);
                };
            }
        }

        tableBody.appendChild(tr);
    });
}

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    if (!bytes) return '-';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ===== ACTIONS =====
async function createDirectory() {
    const nameInput = document.getElementById('new-dir-name');
    const name = nameInput.value.trim();
    if (!name) { alert("Please enter a directory name"); return; }

    try {
        const res = await fetch('/api/remote/mkdir', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name, parent_path: CLIENT_STATE.remote_path })
        });
        const data = await res.json();
        if (data.error) alert(data.error);
        else {
            nameInput.value = '';
            loadRemoteFiles();
        }
    } catch (e) { console.error(e); alert("Failed to create directory"); }
}

async function deleteRemoteItem(name) {
    if (!confirm(`Are you sure you want to delete "${name}"?`)) return;

    try {
        let fullPath = CLIENT_STATE.remote_path ? `${CLIENT_STATE.remote_path}/${name}` : name;

        const res = await fetch('/api/remote/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: fullPath })
        });
        const d = await res.json();
        if (d.success) loadRemoteFiles();
        else alert(d.error || "Delete failed");
    } catch (e) { alert(e.message); }
}

async function downloadFile(name) {
    try {
        const res = await fetch('/api/download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: name })
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = name;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } else {
            const j = await res.json();
            alert("Download Failed: " + j.error);
        }
    } catch (e) { alert("Download error: " + e.message); }
}

async function disconnectFromServer() {
    try {
        await fetch('/api/logout', { method: 'POST' });
    } catch (e) { }
    window.location.href = "/login";
}

function setSpeedLimit() {
    const select = document.getElementById('speed-limit');
    const value = parseInt(select.value);
    CLIENT_STATE.speedLimit = value;

    const display = document.getElementById('current-speed');
    if (value === 0) {
        display.innerText = "No Limit";
    } else {
        display.innerText = (value / 1024) + " MB/s";
    }
}

// ===== UPLOAD =====
function initUploadDropZone() {
    const dropZone = document.getElementById('upload-drop-zone');
    const fileInput = document.getElementById('file-input');

    if (!dropZone || !fileInput) return;

    // Drag/Drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--accent)';
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.style.borderColor = 'var(--border-color)';
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--border-color)';
        if (e.dataTransfer.files.length > 0) {
            handleFiles(e.dataTransfer.files);
        }
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFiles(e.target.files);
        }
    });
}

async function handleFiles(files) {
    uploadQueue.files = Array.from(files);
    uploadQueue.currentIndex = 0;
    uploadQueue.isPaused = false;
    uploadQueue.totalFiles = files.length;

    await processUploadQueue();
}

// Upload queue state
const uploadQueue = {
    files: [],
    currentIndex: 0,
    totalFiles: 0,
    isPaused: false,
    currentXhr: null,
    pausedFile: null
};

async function processUploadQueue() {
    while (uploadQueue.currentIndex < uploadQueue.files.length) {
        if (uploadQueue.isPaused) {
            // Store the file we paused on
            uploadQueue.pausedFile = uploadQueue.files[uploadQueue.currentIndex];
            console.log("Queue paused at index", uploadQueue.currentIndex);
            return;
        }

        const file = uploadQueue.files[uploadQueue.currentIndex];
        const result = await uploadFile(file, false); // Don't refresh after each upload

        // If paused during upload, don't increment
        if (uploadQueue.isPaused) {
            console.log("Upload paused mid-transfer");
            return;
        }

        // Handle different upload results
        if (result === 'aborted') {
            // Upload was paused then resumed - retry same file
            console.log("Retrying file after pause/resume:", file.name);
            // Don't increment index, loop will retry this file
        } else if (result === true) {
            // Success - move to next file
            uploadQueue.currentIndex++;
        } else {
            // Failed - skip to next file
            console.log(`Upload failed for ${file.name}, skipping to next`);
            uploadQueue.currentIndex++;
        }
    }

    // All uploads complete - hide progress and refresh file list
    console.log("All uploads complete!");
    const progressContainer = document.getElementById('upload-progress-container');
    if (progressContainer) {
        progressContainer.classList.add('hidden');
    }

    if (uploadQueue.currentIndex > 0) {
        loadRemoteFiles();
    }
}

let currentUploadXhr = null;

async function uploadFile(file, shouldRefresh = true) {
    const progressContainer = document.getElementById('upload-progress-container');
    const filenameSpan = document.getElementById('upload-filename');
    const fileCounter = document.getElementById('upload-file-counter');
    const uploadStatus = document.getElementById('upload-status');
    const progressBar = document.getElementById('upload-bar');
    const pauseBtn = document.getElementById('btn-pause-upload');
    const resumeBtn = document.getElementById('btn-resume-upload');
    const cancelBtn = document.getElementById('btn-cancel-upload');

    // Show UI
    progressContainer.classList.remove('hidden');
    filenameSpan.innerText = file.name;
    progressBar.style.width = '0%';
    pauseBtn.classList.remove('hidden');
    resumeBtn.classList.add('hidden');

    // Update file counter if multi-file
    if (uploadQueue.totalFiles > 1) {
        fileCounter.innerText = `(${uploadQueue.currentIndex + 1}/${uploadQueue.totalFiles})`;
        uploadStatus.innerText = 'Computing hash...';
    } else {
        fileCounter.innerText = '';
        uploadStatus.innerText = 'Computing hash...';
    }

    // Compute BLAKE2b hash before upload
    let fileHash = null;
    try {
        const buffer = await file.arrayBuffer();
        const uint8 = new Uint8Array(buffer);
        fileHash = blakejs.blake2bHex(uint8, null, 32);

        console.log(`✓ Computed BLAKE2b hash for ${file.name}: ${fileHash.substring(0, 16)}...`);
        uploadStatus.innerText = uploadQueue.totalFiles > 1 ? 'Uploading...' : 'Uploading with verification...';
    } catch (hashError) {
        console.warn('Failed to compute hash, uploading without verification:', hashError);
        uploadStatus.innerText = 'Uploading...';
    }

    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        currentUploadXhr = xhr;
        uploadQueue.currentXhr = xhr;
        const formData = new FormData();
        formData.append('file', file);

        // Add computed hash to upload (if available)
        if (fileHash) {
            formData.append('file_hash', fileHash);
            console.log(`✓ Adding hash to upload: ${fileHash.substring(0, 32)}...`);
        }

        // Pause button handler
        pauseBtn.onclick = () => {
            console.log("Pause clicked");
            uploadQueue.isPaused = true;
            xhr.abort();
            pauseBtn.classList.add('hidden');
            resumeBtn.classList.remove('hidden');
            uploadStatus.innerText = 'Paused';
            progressBar.style.backgroundColor = '#fbbf24'; // Yellow
            // Don't resolve yet, wait for resume or cancel
        };

        // Resume button handler
        resumeBtn.onclick = () => {
            console.log("Resume clicked - continuing from file", uploadQueue.currentIndex);
            uploadQueue.isPaused = false;
            resumeBtn.classList.add('hidden');
            progressBar.style.backgroundColor = ''; // Reset to default

            // Resolve this promise as "aborted" and let processUploadQueue() continue
            resolve('aborted');
        };

        // Cancel button handler
        cancelBtn.onclick = () => {
            console.log("Cancel clicked - stopping all uploads");
            uploadQueue.isPaused = false;
            uploadQueue.currentIndex = uploadQueue.files.length; // Skip remaining
            xhr.abort();
            progressContainer.classList.add('hidden');
            uploadStatus.innerText = '';
            resolve(false);
        };

        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
                const percent = (e.loaded / e.total) * 100;
                progressBar.style.width = `${percent}%`;
                uploadStatus.innerText = `Uploading... ${Math.round(percent)}%`;
            }
        };

        xhr.onload = () => {
            if (xhr.status === 200) {
                try {
                    const data = JSON.parse(xhr.responseText);
                    if (data.success) {
                        // Show hash verification status
                        if (data.hash_verified) {
                            console.log(`✅ Upload verified! Hash: ${data.hash.substring(0, 16)}...`);
                            uploadStatus.innerText = '✓ Verified';
                        } else {
                            uploadStatus.innerText = 'Complete';
                        }

                        showToast(file.name);

                        // Hide progress if this is the last file or single file upload
                        if (uploadQueue.currentIndex >= uploadQueue.totalFiles - 1 || shouldRefresh) {
                            progressContainer.classList.add('hidden');
                        }

                        // Only refresh if shouldRefresh is true (single file upload)
                        if (shouldRefresh) {
                            loadRemoteFiles();
                        }
                        resolve(true); // Return true for success
                    } else {
                        uploadStatus.innerText = 'Failed!';
                        progressBar.style.backgroundColor = '#ef4444'; // Red
                        setTimeout(() => {
                            if (!uploadQueue.isPaused) {
                                progressContainer.classList.add('hidden');
                            }
                        }, 2000);
                        resolve(false); // Return false for failure
                    }
                } catch (e) {
                    uploadStatus.innerText = 'Error!';
                    setTimeout(() => progressContainer.classList.add('hidden'), 2000);
                    resolve(false);
                }
            } else {
                uploadStatus.innerText = `Failed (${xhr.status})`;
                progressBar.style.backgroundColor = '#ef4444';
                setTimeout(() => {
                    if (!uploadQueue.isPaused) {
                        progressContainer.classList.add('hidden');
                    }
                }, 2000);
                resolve(false);
            }
        };

        xhr.onerror = () => {
            uploadStatus.innerText = 'Network error';
            progressBar.style.backgroundColor = '#ef4444';
            setTimeout(() => {
                if (!uploadQueue.isPaused) {
                    progressContainer.classList.add('hidden');
                }
            }, 2000);
            resolve(false); // Return false on network error
        };

        xhr.open('POST', '/api/upload');
        xhr.send(formData);
    });
}

function showToast(filename) {
    const toast = document.getElementById('upload-complete-toast');
    document.getElementById('toast-filename').innerText = filename;
    toast.classList.remove('hidden');

    // Auto hide after 4s
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 4000);
}

function closeToast() {
    document.getElementById('upload-complete-toast').classList.add('hidden');
}

// ===== BULK ACTIONS =====
async function downloadFile(filename) {
    const fullPath = CLIENT_STATE.remote_path ? `${CLIENT_STATE.remote_path}/${filename}` : filename;

    try {
        const res = await fetch('/api/remote/read', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: fullPath })
        });

        const data = await res.json();

        if (data.success && data.content) {
            // Check hash verification status
            if (data.verification_status) {
                const status = data.verification_status;
                const hash = data.hash ? data.hash.substring(0, 16) : 'N/A';

                console.log(`Download: ${filename}`);
                console.log(`  Hash: ${hash}...`);
                console.log(`  Status: ${status}`);

                if (status === 'VERIFIED') {
                    console.log(`✅ File verified - integrity confirmed`);
                } else if (status === 'TAMPERED') {
                    console.error(`🚨 WARNING: File has been tampered with!`);
                    console.error(`  This file's hash does not match the registry.`);
                    console.error(`  DO NOT trust this file's contents!`);

                    // Show warning to user
                    const proceed = confirm(
                        `⚠️  SECURITY WARNING ⚠️\n\n` +
                        `File: ${filename}\n` +
                        `Status: TAMPERED - Hash mismatch detected!\n\n` +
                        `This file may have been modified or corrupted on the server.\n` +
                        `The file's integrity cannot be verified.\n\n` +
                        `Do you still want to download this file?`
                    );

                    if (!proceed) {
                        console.log('Download cancelled by user');
                        return;
                    }
                } else if (status === 'UNTRACKED') {
                    console.log(`ℹ️  File not in hash registry (uploaded before verification was enabled)`);
                }
            }

            // Decode base64 content
            const binaryString = atob(data.content);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }

            // Create blob and download
            const blob = new Blob([bytes]);
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            // Store hash data and show notification with "View Integrity Check" button
            if (data.verification_status && data.hash) {
                // Store data globally for the button to access
                window.lastDownloadHashData = {
                    filename: filename,
                    fileSize: data.file_size,
                    currentHash: data.hash,
                    storedHash: data.stored_hash || data.hash,
                    verificationStatus: data.verification_status,
                    algorithm: data.hash_algorithm || 'BLAKE2b'
                };

                // Show download notification with integrity check button
                showDownloadNotification(filename, data.verification_status);
            } else {
                // Fallback: just show console message
                console.log(`✓ Download complete: ${filename}`);
            }
        } else {
            console.error(`Failed to download ${filename}:`, data.error);
        }
    } catch (e) {
        console.error(`Error downloading ${filename}:`, e);
    }
}

async function downloadSelected() {
    if (selectedFiles.size === 0) return;

    const files = Array.from(selectedFiles).map(f => JSON.parse(f));
    console.log("Downloading", files.length, "files");

    // Download each file sequentially
    for (const file of files) {
        await downloadFile(file.name);
        // Small delay between downloads
        await new Promise(resolve => setTimeout(resolve, 800));
    }

    // Clear selection after download
    selectedFiles.clear();
    updateBulkActions();

    // Uncheck all checkboxes
    document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = false);
    document.getElementById('select-all-checkbox').checked = false;
}

async function deleteSelected() {
    if (selectedFiles.size === 0) return;

    const files = Array.from(selectedFiles).map(f => JSON.parse(f));
    const count = files.length;

    if (!confirm(`Delete ${count} file${count > 1 ? 's' : ''}?`)) {
        return;
    }

    console.log("Deleting", count, "files");
    let successCount = 0;

    // Delete each file
    for (const file of files) {
        try {
            const res = await fetch('/api/remote/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: file.path })
            });

            const data = await res.json();
            if (data.success) {
                successCount++;
            }
        } catch (e) {
            console.error(`Failed to delete ${file.name}:`, e);
        }
    }

    console.log(`Deleted ${successCount}/${count} files`);

    // Clear selection and refresh
    selectedFiles.clear();
    updateBulkActions();
    loadRemoteFiles();
}

// ===== DOWNLOAD NOTIFICATION WITH INTEGRITY CHECK BUTTON =====
function showDownloadNotification(filename, verificationStatus) {
    // Create backdrop if it doesn't exist and this is the first notification
    if (!document.querySelector('.notifications-backdrop')) {
        const backdrop = document.createElement('div');
        backdrop.className = 'notifications-backdrop';
        backdrop.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(3px);
            z-index: 9998;
            animation: fadeIn 0.3s ease;
        `;
        document.body.appendChild(backdrop);
    }

    // Calculate position based on existing notifications
    const existingNotifications = document.querySelectorAll('.download-notification');
    let bottomPosition = 30; // Start at 30px from bottom

    existingNotifications.forEach(notification => {
        const rect = notification.getBoundingClientRect();
        bottomPosition += rect.height + 15; // Add height + 15px gap
    });

    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'download-notification';
    notification.style.cssText = `
        position: fixed;
        bottom: ${bottomPosition}px;
        right: 30px;
        background: #1f2937;
        border: 1px solid #374151;
        border-left: 4px solid ${verificationStatus === 'VERIFIED' ? '#10b981' : verificationStatus === 'TAMPERED' ? '#ef4444' : '#f59e0b'};
        border-radius: 8px;
        padding: 1.25rem;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8);
        z-index: 9999;
        min-width: 350px;
        animation: slideInRight 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        transition: bottom 0.3s ease;
    `;

    const statusIcon = verificationStatus === 'VERIFIED' ? '✓' : verificationStatus === 'TAMPERED' ? '⚠' : 'ℹ';
    const statusText = verificationStatus === 'VERIFIED' ? 'Verified' : verificationStatus === 'TAMPERED' ? 'Security Warning' : 'Untracked';
    const statusColor = verificationStatus === 'VERIFIED' ? '#10b981' : verificationStatus === 'TAMPERED' ? '#ef4444' : '#f59e0b';

    notification.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
            <div style="flex: 1;">
                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                    <span style="font-size: 1.5rem; color: ${statusColor};">${statusIcon}</span>
                    <h4 style="margin: 0; font-size: 1rem; color: var(--text-primary);">Download Complete</h4>
                </div>
                <p style="margin: 0; font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 0.25rem;">${filename}</p>
                <p style="margin: 0; font-size: 0.75rem; color: ${statusColor}; font-weight: 600;">${statusText}</p>
            </div>
            <button onclick="closeDownloadNotification(this)" style="background: none; border: none; color: var(--text-secondary); cursor: pointer; font-size: 1.5rem; padding: 0; width: 24px; height: 24px;">×</button>
        </div>
        <button onclick="openIntegrityCheck(event)" class="btn-integrity-check" style="
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        ">
            <span>🔍</span>
            View Integrity Check
        </button>
    `;

    // Add hover effect
    const btn = notification.querySelector('.btn-integrity-check');
    btn.onmouseenter = () => {
        btn.style.transform = 'translateY(-2px)';
        btn.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.4)';
    };
    btn.onmouseleave = () => {
        btn.style.transform = 'translateY(0)';
        btn.style.boxShadow = 'none';
    };

    document.body.appendChild(notification);

    // Auto-remove after 30 seconds and reposition remaining notifications
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
            repositionNotifications();
        }
    }, 30000);
}

function closeDownloadNotification(button) {
    const notification = button.closest('.download-notification');
    if (notification) {
        notification.remove();
        repositionNotifications();
    }
}

function repositionNotifications() {
    const notifications = document.querySelectorAll('.download-notification');

    // Remove backdrop if no notifications remain
    if (notifications.length === 0) {
        const backdrop = document.querySelector('.notifications-backdrop');
        if (backdrop) {
            backdrop.remove();
        }
        return;
    }

    let bottomPosition = 30;

    notifications.forEach(notification => {
        notification.style.bottom = bottomPosition + 'px';
        const rect = notification.getBoundingClientRect();
        bottomPosition += rect.height + 15;
    });
}

function openIntegrityCheck(event) {
    // Close the notification that contains this button
    const notification = event.target.closest('.download-notification');
    if (notification) {
        notification.remove();
        repositionNotifications();
    }

    // Show modal with stored data
    if (window.lastDownloadHashData) {
        showHashVerificationModal(window.lastDownloadHashData);
    }
}

// ===== HASH VERIFICATION MODAL =====
function showHashVerificationModal(data) {
    const modal = document.getElementById('hash-verification-modal');
    const statusSection = document.getElementById('hash-status-section');
    const statusIcon = document.getElementById('hash-status-icon');
    const statusTitle = document.getElementById('hash-status-title');
    const statusMessage = document.getElementById('hash-status-message');

    // Set file info
    document.getElementById('hash-filename').textContent = data.filename;
    document.getElementById('hash-filesize').textContent = formatBytes(data.fileSize || 0);

    // Set hashes
    document.getElementById('hash-original').textContent = data.storedHash || 'Not available';
    document.getElementById('hash-current').textContent = data.currentHash;

    // Set status based on verification result
    statusSection.className = 'hash-status'; // Reset classes
    const matchIndicator = document.getElementById('hash-match-indicator');
    const matchIcon = document.getElementById('hash-match-icon');
    const matchText = document.getElementById('hash-match-text');

    if (data.verificationStatus === 'VERIFIED') {
        statusSection.classList.add('verified');
        statusIcon.textContent = '✓';
        statusTitle.textContent = 'Verified';
        statusMessage.textContent = 'File integrity confirmed - this file is authentic';

        matchIndicator.className = 'hash-match match';
        matchIcon.textContent = '✓';
        matchText.textContent = 'Hashes Match - File is Authentic';
    } else if (data.verificationStatus === 'TAMPERED') {
        statusSection.classList.add('tampered');
        statusIcon.textContent = '⚠';
        statusTitle.textContent = 'Security Warning';
        statusMessage.textContent = 'File has been modified - hash mismatch detected!';

        matchIndicator.className = 'hash-match mismatch';
        matchIcon.textContent = '✗';
        matchText.textContent = 'Hash Mismatch - File May Be Corrupted or Tampered';
    } else if (data.verificationStatus === 'UNTRACKED') {
        statusSection.classList.add('untracked');
        statusIcon.textContent = 'ℹ';
        statusTitle.textContent = 'Untracked File';
        statusMessage.textContent = 'This file was uploaded before verification was enabled';

        matchIndicator.className = 'hash-match';
        matchIndicator.style.background = 'rgba(245, 158, 11, 0.1)';
        matchIndicator.style.color = '#f59e0b';
        matchIndicator.style.border = '1px solid rgba(245, 158, 11, 0.3)';
        matchIcon.textContent = 'ℹ';
        matchText.textContent = 'No Stored Hash Available for Comparison';
    }

    // Show modal
    modal.classList.remove('hidden');

    // Log to console for debugging
    console.log(`✓ Downloaded: ${data.filename} [${data.verificationStatus}]`);
    console.log(`  Current Hash: ${data.currentHash.substring(0, 16)}...`);
    if (data.storedHash) {
        console.log(`  Stored Hash:  ${data.storedHash.substring(0, 16)}...`);
    }
}

function closeHashModal() {
    const modal = document.getElementById('hash-verification-modal');
    modal.classList.add('hidden');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Close modal on background click
document.addEventListener('DOMContentLoaded', () => {
    const modal = document.getElementById('hash-verification-modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeHashModal();
            }
        });
    }
});
