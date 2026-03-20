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
    return downloadFileChunked(name);
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
    const fileBuffer = await file.arrayBuffer();
    try {
        const uint8 = new Uint8Array(fileBuffer);
        fileHash = blakejs.blake2bHex(uint8, null, 32);
        console.log(`✓ Computed BLAKE2b hash for ${file.name}: ${fileHash.substring(0, 16)}...`);
    } catch (hashError) {
        console.warn('Failed to compute hash:', hashError);
    }

    uploadStatus.innerText = 'Initializing transfer...';

    // ── Chunked Resumable Upload ──────────────────────────────────
    try {
        // Step 1: Init transfer (server checks for existing session to resume)
        const initRes = await fetch('/api/upload/init', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename: file.name,
                total_size: file.size,
                file_hash: fileHash || ''
            })
        });
        const initData = await initRes.json();

        if (!initRes.ok) {
            uploadStatus.innerText = `Error: ${initData.error}`;
            progressBar.style.backgroundColor = '#ef4444';
            setTimeout(() => progressContainer.classList.add('hidden'), 2000);
            return false;
        }

        const transferId = initData.transfer_id;
        const chunkSize = initData.chunk_size || 262144; // 256KB
        let offset = initData.resume_offset || 0;
        const totalSize = file.size;

        if (initData.resumed && offset > 0) {
            console.log(`↻ Resuming upload from offset ${offset}/${totalSize}`);
            uploadStatus.innerText = `Resuming from ${Math.round(offset / 1024)}KB...`;
            progressBar.style.width = `${(offset / totalSize) * 100}%`;
        }

        // Save transfer state to localStorage for cross-session resume
        localStorage.setItem(`transfer_${file.name}`, JSON.stringify({
            transfer_id: transferId,
            offset: offset,
            total_size: totalSize,
            file_hash: fileHash
        }));

        // Pause/Resume/Cancel state
        let isPaused = false;
        let isCancelled = false;

        pauseBtn.onclick = () => {
            isPaused = true;
            pauseBtn.classList.add('hidden');
            resumeBtn.classList.remove('hidden');
            uploadStatus.innerText = `Paused at ${Math.round(offset / 1024)}KB`;
            progressBar.style.backgroundColor = '#fbbf24';
            // Save pause state
            localStorage.setItem(`transfer_${file.name}`, JSON.stringify({
                transfer_id: transferId,
                offset: offset,
                total_size: totalSize,
                file_hash: fileHash,
                paused: true
            }));
        };

        resumeBtn.onclick = () => {
            isPaused = false;
            resumeBtn.classList.add('hidden');
            pauseBtn.classList.remove('hidden');
            progressBar.style.backgroundColor = '';
            uploadStatus.innerText = 'Resuming...';
        };

        cancelBtn.onclick = () => {
            isCancelled = true;
            isPaused = false;
            uploadQueue.isPaused = false;
            uploadQueue.currentIndex = uploadQueue.files.length;
            progressContainer.classList.add('hidden');
            localStorage.removeItem(`transfer_${file.name}`);
        };

        // Step 2: Send chunks sequentially
        while (offset < totalSize) {
            // Wait if paused
            while (isPaused && !isCancelled) {
                await new Promise(r => setTimeout(r, 200));
            }
            if (isCancelled) return false;

            const end = Math.min(offset + chunkSize, totalSize);
            const chunkBlob = file.slice(offset, end);
            const isFinal = (end >= totalSize);

            const formData = new FormData();
            formData.append('transfer_id', transferId);
            formData.append('offset', offset.toString());
            formData.append('is_final', isFinal.toString());
            formData.append('chunk', chunkBlob);

            const chunkRes = await fetch('/api/upload/chunk', {
                method: 'POST',
                body: formData
            });
            const chunkData = await chunkRes.json();

            if (!chunkRes.ok || !chunkData.success) {
                uploadStatus.innerText = `Error: ${chunkData.error || 'Chunk failed'}`;
                progressBar.style.backgroundColor = '#ef4444';
                setTimeout(() => {
                    if (!uploadQueue.isPaused) progressContainer.classList.add('hidden');
                }, 2000);
                return false;
            }

            offset = chunkData.bytes_transferred;

            // Update progress
            const percent = (offset / totalSize) * 100;
            progressBar.style.width = `${percent}%`;
            uploadStatus.innerText = `Uploading... ${Math.round(percent)}%`;

            // Save progress
            localStorage.setItem(`transfer_${file.name}`, JSON.stringify({
                transfer_id: transferId,
                offset: offset,
                total_size: totalSize,
                file_hash: fileHash
            }));
        }

        // Step 3: Finalize
        uploadStatus.innerText = 'Finalizing...';
        const completeRes = await fetch('/api/upload/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ transfer_id: transferId })
        });
        const completeData = await completeRes.json();

        if (completeData.success) {
            uploadStatus.innerText = '✓ Complete';
            showToast(file.name, 'upload', {
                hash: completeData.file_hash || fileHash,
                algorithm: completeData.hash_algorithm || 'BLAKE2b',
                verified: completeData.hash_verified || false,
                fileSize: file.size
            });
            localStorage.removeItem(`transfer_${file.name}`);

            if (uploadQueue.currentIndex >= uploadQueue.totalFiles - 1 || shouldRefresh) {
                progressContainer.classList.add('hidden');
            }
            if (shouldRefresh) loadRemoteFiles();
            return true;
        } else {
            uploadStatus.innerText = 'Finalize failed';
            return false;
        }

    } catch (err) {
        console.error('Chunked upload error:', err);
        uploadStatus.innerText = 'Network error';
        progressBar.style.backgroundColor = '#ef4444';
        setTimeout(() => {
            if (!uploadQueue.isPaused) progressContainer.classList.add('hidden');
        }, 2000);
        return false;
    }
}

// ===== TOAST NOTIFICATION SYSTEM =====
function getToastContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position:fixed;bottom:20px;left:20px;z-index:9999;display:flex;flex-direction:column-reverse;gap:12px;max-width:420px;';
        document.body.appendChild(container);
    }
    return container;
}

function showToast(filename, action = 'upload', hashData = {}) {
    const container = getToastContainer();
    const toast = document.createElement('div');
    toast.className = 'toast-notification';

    const isUpload = action === 'upload';
    const isDelete = action === 'delete';
    const icon = isDelete ? 'fa-trash-can' : (isUpload ? 'fa-cloud-arrow-up' : 'fa-cloud-arrow-down');
    const actionLabel = isDelete ? 'Delete Complete' : (isUpload ? 'Upload Complete' : 'Download Complete');
    const isVerified = (hashData.verified || hashData.status === 'VERIFIED');
    const iconColor = isDelete ? 'var(--danger)' : 'var(--success)';
    toast.style.borderLeftColor = isDelete ? 'var(--danger)' : (isVerified ? 'var(--success)' : '#fbbf24');

    // Build file size line
    let sizeLine = '';
    if (hashData.fileSize) {
        sizeLine = `<span style="color:var(--text-muted);font-size:0.78rem;"> · ${formatBytes(hashData.fileSize)}</span>`;
    }

    // Hash Show More Button
    let showMoreBtn = '';
    if (hashData.hash) {
        // Prepare data for the modal
        const modalData = {
            filename: filename,
            fileSize: hashData.fileSize,
            currentHash: hashData.hash,
            storedHash: hashData.hash,
            verificationStatus: (hashData.verified || hashData.status === 'VERIFIED') ? 'VERIFIED' : 'UNTRACKED',
            algorithm: hashData.algorithm || 'BLAKE2b'
        };
        // We attach the data as a JSON string to the button so it can be parsed when clicked
        const dataStr = encodeURIComponent(JSON.stringify(modalData));
        showMoreBtn = `
            <div style="margin-top: 8px;">
                <button onclick="openToastHashModal('${dataStr}', this)" style="
                    background: transparent;
                    border: 1px solid var(--border-color);
                    color: var(--accent);
                    padding: 0.3rem 0.6rem;
                    border-radius: 4px;
                    font-size: 0.75rem;
                    cursor: pointer;
                    transition: all 0.2s;
                " onmouseover="this.style.background='rgba(59, 130, 246, 0.1)'" onmouseout="this.style.background='transparent'">
                    Show More 🔍
                </button>
            </div>
        `;
    }

    toast.innerHTML = `
        <div style="color:${iconColor};font-size:1.2rem;margin-top:2px;"><i class="fa-solid ${icon}"></i></div>
        <div class="toast-content" style="flex:1;">
            <h4>${actionLabel}</h4>
            <p style="font-size:0.85rem;color:var(--text-secondary);">${filename}${sizeLine}</p>
            ${showMoreBtn}
        </div>
        <button class="toast-close" onclick="this.closest('.toast-notification').remove()">✕</button>
    `;

    container.appendChild(toast);

    // Auto-dismiss after 6 seconds
    setTimeout(() => {
        toast.style.transition = 'opacity 0.4s, transform 0.4s';
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(-100%)';
        setTimeout(() => toast.remove(), 400);
    }, 6000);
}

function closeToast() {
    // Legacy compat — no-op
}

// ===== BULK ACTIONS =====
async function downloadFileChunked(filename) {
    try {
        // Step 1: Init chunked download
        const initRes = await fetch('/api/download/init', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: filename })
        });
        const initData = await initRes.json();

        if (!initRes.ok) {
            console.error(`Download init failed: ${initData.error}`);
            return;
        }

        const transferId = initData.transfer_id;
        const chunkSize = initData.chunk_size || 262144;
        let offset = initData.resume_offset || 0;
        const totalSize = initData.total_size;
        const originalHash = initData.original_hash || null;

        if (initData.resumed && offset > 0) {
            console.log(`↻ Resuming download from offset ${offset}/${totalSize}`);
        }

        // Save download state for cross-session resume
        localStorage.setItem(`dl_${filename}`, JSON.stringify({
            transfer_id: transferId,
            offset: offset,
            total_size: totalSize
        }));

        // Step 2: Fetch chunks and assemble
        const chunks = [];
        let fileHash = null;
        let fileSize = 0;

        while (offset < totalSize) {
            const chunkRes = await fetch('/api/download/chunk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    transfer_id: transferId,
                    offset: offset
                })
            });
            const chunkData = await chunkRes.json();

            if (!chunkRes.ok || !chunkData.success) {
                console.error(`Chunk download failed: ${chunkData.error}`);
                return;
            }

            // Decode chunk
            const binaryString = atob(chunkData.content);
            const chunkBytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                chunkBytes[i] = binaryString.charCodeAt(i);
            }
            chunks.push(chunkBytes);

            offset = chunkData.bytes_transferred;
            fileSize = chunkData.total_size;

            // Update progress in localStorage
            localStorage.setItem(`dl_${filename}`, JSON.stringify({
                transfer_id: transferId,
                offset: offset,
                total_size: totalSize
            }));

            const percent = Math.round((offset / totalSize) * 100);
            console.log(`Downloading ${filename}: ${percent}%`);

            if (chunkData.is_final) break;
        }

        // Step 3: Assemble final file
        const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
        const assembled = new Uint8Array(totalLength);
        let pos = 0;
        for (const chunk of chunks) {
            assembled.set(chunk, pos);
            pos += chunk.length;
        }

        // Compute BLAKE2b hash for verification
        try {
            fileHash = blakejs.blake2bHex(assembled, null, 32);
            console.log(`✓ Download hash: ${fileHash.substring(0, 16)}...`);
        } catch (e) {
            console.warn('Hash computation failed:', e);
        }

        // Create blob and trigger download
        const blob = new Blob([assembled]);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        // Clean up localStorage
        localStorage.removeItem(`dl_${filename}`);

        let finalStatus = 'UNTRACKED';
        if (fileHash && originalHash) {
            // Constant-time comparison or simple equality
            finalStatus = (fileHash.toLowerCase() === originalHash.toLowerCase()) ? 'VERIFIED' : 'TAMPERED';
        } else if (fileHash) {
            finalStatus = 'UNTRACKED';
        }

        // Store hash data for integrity check modal
        window.lastDownloadHashData = {
            filename: filename,
            fileSize: totalLength,
            currentHash: fileHash || 'Not Computed',
            storedHash: originalHash || 'Not available',
            verificationStatus: finalStatus,
            algorithm: 'BLAKE2b'
        };

        // Always show the notification toast when download completes
        showDownloadNotification(filename, finalStatus);

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

    // Show toast for delete
    if (successCount > 0) {
        showToast(`${successCount} file${successCount > 1 ? 's' : ''} deleted`, 'delete', {});
    }

    // Clear selection and refresh
    selectedFiles.clear();
    updateBulkActions();
    loadRemoteFiles();
}

// ===== DOWNLOAD NOTIFICATION =====
function showDownloadNotification(filename, verificationStatus) {
    const hashData = window.lastDownloadHashData || {};
    showToast(filename, 'download', {
        hash: hashData.currentHash || null,
        algorithm: hashData.algorithm || 'BLAKE2b',
        verified: verificationStatus === 'VERIFIED',
        status: verificationStatus,
        fileSize: hashData.fileSize || null
    });
}

function openToastHashModal(dataStr, btn) {
    // Hide the toast when opening modal
    const toast = btn.closest('.toast-notification');
    if (toast) {
        toast.remove();
    }

    // Parse data and show modal
    try {
        const data = JSON.parse(decodeURIComponent(dataStr));
        showHashVerificationModal(data);
    } catch (e) {
        console.error('Failed to parse hash data for modal', e);
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

// (Toast system defined above in lines 658+)

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
