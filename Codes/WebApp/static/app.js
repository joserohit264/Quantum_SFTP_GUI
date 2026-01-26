// State
const CLIENT_STATE = {
    remote_path: "",
    connected: false,
    speedLimit: 0
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
        }
    } catch (e) {
        console.error("Status check failed:", e);
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

    tableBody.innerHTML = '<tr><td colspan="5" class="loading-cell"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading...</td></tr>';

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
        renderRemoteFiles(data.files, data.current_path);
    } catch (err) {
        console.error(err);
        tableBody.innerHTML = `<tr><td colspan="5" class="loading-cell text-danger">Error: ${err.message}</td></tr>`;
    }
}

function renderRemoteFiles(files, currentPath) {
    const tableBody = document.getElementById('file-table-body');
    const pathDisplay = document.getElementById('current-path-display');
    const tableTitle = document.getElementById('table-title');

    tableBody.innerHTML = '';

    // Update breadcrumb and title
    pathDisplay.innerText = currentPath || "Root";
    tableTitle.innerText = `Contents of: ${currentPath || "/"}`;

    // "Up" Row
    if (currentPath && currentPath !== '/' && currentPath !== '') {
        const upRow = document.createElement('tr');
        upRow.style.cursor = 'pointer';
        upRow.innerHTML = `
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
        emptyRow.innerHTML = '<td colspan="5" class="loading-cell text-muted">Empty directory</td>';
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
        const icon = isDir ? 'fa-folder text-primary' : 'fa-file-lines text-muted';
        const sizeText = isDir ? '-' : formatSize(file.size);

        tr.innerHTML = `
            <td>
                <i class="fa-solid ${icon}" style="margin-right:0.5rem;"></i>
                <span class="${isDir ? 'folder-name' : ''}">${file.name}</span>
            </td>
            <td>${file.type}</td>
            <td>${sizeText}</td>
            <td>${file.modified || '-'}</td>
            <td>
                <div class="action-btn-group">
                    ${!isDir ? `<button class="btn-action-dl" onclick="downloadFile('${file.name}')">Download</button>` : ''}
                    <button class="btn-action-del" onclick="deleteRemoteItem('${file.name}')">Delete</button>
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
    for (let i = 0; i < files.length; i++) {
        await uploadFile(files[i]);
    }
}

let currentUploadXhr = null;

async function uploadFile(file) {
    const progressContainer = document.getElementById('upload-progress-container');
    const filenameSpan = document.getElementById('upload-filename');
    const progressBar = document.getElementById('upload-bar');
    const cancelBtn = document.getElementById('btn-cancel-upload');

    // Show UI
    progressContainer.classList.remove('hidden');
    filenameSpan.innerText = `Uploading ${file.name}...`;
    progressBar.style.width = '0%';

    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        currentUploadXhr = xhr;
        const formData = new FormData();
        formData.append('file', file);

        cancelBtn.onclick = () => {
            xhr.abort();
            progressContainer.classList.add('hidden');
            alert('Upload cancelled');
            reject(new Error('Cancelled'));
        };

        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
                const percent = (e.loaded / e.total) * 100;
                progressBar.style.width = `${percent}%`;
            }
        };

        xhr.onload = () => {
            progressContainer.classList.add('hidden');
            if (xhr.status === 200) {
                try {
                    const data = JSON.parse(xhr.responseText);
                    if (data.success) {
                        showToast(file.name);
                        loadRemoteFiles();
                        resolve();
                    } else {
                        alert(`Error: ${data.error}`);
                        resolve(); // Resolve to wait for next file
                    }
                } catch (e) {
                    alert('Upload failed: Invalid response');
                    resolve();
                }
            } else {
                alert(`Upload failed (${xhr.status})`);
                resolve();
            }
        };

        xhr.onerror = () => {
            progressContainer.classList.add('hidden');
            alert('Network error');
            reject(new Error('Network error'));
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
