// State
let localFiles = [];
let localPath = "";
let selectedLocalFile = null;
let isConnected = false;

// DOM Elements
const localFileList = document.getElementById('local-file-list');
const localPathInput = document.getElementById('local-path-input');
const btnUpload = document.getElementById('btn-upload');
const btnConnect = document.getElementById('btn-connect');
const statusConn = document.getElementById('status-conn');

// Init
document.addEventListener('DOMContentLoaded', () => {
    // Check Status immediately on load
    checkConnectionStatus();
    loadLocalFiles();

    // Auto-load theme from storage
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
        const icon = document.querySelector('#btn-theme-toggle i');
        if (icon) icon.className = savedTheme === 'light' ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
    }
});

async function checkConnectionStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        if (data.connected) {
            isConnected = true;
            // Update UI without full 'connectToServer' logic which inputs rely on
            const statusDiv = document.getElementById('status-conn');
            if (statusDiv) statusDiv.innerHTML = '<i class="fa-solid fa-link text-success"></i> Secure Connection Established';

            // Show PQC Badges
            document.getElementById('pqc-kyber').classList.remove('hidden');
            document.getElementById('pqc-dilithium').classList.remove('hidden');
            document.getElementById('pqc-aes').classList.remove('hidden');

            loadRemoteFiles();
            updateActionButtons();
        }
    } catch (e) {
        console.log("Check status failed", e);
    }
}

async function disconnectFromServer() {
    try {
        await fetch('/api/logout', { method: 'POST' });
    } catch (e) {
        console.error(e);
    }
    window.location.href = "/login";
}

// --- Local File Management ---

async function loadLocalFiles(path = null) {
    localFileList.innerHTML = '<div class="loading-spinner"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading...</div>';

    let url = '/api/local/files';
    if (path) {
        url += `?path=${encodeURIComponent(path)}`;
    }

    try {
        const res = await fetch(url);
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        localFiles = data.files;
        localPath = data.current_path;
        localPathInput.value = localPath;
        renderLocalFiles();
    } catch (err) {
        localFileList.innerHTML = `<div class="empty-state"><p class="text-danger">Error: ${err.message}</p></div>`;
    }
}

function renderLocalFiles() {
    localFileList.innerHTML = '';
    selectedLocalFile = null;
    updateActionButtons();

    if (localFiles.length === 0) {
        localFileList.innerHTML = '<div class="empty-state"><p>Folder is empty</p></div>';
        return;
    }

    localFiles.forEach(file => {
        const el = document.createElement('div');
        el.className = 'file-item';
        el.innerHTML = `
            <div class="file-icon"><i class="${getFileIcon(file.type, file.name)}"></i></div>
            <div class="file-name">${file.name}</div>
            <div class="file-size">${formatSize(file.size)}</div>
            <div class="file-date">${file.modified}</div>
        `;

        el.onclick = () => {
            if (file.type === 'dir') {
                loadLocalFiles(file.path);
            } else {
                selectFile(el, file);
            }
        };

        localFileList.appendChild(el);
    });
}

function selectFile(el, file) {
    // Clear prev selection
    const prev = document.querySelector('.file-item.selected');
    if (prev) prev.classList.remove('selected');

    // Select new
    el.classList.add('selected');
    selectedLocalFile = file;
    updateActionButtons();
}

function navigateUp(pane) {
    if (pane === 'local') {
        const parent = localPath.substring(0, localPath.lastIndexOf(localPath.includes('/') ? '/' : '\\'));
        // If we are at root, might be empty or C:/
        if (localPath.length > 3)
            loadLocalFiles(parent || 'C:/');
    } else if (pane === 'remote') {
        if (!remotePath) return;
        const parts = remotePath.split(/[/\\]/);
        parts.pop();
        loadRemoteFiles(parts.join('/'));
    }
}

function updateActionButtons() {
    btnUpload.disabled = !(isConnected && selectedLocalFile);

    const btnDownloadRemote = document.getElementById('btn-download-remote');
    if (btnDownloadRemote) btnDownloadRemote.disabled = !(isConnected && selectedRemoteFile);

    const btnNewFolder = document.getElementById('btn-new-folder');
    if (btnNewFolder) btnNewFolder.disabled = !isConnected;

    const btnDelete = document.getElementById('btn-delete');
    if (btnDelete) btnDelete.disabled = !(isConnected && selectedRemoteFile);

    const btnRemoteUp = document.getElementById('btn-remote-up');
    if (btnRemoteUp) btnRemoteUp.disabled = !isConnected || !remotePath;
}

// --- Connection ---

async function connectToServer() {
    const ip = document.getElementById('host-ip').value;
    const port = document.getElementById('host-port').value;

    btnConnect.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Connecting...';
    btnConnect.disabled = true;

    try {
        const res = await fetch('/api/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, port })
        });
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        isConnected = true;
        updateUIConnected();

        // Show PQC Badges
        if (data.security) {
            document.getElementById('pqc-kyber').classList.remove('hidden');
            document.getElementById('pqc-dilithium').classList.remove('hidden');
            document.getElementById('pqc-aes').classList.remove('hidden');
        }

    } catch (err) {
        alert(`Connection Failed: ${err.message}`);
        btnConnect.innerHTML = '<i class="fa-solid fa-plug"></i> Connect';
        btnConnect.disabled = false;
    }
}

// --- Remote File Management ---

// --- Remote File Management ---
let remotePath = "";
let selectedRemoteFile = null;

async function loadRemoteFiles(path = null) {
    const remoteList = document.getElementById('remote-file-list');
    remoteList.innerHTML = '<div class="loading-spinner"><i class="fa-solid fa-circle-notch fa-spin"></i> Fetching Remote...</div>';

    let url = '/api/remote/files';
    if (path !== null) {
        url += `?path=${encodeURIComponent(path)}`;
    }

    try {
        const res = await fetch(url);
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        remotePath = data.current_path;
        document.getElementById('remote-path-input').value = `/${remotePath}`;

        renderRemoteFiles(data.files);
    } catch (err) {
        remoteList.innerHTML = `<div class="empty-state"><p class="text-danger">Error: ${err.message}</p></div>`;
    }
}

function renderRemoteFiles(files) {
    const remoteList = document.getElementById('remote-file-list');
    remoteList.innerHTML = '';
    selectedRemoteFile = null;
    updateActionButtons();

    if (files.length === 0 && !remotePath) {
        remoteList.innerHTML = '<div class="empty-state"><p>Remote Folder is empty</p></div>';
        return;
    }

    files.forEach(file => {
        const el = document.createElement('div');
        el.className = 'file-item';
        el.innerHTML = `
            <div class="file-icon"><i class="${getFileIcon(file.type, file.name)}"></i></div>
            <div class="file-name">${file.name}</div>
            <div class="file-size">${formatSize(file.size)}</div>
            <div class="file-date">${file.modified}</div>
        `;

        el.onclick = () => {
            if (file.type === 'dir') {
                loadRemoteFiles(remotePath ? `${remotePath}/${file.name}` : file.name);
            } else {
                selectRemoteFile(el, file);
            }
        };

        remoteList.appendChild(el);
    });
}

function selectRemoteFile(el, file) {
    const prev = document.querySelector('#remote-file-list .file-item.selected');
    if (prev) prev.classList.remove('selected');
    el.classList.add('selected');
    selectedRemoteFile = file;
    updateActionButtons();
}

async function createRemoteFolder() {
    if (!isConnected) return;

    const name = prompt("Enter new folder name:");
    if (!name) return;

    try {
        const res = await fetch('/api/remote/mkdir', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
        });
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        alert("Folder created!");
        loadRemoteFiles(remotePath);

    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function downloadSelected() {
    if (!selectedRemoteFile) return;

    addToQueue(selectedRemoteFile.name, 'Downloading');

    try {
        const res = await fetch('/api/download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: selectedRemoteFile.name })
        });
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        updateQueue(selectedRemoteFile.name, 'Complete');
        // Refresh Local Files
        loadLocalFiles(localPath);
        alert(`File Downloaded to: ${data.path}`);

    } catch (e) {
        updateQueue(selectedRemoteFile.name, 'Failed');
        alert(`Download Error: ${e.message}`);
    }
}

async function deleteRemoteSelection() {
    if (!selectedRemoteFile || !isConnected) return;

    if (!confirm(`Are you sure you want to delete "${selectedRemoteFile.name}"?`)) return;

    try {
        const res = await fetch('/api/remote/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: selectedRemoteFile.name })
        });
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        alert("Item Deleted");
        loadRemoteFiles(remotePath);

    } catch (e) {
        alert(`Delete Error: ${e.message}`);
    }
}

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', newTheme);

    const btn = document.getElementById('btn-theme-toggle');
    if (newTheme === 'light') {
        btn.innerHTML = '<i class="fa-solid fa-sun"></i>';
    } else {
        btn.innerHTML = '<i class="fa-solid fa-moon"></i>';
    }
}

function updateUIConnected() {
    btnConnect.innerHTML = '<i class="fa-solid fa-check"></i> Connected';
    btnConnect.classList.remove('btn-primary');
    btnConnect.style.backgroundColor = 'var(--success)';

    statusConn.innerHTML = '<i class="fa-solid fa-link text-success"></i> Secure Connection Established';

    // Initial Load
    loadRemoteFiles();

    updateActionButtons();
}

// --- Upload ---

async function uploadSelected() {
    if (!selectedLocalFile) return;

    addToQueue(selectedLocalFile.name, 'Sending');
    const queueId = Date.now();

    try {
        const res = await fetch('/api/upload', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: selectedLocalFile.path })
        });
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        updateQueue(selectedLocalFile.name, 'Complete');
        // Refresh Remote List
        loadRemoteFiles(remotePath);

    } catch (err) {
        updateQueue(selectedLocalFile.name, 'Failed');
        alert(`Upload Error: ${err.message}`);
    }
}

// --- Queue / Helpers ---

function addToQueue(filename, status) {
    const list = document.getElementById('queue-list');
    const el = document.createElement('div');
    el.className = 'queue-item';
    el.dataset.file = filename;
    el.innerHTML = `
        <div class="q-filename">${filename}</div>
        <div class="q-status">${status}</div>
        <div class="q-progress">
            <div class="q-bar" style="width: ${status === 'Sending' ? '50%' : '0%'}"></div>
        </div>
    `;
    list.prepend(el);

    // Update count
    document.getElementById('queue-count').innerText = list.children.length;
}

function updateQueue(filename, status) {
    const item = document.querySelector(`.queue-item[data-file="${filename}"]`);
    if (item) {
        item.querySelector('.q-status').innerText = status;
        const bar = item.querySelector('.q-bar');
        if (status === 'Complete') {
            bar.style.width = '100%';
            bar.style.backgroundColor = 'var(--success)';
        } else if (status === 'Failed') {
            bar.style.width = '100%';
            bar.style.backgroundColor = 'var(--danger)';
        }
    }
}

function getFileIcon(type, name) {
    if (type === 'dir') return 'fa-solid fa-folder';
    if (name.endsWith('.pdf')) return 'fa-solid fa-file-pdf';
    if (name.endsWith('.jpg') || name.endsWith('.png')) return 'fa-solid fa-file-image';
    if (name.endsWith('.txt')) return 'fa-solid fa-file-lines';
    return 'fa-solid fa-file';
}

function formatSize(bytes) {
    if (bytes === 0) return '';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) {
        bytes /= 1024;
        i++;
    }
    return bytes.toFixed(1) + ' ' + units[i];
}
