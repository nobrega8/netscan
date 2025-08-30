// NetScan Application JavaScript

// Auto-refresh functionality
let autoRefreshInterval;

function startAutoRefresh(intervalMs = 30000) {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
    
    autoRefreshInterval = setInterval(() => {
        updateDeviceStatus();
    }, intervalMs);
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

// Update device status via API
function updateDeviceStatus() {
    fetch('/api/devices')
        .then(response => response.json())
        .then(devices => {
            devices.forEach(device => {
                updateDeviceRow(device);
            });
        })
        .catch(error => {
            console.error('Error updating device status:', error);
        });
}

function updateDeviceRow(device) {
    const rows = document.querySelectorAll(`tr[data-device-id="${device.id}"]`);
    rows.forEach(row => {
        const statusBadge = row.querySelector('.badge');
        if (statusBadge) {
            if (device.is_online) {
                statusBadge.className = 'badge bg-success';
                statusBadge.innerHTML = '<i class="fas fa-circle me-1"></i>Online';
            } else {
                statusBadge.className = 'badge bg-secondary';
                statusBadge.innerHTML = '<i class="fas fa-circle me-1"></i>Offline';
            }
        }
        
        const lastSeenCell = row.querySelector('.last-seen');
        if (lastSeenCell && device.last_seen) {
            const date = new Date(device.last_seen);
            lastSeenCell.textContent = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        }
    });
}

// Device selection for merging
let selectedDevices = new Set();

function toggleDeviceSelection(deviceId) {
    const checkbox = document.querySelector(`input[data-device-id="${deviceId}"]`);
    const row = checkbox.closest('tr');
    
    if (checkbox.checked) {
        selectedDevices.add(deviceId);
        row.classList.add('table-active');
    } else {
        selectedDevices.delete(deviceId);
        row.classList.remove('table-active');
    }
    
    updateMergeButton();
}

function updateMergeButton() {
    const mergeButton = document.getElementById('merge-button');
    if (mergeButton) {
        mergeButton.disabled = selectedDevices.size < 2;
        mergeButton.textContent = `Merge ${selectedDevices.size} devices`;
    }
}

function mergeSelectedDevices() {
    if (selectedDevices.size < 2) {
        alert('Please select at least 2 devices to merge.');
        return;
    }
    
    const deviceIds = Array.from(selectedDevices);
    const primaryDeviceId = deviceIds[0];
    const devicesToMerge = deviceIds.slice(1);
    
    if (confirm(`Merge ${devicesToMerge.length} devices into the primary device?`)) {
        fetch('/merge_devices', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                primary_device_id: primaryDeviceId,
                device_ids: devicesToMerge
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Devices merged successfully!');
                location.reload();
            } else {
                alert(`Error merging devices: ${data.error}`);
            }
        })
        .catch(error => {
            alert(`Error: ${error}`);
        });
    }
}

// Utility functions
function formatDate(dateString) {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function formatMacAddress(mac) {
    return mac.toUpperCase().replace(/(.{2})/g, '$1:').slice(0, -1);
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Start auto-refresh on device pages
    if (window.location.pathname.includes('/devices') || window.location.pathname === '/') {
        startAutoRefresh();
    }
    
    // Initialize GitHub-style avatars
    initializeGitHubAvatars();
    
    // Add device ID attributes to table rows for easier updates
    const deviceRows = document.querySelectorAll('table tbody tr');
    deviceRows.forEach((row, index) => {
        const deviceLink = row.querySelector('a[href*="/device/"]');
        if (deviceLink) {
            const deviceId = deviceLink.href.split('/device/')[1];
            row.setAttribute('data-device-id', deviceId);
        }
    });
});

// GitHub-style avatar generation
function generateGitHubAvatar(identifier, size = 80) {
    // Create a simple hash from the identifier
    let hash = 0;
    for (let i = 0; i < identifier.length; i++) {
        const char = identifier.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    
    // Generate colors based on hash
    const hue = Math.abs(hash) % 360;
    const saturation = 65 + (Math.abs(hash >> 8) % 20); // 65-85%
    const lightness = 40 + (Math.abs(hash >> 16) % 20); // 40-60%
    
    // Create canvas
    const canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d');
    
    // Background
    ctx.fillStyle = `hsl(${hue}, ${saturation}%, ${lightness}%)`;
    ctx.fillRect(0, 0, size, size);
    
    // Generate geometric pattern (GitHub-style identicon)
    const gridSize = 5;
    const cellSize = size / gridSize;
    
    // Create a pattern based on hash
    for (let x = 0; x < Math.ceil(gridSize / 2); x++) {
        for (let y = 0; y < gridSize; y++) {
            const index = x * gridSize + y;
            const hashBit = (Math.abs(hash >> index) % 2) === 1;
            
            if (hashBit) {
                // Darker shade for pattern
                ctx.fillStyle = `hsl(${hue}, ${saturation}%, ${lightness - 20}%)`;
                
                // Draw left side
                ctx.fillRect(x * cellSize, y * cellSize, cellSize, cellSize);
                
                // Mirror to right side (except middle column)
                if (x < Math.floor(gridSize / 2)) {
                    ctx.fillRect((gridSize - 1 - x) * cellSize, y * cellSize, cellSize, cellSize);
                }
            }
        }
    }
    
    return canvas.toDataURL();
}

function setGitHubAvatar(element, identifier) {
    const avatarUrl = generateGitHubAvatar(identifier, 80);
    element.style.backgroundImage = `url(${avatarUrl})`;
    element.classList.add('github-avatar');
    element.innerHTML = ''; // Remove initials
}

// Initialize GitHub-style avatars for people without photos
function initializeGitHubAvatars() {
    const avatarElements = document.querySelectorAll('.github-avatar:not([style*="background-image"])');
    avatarElements.forEach(element => {
        // Get identifier from data attribute
        const identifier = element.dataset.identifier;
        if (identifier) {
            setGitHubAvatar(element, identifier);
        }
    });
}

// Cleanup when page unloads
window.addEventListener('beforeunload', function() {
    stopAutoRefresh();
});