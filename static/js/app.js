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

// Cleanup when page unloads
window.addEventListener('beforeunload', function() {
    stopAutoRefresh();
});