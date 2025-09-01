// Enhanced NetScan Application JavaScript

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
                statusBadge.className = 'badge badge-success gap-2';
                statusBadge.innerHTML = '<i class="fas fa-circle text-xs"></i>Online';
            } else {
                statusBadge.className = 'badge badge-ghost gap-2';
                statusBadge.innerHTML = '<i class="fas fa-circle text-xs"></i>Offline';
            }
        }
        
        // Update last seen
        const lastSeenCell = row.querySelector('.last-seen');
        if (lastSeenCell && device.last_seen) {
            const date = new Date(device.last_seen);
            lastSeenCell.textContent = date.toLocaleDateString() + ' ' + 
                                     date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        }
    });
}

// Enhanced scan functionality with better error handling
function startScan() {
    const button = event.target;
    const originalContent = button.innerHTML;
    
    button.disabled = true;
    button.innerHTML = '<span class="loading loading-spinner loading-sm"></span> Scanning...';
    
    fetch('/scan', { 
        method: 'POST',
        headers: {
            'X-CSRFToken': document.querySelector('meta[name=csrf-token]').getAttribute('content')
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            if (window.showToast) {
                showToast(`Scan completed! Found ${data.devices_found} devices.`, 'success');
            } else {
                alert(`Scan completed! Found ${data.devices_found} devices.`);
            }
            
            // Trigger HTMX refresh if available
            if (typeof htmx !== 'undefined') {
                htmx.trigger(document.body, 'scan-completed');
            } else {
                location.reload();
            }
        } else {
            if (window.showToast) {
                showToast(`Scan failed: ${data.error}`, 'error');
            } else {
                alert(`Scan failed: ${data.error}`);
            }
        }
    })
    .catch(error => {
        if (window.showToast) {
            showToast(`Error: ${error}`, 'error');
        } else {
            alert(`Error: ${error}`);
        }
    })
    .finally(() => {
        button.disabled = false;
        button.innerHTML = originalContent;
    });
}

// Device merging functionality
function mergeSelectedDevices() {
    const checkedBoxes = document.querySelectorAll('input[type="checkbox"][data-device-id]:checked');
    const deviceIds = Array.from(checkedBoxes).map(cb => parseInt(cb.dataset.deviceId));
    
    if (deviceIds.length < 2) {
        if (window.showToast) {
            showToast('Please select at least 2 devices to merge', 'error');
        } else {
            alert('Please select at least 2 devices to merge');
        }
        return;
    }
    
    const confirmed = confirm(`Are you sure you want to merge ${deviceIds.length} devices? This action cannot be undone.`);
    if (!confirmed) return;
    
    fetch('/api/devices/merge', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name=csrf-token]').getAttribute('content')
        },
        body: JSON.stringify({ device_ids: deviceIds })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            if (window.showToast) {
                showToast('Devices merged successfully', 'success');
            } else {
                alert('Devices merged successfully');
            }
            location.reload();
        } else {
            if (window.showToast) {
                showToast(`Error: ${data.error}`, 'error');
            } else {
                alert(`Error: ${data.error}`);
            }
        }
    })
    .catch(error => {
        if (window.showToast) {
            showToast(`Error: ${error}`, 'error');
        } else {
            alert(`Error: ${error}`);
        }
    });
}

// Update merge button state based on selected devices
function updateMergeButton() {
    const checkedBoxes = document.querySelectorAll('input[type="checkbox"][data-device-id]:checked');
    const mergeButton = document.getElementById('merge-button');
    
    if (mergeButton) {
        mergeButton.disabled = checkedBoxes.length < 2;
        if (checkedBoxes.length > 0) {
            mergeButton.innerHTML = `<i class="fas fa-compress-arrows-alt me-2"></i>Merge Devices (${checkedBoxes.length})`;
        } else {
            mergeButton.innerHTML = '<i class="fas fa-compress-arrows-alt me-2"></i>Merge Devices';
        }
    }
}

// Add event listeners for device selection
document.addEventListener('change', function(e) {
    if (e.target.type === 'checkbox' && e.target.dataset.deviceId) {
        updateMergeButton();
    }
});

// GitHub-style avatars initialization
function initializeGitHubAvatars() {
    // This function can be used to initialize avatar placeholders
    const avatars = document.querySelectorAll('.avatar-placeholder');
    avatars.forEach(avatar => {
        const name = avatar.dataset.name;
        if (name) {
            avatar.textContent = name.charAt(0).toUpperCase();
        }
    });
}

// Dark mode toggle functionality
function toggleDarkMode() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('darkMode', newTheme === 'dark');
    
    // Update theme toggle icon if it exists
    const themeToggle = document.querySelector('.theme-toggle');
    if (themeToggle) {
        const icon = themeToggle.querySelector('i');
        if (icon) {
            icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }
}

// Table sorting functionality
function sortTable(columnIndex, dataType = 'string') {
    const table = document.querySelector('table');
    if (!table) return;
    
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    
    // Determine sort direction
    const header = table.querySelectorAll('th')[columnIndex];
    const currentDir = header.dataset.sortDir || 'asc';
    const newDir = currentDir === 'asc' ? 'desc' : 'asc';
    
    // Clear all sort indicators
    table.querySelectorAll('th').forEach(th => {
        th.dataset.sortDir = '';
        const icon = th.querySelector('.sort-icon');
        if (icon) icon.className = 'fas fa-sort sort-icon';
    });
    
    // Set new sort direction
    header.dataset.sortDir = newDir;
    const sortIcon = header.querySelector('.sort-icon');
    if (sortIcon) {
        sortIcon.className = `fas fa-sort-${newDir === 'asc' ? 'up' : 'down'} sort-icon`;
    }
    
    // Sort rows
    rows.sort((a, b) => {
        const aCell = a.cells[columnIndex];
        const bCell = b.cells[columnIndex];
        
        let aVal = aCell.textContent.trim();
        let bVal = bCell.textContent.trim();
        
        if (dataType === 'number') {
            aVal = parseFloat(aVal) || 0;
            bVal = parseFloat(bVal) || 0;
        } else if (dataType === 'date') {
            aVal = new Date(aVal);
            bVal = new Date(bVal);
        }
        
        if (aVal < bVal) return newDir === 'asc' ? -1 : 1;
        if (aVal > bVal) return newDir === 'asc' ? 1 : -1;
        return 0;
    });
    
    // Reorder rows in table
    rows.forEach(row => tbody.appendChild(row));
}

// Export functionality
function exportDevices(format) {
    const url = `/api/export/devices?format=${format}`;
    const link = document.createElement('a');
    link.href = url;
    link.download = `netscan_devices.${format}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    if (window.showToast) {
        showToast(`Exporting devices as ${format.toUpperCase()}...`, 'info');
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Initialize GitHub-style avatars
    initializeGitHubAvatars();
    
    // Start auto-refresh for device status
    if (window.location.pathname.includes('devices') || window.location.pathname.includes('dashboard')) {
        startAutoRefresh(30000); // 30 seconds
    }
    
    // Setup HTMX error handling
    if (typeof htmx !== 'undefined') {
        htmx.on('htmx:responseError', function(evt) {
            console.error('HTMX Error:', evt.detail);
            if (window.showToast) {
                showToast('Failed to update content', 'error');
            }
        });
        
        htmx.on('htmx:sendError', function(evt) {
            console.error('HTMX Send Error:', evt.detail);
            if (window.showToast) {
                showToast('Network error', 'error');
            }
        });
    }
    
    // Setup table sorting
    const sortableHeaders = document.querySelectorAll('th[data-sortable]');
    sortableHeaders.forEach((header, index) => {
        header.style.cursor = 'pointer';
        header.addEventListener('click', () => {
            const dataType = header.dataset.sortType || 'string';
            sortTable(index, dataType);
        });
        
        // Add sort icon if not present
        if (!header.querySelector('.sort-icon')) {
            header.innerHTML += ' <i class="fas fa-sort sort-icon"></i>';
        }
    });
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    stopAutoRefresh();
});
        
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