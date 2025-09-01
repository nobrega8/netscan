#!/usr/bin/env bash
# NetScan Update Script
# Handles complete system update with database backup and migrations

set -e  # Exit on any error

# Configuration
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$APP_DIR/update.log"
BACKUP_DIR="$APP_DIR/backups"
DB_FILE="$APP_DIR/instance/netscan.db"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

log "=== NetScan Update Process Started ==="
log "Working directory: $APP_DIR"

# Change to application directory
cd "$APP_DIR"

# 1. Create database backup
if [ -f "$DB_FILE" ]; then
    BACKUP_FILE="$BACKUP_DIR/netscan-$(date +%Y%m%d-%H%M).db"
    log "Creating database backup: $BACKUP_FILE"
    cp "$DB_FILE" "$BACKUP_FILE" || error_exit "Failed to create database backup"
    log "Database backup created successfully"
else
    log "No existing database found, skipping backup"
fi

# 2. Get current commit hash for logging
CURRENT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
log "Current commit: $CURRENT_COMMIT"

# 3. Pull latest changes from Git
log "Pulling latest changes from Git..."
git pull --ff-only origin main || error_exit "Git pull failed"

# Get new commit hash
NEW_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
log "Updated to commit: $NEW_COMMIT"

# 4. Install/update Python dependencies
if [ -f "venv/bin/activate" ]; then
    log "Activating virtual environment..."
    source venv/bin/activate
else
    log "Warning: Virtual environment not found at venv/bin/activate"
    log "Using system Python environment"
fi

log "Installing/updating dependencies..."
pip install -r requirements.txt || error_exit "Failed to install dependencies"

# 5. Run database migrations
log "Running database migrations..."
export FLASK_APP=app.py
flask db upgrade || error_exit "Database migration failed"

# 6. Restart the service
log "Restarting NetScan service..."
if systemctl is-active --quiet netscan 2>/dev/null; then
    log "Stopping NetScan service..."
    sudo systemctl stop netscan || error_exit "Failed to stop service"
    
    log "Starting NetScan service..."
    sudo systemctl start netscan || error_exit "Failed to start service"
    
    # Wait a moment and check if service is running
    sleep 2
    if systemctl is-active --quiet netscan; then
        log "✅ NetScan service is running"
    else
        error_exit "❌ NetScan service failed to start"
    fi
else
    log "NetScan service not found or not running as systemd service"
    log "Manual restart may be required"
fi

# 7. Cleanup old backups (keep last 10)
log "Cleaning up old backups..."
ls -t "$BACKUP_DIR"/netscan-*.db 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true

log "=== Update Process Completed Successfully ==="
log "Updated from $CURRENT_COMMIT to $NEW_COMMIT"
log "Service status: $(systemctl is-active netscan 2>/dev/null || echo 'unknown')"
log "Access the web interface at: http://localhost:2530"

# Write update status for UI
cat > "$APP_DIR/update_status.json" <<EOF
{
    "last_update": "$(date -Iseconds)",
    "status": "success",
    "from_commit": "$CURRENT_COMMIT",
    "to_commit": "$NEW_COMMIT",
    "log_file": "$LOG_FILE"
}
EOF

echo "Update completed successfully!"