#!/usr/bin/env bash
# NetScan Deployment Script
# This script handles updating the application with database migrations

set -e  # Exit on any error

echo "=== NetScan Deployment Script ==="
echo "Starting deployment process..."

# Change to application directory
cd "$(dirname "$0")"

# Backup current database (optional but recommended)
if [ -f "instance/netscan.db" ]; then
    echo "Creating database backup..."
    cp instance/netscan.db instance/netscan.db.backup.$(date +%Y%m%d_%H%M%S)
    echo "Database backed up"
fi

# Pull latest changes from Git
echo "Pulling latest changes from Git..."
git pull --ff-only origin main

# Install/update Python dependencies
if [ -f "venv/bin/activate" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
else
    echo "Warning: Virtual environment not found at venv/bin/activate"
    echo "Please ensure you have the correct Python environment activated"
fi

echo "Installing/updating dependencies..."
pip install -r requirements.txt

# Run database migrations
echo "Running database migrations..."
export FLASK_APP=app.py
flask db upgrade

# Restart the service
echo "Restarting NetScan service..."
if systemctl is-active --quiet netscan; then
    echo "Stopping NetScan service..."
    sudo systemctl stop netscan
fi

echo "Starting NetScan service..."
sudo systemctl start netscan

# Check service status
if systemctl is-active --quiet netscan; then
    echo "✅ NetScan service is running"
else
    echo "❌ NetScan service failed to start"
    echo "Check logs with: sudo journalctl -u netscan -f"
    exit 1
fi

echo "=== Deployment completed successfully! ==="
echo ""
echo "The NetScan application has been updated and is running."
echo "If you encounter any issues, check the service logs:"
echo "  sudo journalctl -u netscan -f"
echo ""
echo "Auto-healing is enabled by default. If you need to disable it:"
echo "  export DISABLE_SQLITE_AUTOHEAL=1"