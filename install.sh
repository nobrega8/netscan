#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/netscan"

# Determine the correct user for running the service
# This ensures the installation works on any Raspberry Pi with any username
# Priority: SUDO_USER (who ran sudo), then USER, then whoami as fallback
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    RUN_USER="$SUDO_USER"
    echo "Detected installation user from SUDO_USER: $RUN_USER"
elif [ -n "${USER:-}" ] && [ "$USER" != "root" ]; then
    RUN_USER="$USER"
    echo "Detected installation user from USER: $RUN_USER"
else
    RUN_USER="$(whoami)"
    if [ "$RUN_USER" = "root" ]; then
        echo "ERROR: Cannot determine non-root user. Please run as a regular user with sudo."
        echo "Example: sudo ./install.sh"
        exit 1
    fi
    echo "Detected installation user from whoami: $RUN_USER"
fi

# Verify the user exists and get their primary group
if ! id "$RUN_USER" >/dev/null 2>&1; then
    echo "ERROR: User '$RUN_USER' does not exist on this system."
    exit 1
fi

RUN_GROUP="$(id -gn "$RUN_USER")"

echo "Installing NetScan service to run as root for advanced scanning capabilities..."
echo "Installation files will be owned by $RUN_USER:$RUN_GROUP for compatibility."

# 1) Copy code to /opt/netscan (if not already there)
SRC="$(pwd)"
if [ "$SRC" != "$APP_DIR" ]; then
  sudo rsync -a --delete "$SRC"/ "$APP_DIR"/
fi
sudo chown -R "$RUN_USER:$RUN_GROUP" "$APP_DIR"

# 2) Install system dependencies (if lock is free)
if ! sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
  echo "Installing system dependencies..."
  sudo apt update
  sudo apt -y install python3-venv nmap
else
  echo "APT is busy; install manually when free: sudo apt -y install python3-venv nmap"
fi

# 3) Generate SECRET_KEY if not provided
if [ -z "${SECRET_KEY:-}" ]; then
  SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  echo "Generated SECRET_KEY: $SECRET_KEY"
  echo "Consider setting SECRET_KEY environment variable for production"
fi

# 4) Create virtual environment and install requirements
cd "$APP_DIR"
echo "Creating virtual environment..."
python3 -m venv venv
echo "Installing dependencies..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# 5) Run database migrations and initialize admin user
echo "Setting up database..."
export FLASK_APP=app.py
export SECRET_KEY="$SECRET_KEY"
./venv/bin/flask db upgrade 2>/dev/null || echo "Database migration not needed or failed"

# Initialize database and create admin user
echo "Initializing database and creating admin user..."
./venv/bin/python -c "
import sys
sys.path.insert(0, '.')
from app import app
with app.app_context():
    from models import db
    from app import create_default_admin
    db.create_all()
    create_default_admin()
    print('Database initialized successfully')
" || echo "Database initialization failed or already complete"

# Ensure proper permissions on database files for root access
sudo chown -R "$RUN_USER:$RUN_GROUP" "$APP_DIR"
if [ -f "instance/netscan.db" ]; then
    sudo chown root:root instance/netscan.db
    sudo chmod 644 instance/netscan.db
fi
if [ -d "instance" ]; then
    sudo chown -R root:root instance/
    sudo chmod 755 instance/
fi

# 6) Create/update systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/netscan.service >/dev/null <<SERVICE
[Unit]
Description=NetScan Network Device Scanner (Advanced Mode)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$APP_DIR
Environment="PYTHONUNBUFFERED=1"
Environment="SECRET_KEY=$SECRET_KEY"
Environment="NETSCAN_PORT=2530"
Environment="ENABLE_OS_DETECTION=true"
Environment="ENABLE_SYN_SCAN=true"
Environment="PATH=$APP_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/service.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

echo "Starting and enabling service..."
sudo systemctl daemon-reload
sudo systemctl enable --now netscan
sudo systemctl status netscan --no-pager
echo "Done. NetScan service is now running as root with advanced scanning capabilities!"
echo ""
echo "Advanced features enabled:"
echo "  - OS Detection: Enabled (requires root)"
echo "  - SYN Scanning: Enabled (requires root)"
echo "  - Full nmap capabilities available"
echo ""
echo "Useful commands:"
echo "  View logs: sudo journalctl -u netscan -f"
echo "  Stop service: sudo systemctl stop netscan"
echo "  Start service: sudo systemctl start netscan"
echo "  Restart service: sudo systemctl restart netscan"
