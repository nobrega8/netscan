#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/netscan"
RUN_USER="${SUDO_USER:-$USER}"
RUN_GROUP="$(id -gn "$RUN_USER")"

echo "Installing NetScan service as $RUN_USER:$RUN_GROUP ..."

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

# 5) Run database migrations
echo "Setting up database..."
export FLASK_APP=app.py
export SECRET_KEY="$SECRET_KEY"
./venv/bin/flask db upgrade 2>/dev/null || echo "Database migration not needed or failed"

# 6) Create/update systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/netscan.service >/dev/null <<SERVICE
[Unit]
Description=NetScan Network Device Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_GROUP
WorkingDirectory=$APP_DIR
Environment="PYTHONUNBUFFERED=1"
Environment="SECRET_KEY=$SECRET_KEY"
Environment="NETSCAN_PORT=2530"
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
echo "Done. NetScan service is now running!"
echo ""
echo "Useful commands:"
echo "  View logs: sudo journalctl -u netscan -f"
echo "  Stop service: sudo systemctl stop netscan"
echo "  Start service: sudo systemctl start netscan"
echo "  Restart service: sudo systemctl restart netscan"
