#!/bin/bash

# NetScan Service Installation Script for Raspberry Pi

SERVICE_NAME="netscan"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_DIR="/opt/netscan"
USER="pi"

echo "Installing NetScan service..."

# Create installation directory
sudo mkdir -p $INSTALL_DIR
sudo cp -r . $INSTALL_DIR/
sudo chown -R $USER:$USER $INSTALL_DIR

# Install system dependencies
echo "Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y python3 python3-pip nmap

# Install Python dependencies
echo "Installing Python dependencies..."
cd $INSTALL_DIR
sudo pip3 install -r requirements.txt

# Create systemd service file
echo "Creating systemd service..."
sudo tee $SERVICE_FILE > /dev/null <<EOF
[Unit]
Description=NetScan Network Device Scanner
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/service.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME

echo "Installation complete!"
echo ""
echo "To start the service: sudo systemctl start $SERVICE_NAME"
echo "To check status: sudo systemctl status $SERVICE_NAME"
echo "To view logs: sudo journalctl -u $SERVICE_NAME -f"
echo "To access web interface: http://localhost:5000"