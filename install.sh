sudo tee /opt/netscan/install.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/netscan"
RUN_USER="${SUDO_USER:-$USER}"
RUN_GROUP="$(id -gn "$RUN_USER")"

echo "Installing NetScan service as $RUN_USER:$RUN_GROUP ..."

# 1) Copiar código para /opt/netscan (se ainda não estiver aí)
SRC="$(pwd)"
if [ "$SRC" != "$APP_DIR" ]; then
  sudo rsync -a --delete "$SRC"/ "$APP_DIR"/
fi
sudo chown -R "$RUN_USER:$RUN_GROUP" "$APP_DIR"

# 2) Dependências do sistema (opcional, só se lock estiver livre)
if ! sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
  sudo apt -y install python3-venv
else
  echo "APT está ocupado; a instalar só quando livre ou instala manualmente: sudo apt -y install python3-venv"
fi

# 3) Generate SECRET_KEY if not provided
if [ -z "$SECRET_KEY" ]; then
  SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  echo "Generated SECRET_KEY: $SECRET_KEY"
  echo "Consider setting SECRET_KEY environment variable for production"
fi

# 4) venv + requirements
cd "$APP_DIR"
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# 5) Run database migrations
export FLASK_APP=app.py
export SECRET_KEY="$SECRET_KEY"
./venv/bin/flask db upgrade 2>/dev/null || echo "Database migration not needed or failed"

# 6) Criar/atualizar serviço systemd
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
Environment="PATH=$APP_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/service.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable --now netscan
sudo systemctl status netscan --no-pager
echo "Done."
EOF

sudo chmod +x /opt/netscan/install.sh
