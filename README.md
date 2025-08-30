# NetScan

A Python network device scanner with web interface for Raspberry Pi.

## Features

- **Network Device Scanning**: Automatically discovers devices on your network
- **Modern Web Interface**: Clean, responsive HTML/CSS interface
- **Device Management**: Track hostname, IP, MAC address, open ports, and online status  
- **Custom Device Fields**: Add brand, model, owner, and custom icons
- **People Management**: Associate devices with people and view activity timelines
- **Device Merging**: Merge multiple MAC addresses into one device (e.g., dual-band WiFi)
- **Background Scanning Service**: Configurable scan frequency
- **OUI Database**: Automatic manufacturer lookup from MAC addresses
- **Real-time Updates**: Live status updates on web interface

## Installation

### Quick Start (Development)

```bash
# Clone the repository
git clone https://github.com/nobrega8/netscan.git
cd netscan

# Install dependencies
pip3 install -r requirements.txt

# Initialize database (for new installations)
export FLASK_APP=app.py
flask db upgrade

# Run the application
python3 app.py
```

Access the web interface at: http://localhost:2530

### Raspberry Pi Service Installation

```bash
# Install as system service
sudo ./install.sh

# Initialize/upgrade database
export FLASK_APP=app.py
flask db upgrade

# Start the service
sudo systemctl start netscan

# Enable auto-start on boot
sudo systemctl enable netscan

# Check status
sudo systemctl status netscan
```

### Updating an Existing Installation

NetScan now includes database migrations and auto-healing to handle schema updates safely.

#### Option 1: Automated Deployment (Recommended)

```bash
# Use the deployment script for automatic updates
./deploy.sh
```

The deployment script will:
1. Create a database backup
2. Pull latest changes from Git  
3. Install/update dependencies
4. Run database migrations
5. Restart the service

#### Option 2: Manual Update Process

```bash
# Pull latest changes
git pull --ff-only origin main

# Install/update dependencies
pip install -r requirements.txt

# Run database migrations
export FLASK_APP=app.py
flask db upgrade

# Restart the service
sudo systemctl restart netscan
```

#### Database Auto-Healing

NetScan includes an automatic database healing system for SQLite installations:

- **Automatic**: Missing columns are automatically added when the application starts
- **Safe**: Only adds missing columns, never removes or modifies existing data
- **Logging**: All changes are logged for transparency

To disable auto-healing (not recommended):
```bash
export DISABLE_SQLITE_AUTOHEAL=1
```

#### Migration Troubleshooting

If you encounter database-related errors after an update:

1. **Check migration status**: `flask db current`
2. **View migration history**: `flask db history`
3. **Manual backup**: `cp instance/netscan.db instance/netscan.db.backup`
4. **Reset migrations** (last resort): Delete the database and run `flask db upgrade`

For production deployments, database migrations ensure safe schema evolution without data loss.

## Configuration

Edit `config.py` to customize:

- `SCAN_INTERVAL_MINUTES`: How often to scan the network (default: 30 minutes)
- `NETWORK_RANGE`: Network range to scan (default: auto-detect)
- `DATABASE_URL`: Database location (default: SQLite file)

## Usage

### Web Interface

1. **Dashboard**: Overview of online/offline devices and quick scan
2. **Devices**: Detailed device list with status, IPs, MACs, and ports
3. **People**: Manage people and view their device activity timelines

### Device Management

- Click on any device to view details and scan history
- Edit devices to add custom information (brand, model, owner, icon)
- Merge devices that belong to the same physical device

### People & Timelines

- Add people and assign devices to them
- View activity timelines showing when devices come online/offline
- Track device usage patterns

### Manual Scanning

- Use the "Scan Now" button for immediate network discovery
- Automatic background scanning runs at configured intervals

## API Endpoints

- `GET /api/devices` - JSON list of all devices
- `POST /scan` - Trigger manual network scan
- `POST /merge_devices` - Merge multiple devices

## Requirements

- Python 3.6+
- nmap (system package)
- Network access for scanning
- Root/sudo access for some network operations

## Database Schema

NetScan uses SQLAlchemy with Flask-Migrate for database management:

- **devices**: Core device information and status (includes recent additions: os_info, vendor, device_type, os_family, netbios_name, workgroup, services, category)
- **people**: User/owner information  
- **scans**: Historical scan results and timeline data
- **ouis**: MAC address manufacturer lookup table
- **settings**: Application configuration and preferences

### Database Migrations

The application uses Alembic/Flask-Migrate for safe database schema evolution:

- **Migration files**: Located in `migrations/versions/`
- **Auto-healing**: SQLite installations automatically add missing columns
- **Production safe**: Preserves data during schema updates
- **Version control**: Migration history tracks all schema changes

## License

MIT License
