# NetScan

A Python network device scanner with web interface for Raspberry Pi.

## Features

- **Network Device Scanning**: Automatically discovers devices on your network
- **Modern Web Interface**: Clean, responsive HTML/CSS interface with authentication
- **User Authentication**: Role-based access control (Admin/Editor/Viewer)
- **Device Management**: Track hostname, IP, MAC address, open ports, and online status  
- **Custom Device Fields**: Add brand, model, owner, and custom icons
- **People Management**: Associate devices with people and view activity timelines
- **Device Merging**: Merge multiple MAC addresses into one device (e.g., dual-band WiFi)
- **Background Scanning Service**: Configurable scan frequency
- **OUI Database**: Automatic manufacturer lookup from MAC addresses
- **Real-time Updates**: Live status updates on web interface
- **Security**: CSRF protection, rate limiting, secure sessions

## Authentication System

NetScan includes a comprehensive authentication system:

### User Roles
- **Admin**: Full access, can manage users and system settings
- **Editor**: Can perform scans and manage devices/people, but cannot manage users
- **Viewer**: Read-only access to dashboard and device information

### Security Features
- Password hashing with secure salt
- CSRF protection on all forms
- Rate limiting on login attempts (5 attempts per minute)
- Account locking after failed login attempts
- Secure session cookies
- Mandatory password change on first login

### Default Setup
On first installation, a default admin user is created:
- Username: `admin` (configurable via `ADMIN_USERNAME` env var)
- Password: `admin123` (configurable via `ADMIN_PASSWORD` env var)
- **Must change password on first login**

## Installation

### Recommended Installation (Production Service)

This is the recommended method for most users, especially on Raspberry Pi and other Linux systems:

```bash
# Clone the repository
git clone https://github.com/nobrega8/netscan.git
cd netscan

# Install system dependencies (required on Raspberry Pi/Debian)
sudo apt update
sudo apt install python3-venv

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Set up authentication (recommended)
export SECRET_KEY="your-secret-key-here"
export ADMIN_USERNAME="your-admin-username"  # optional, defaults to 'admin'
export ADMIN_PASSWORD="your-secure-password"  # optional, defaults to 'admin123'

# Initialize database
export FLASK_APP=app.py
flask db upgrade

# Run as service (recommended) - see Service Installation section below
# OR run manually for testing:
python3 app.py
```

Access the web interface at: http://localhost:2530

**First Login**: Use the default credentials (admin/admin123) and you'll be prompted to change the password.

**Note for Raspberry Pi Users**: The `python3-venv` package is required to avoid PEP 668 errors on modern Debian systems. Using a virtual environment keeps dependencies isolated and prevents conflicts with system packages.

### Service Installation (Recommended for Production)

For production use, especially on Raspberry Pi, install NetScan as a systemd service:

```bash
# After completing the basic installation above, install as service
sudo ./install.sh

# The install script will:
# 1. Copy files to /opt/netscan
# 2. Create virtual environment
# 3. Install dependencies
# 4. Set up systemd service
# 5. Start and enable the service

# Check service status
sudo systemctl status netscan

# View service logs
sudo journalctl -u netscan -f
```

The service will start automatically on boot and restart if it crashes.

### Development Installation

For development and testing purposes:

```bash
# Clone the repository
git clone https://github.com/nobrega8/netscan.git
cd netscan

# Create virtual environment (recommended even for development)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up authentication
export SECRET_KEY="your-secret-key-here"
export FLASK_APP=app.py

# Initialize database
flask db upgrade

# Run in development mode
python3 app.py
```

For development, you can also install dependencies system-wide if you prefer (though not recommended on modern Debian systems):

```bash
# Alternative for development only (may cause PEP 668 errors on Raspberry Pi)
pip3 install -r requirements.txt
```

## Configuration

### Environment Variables

NetScan supports the following environment variables:

- `SECRET_KEY`: Flask secret key for sessions (required for production)
- `NETSCAN_PORT`: Port for the web service (default: 2530)
- `ADMIN_USERNAME`: Default admin username (default: 'admin')  
- `ADMIN_PASSWORD`: Default admin password (default: 'admin123')
- `DATABASE_URL`: Database connection string (default: SQLite)
- `SCAN_INTERVAL_MINUTES`: Auto-scan interval (default: 30)
- `NETWORK_RANGE`: Network range to scan (default: auto-detect)

#### Example Configuration

Create a `.env` file in the project root (copy from `.env.example`):

```bash
# Copy example configuration
cp .env.example .env

# Edit the configuration
nano .env
```

Example `.env` file:
```bash
SECRET_KEY=your-long-random-secret-key-here
NETSCAN_PORT=2530
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password
SCAN_INTERVAL_MINUTES=30
NETWORK_RANGE=auto
```

### Service Management

After installing NetScan as a service (see Service Installation section above), use these commands:

```bash
# Check service status
sudo systemctl status netscan

# Start/stop the service
sudo systemctl start netscan
sudo systemctl stop netscan

# Enable/disable auto-start on boot
sudo systemctl enable netscan
sudo systemctl disable netscan

# View service logs
sudo journalctl -u netscan -f

# Restart the service
sudo systemctl restart netscan
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

# Activate virtual environment (if using venv)
source venv/bin/activate

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

### Troubleshooting

#### Port Configuration Issues

If the service is not accessible:

1. **Check the port**: NetScan runs on port 2530 by default
   ```bash
   # Check if the service is running
   sudo systemctl status netscan
   
   # Check if port is in use
   sudo netstat -tlnp | grep 2530
   ```

2. **Change port if needed**: Set `NETSCAN_PORT` environment variable
   ```bash
   # For systemd service
   sudo systemctl edit netscan
   # Add:
   # [Service]
   # Environment="NETSCAN_PORT=8080"
   
   # For development
   export NETSCAN_PORT=8080
   python3 app.py
   ```

3. **Firewall issues**: Ensure the port is not blocked
   ```bash
   # Ubuntu/Debian
   sudo ufw allow 2530
   
   # CentOS/RHEL
   sudo firewall-cmd --add-port=2530/tcp --permanent
   ```

#### Service Issues

1. **Service won't start**: Check logs
   ```bash
   sudo journalctl -u netscan -f
   ```

2. **Permission issues**: Ensure correct ownership
   ```bash
   sudo chown -R netscan:netscan /opt/netscan
   ```

3. **Database errors**: Reset database (last resort)
   ```bash
   rm instance/netscan.db
   export FLASK_APP=app.py
   # Use venv if installed as service
   source venv/bin/activate  # for manual installations
   flask db upgrade
   ```

#### Update Issues

1. **Update fails**: Check update logs
   ```bash
   tail -f update.log
   ```

2. **Git conflicts**: Resolve manually
   ```bash
   git status
   git stash  # save local changes
   git pull origin main
   ```

3. **Dependency issues**: Reinstall requirements
   ```bash
   # For service installations
   source /opt/netscan/venv/bin/activate
   pip install -r requirements.txt --force-reinstall
   
   # For manual installations
   source venv/bin/activate
   pip install -r requirements.txt --force-reinstall
   ```

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

All API endpoints require authentication. Use session-based authentication by logging in through the web interface.

### Device Management (Login Required)
- `GET /api/devices` - JSON list of all devices
- `GET /device/<id>` - Device details page  
- `GET /device/<id>/edit` - Edit device (Editor+ role)

### Network Operations (Editor+ Role Required)
- `POST /scan` - Trigger manual network scan
- `POST /device/<id>/scan_ports` - Scan ports for specific device
- `POST /merge_devices` - Merge multiple devices

### Admin Operations (Admin Role Required)  
- `POST /update_system` - Update application from git
- `POST /update_oui` - Update OUI database

### Speed Testing (Login Required)
- `POST /api/speed-test/ping` - Network ping test
- `POST /api/speed-test/download` - Download speed test  
- `POST /api/speed-test/upload` - Upload speed test
- `POST /api/speed-test/full` - Complete speed test

### Health Check (Public)
- `GET /healthz` - Health check endpoint (no authentication required)

## Requirements

- Python 3.6+
- nmap (system package)
- Network access for scanning
- Root/sudo access for some network operations

## Database Schema

NetScan uses SQLAlchemy with Flask-Migrate for database management:

- **users**: Authentication and authorization (username, password_hash, role, login tracking)
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
