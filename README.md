# NetScan

A Python network device scanner with web interface for Raspberry Pi.

## Quick Start Guide

For users who want to get NetScan running immediately:

### Option 1: Automated Installation (Recommended)
```bash
# Clone and install with a single script
git clone https://github.com/nobrega8/netscan.git
cd netscan
sudo ./install.sh
```

### Option 2: Docker (Easiest)
```bash
# Clone and start with Docker
git clone https://github.com/nobrega8/netscan.git
cd netscan
cp .env.docker.example .env
docker compose up -d
```

### Option 3: Manual Installation
```bash
# Install prerequisites
sudo apt update && sudo apt -y install python3-venv python3-dev build-essential nmap

# Clone and setup
git clone https://github.com/nobrega8/netscan.git
cd netscan
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
export FLASK_APP=app.py
flask db upgrade
python3 app.py
```

**Access**: Open http://localhost:2530 in your browser
**Default Login**: admin / admin123 (you'll be prompted to change this)

### Verification

After installation, verify everything is working:

1. **Check service status** (if using systemd installation):
   ```bash
   sudo systemctl status netscan
   ```

2. **Test web interface**: Visit http://localhost:2530 and log in

3. **Verify dependencies**:
   ```bash
   # Check nmap is installed
   nmap --version
   
   # Check Python virtual environment (if using manual installation)
   source venv/bin/activate
   python -c "import flask, nmap; print('Dependencies OK')"
   ```

4. **Test basic scan**: After logging in, click "Scan Now" to test network discovery

---

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

## Prerequisites

### System Requirements (Debian/Raspberry Pi)

Before installing NetScan, ensure your system has the required dependencies:

```bash
# Update package list
sudo apt update

# Install required system packages (including build tools for Python packages)
sudo apt -y install python3-venv python3-dev build-essential nmap

# Optional: Enable SYN scans without sudo (recommended for better performance)
sudo apt -y install libcap2-bin
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"

# Optional: Fix locale warnings (if you see locale errors)
sudo apt -y install locales
sudo update-locale LANG=en_GB.UTF-8 LC_CTYPE=en_GB.UTF-8
```

#### About the Dependencies

- **python3-venv**: Required to create virtual environments (PEP 668 compliance on modern Debian/Ubuntu)
- **python3-dev**: Development headers for Python (required to compile some packages)
- **build-essential**: C/C++ compilers and build tools (required for packages like netifaces and psutil)
- **nmap**: Network mapping tool used for device discovery and port scanning
- **libcap2-bin**: Allows nmap to run SYN scans without root privileges (optional but recommended)
- **locales**: Prevents locale-related warnings during installation

#### Nmap Scan Types

NetScan automatically chooses the appropriate scan type:
- **Without setcap**: Uses `-sT` (TCP connect) scans - slower but works without privileges
- **With setcap**: Uses `-sS` (SYN) scans - faster and more efficient

## Installation

### Production Installation (Recommended)

This is the recommended method for most users, especially on Raspberry Pi and production systems:

```bash
# Clone the repository to /opt/netscan
sudo git clone https://github.com/nobrega8/netscan.git /opt/netscan

# Set correct ownership (replace 'pi' with your username)
sudo chown -R pi:pi /opt/netscan
cd /opt/netscan

# Create virtual environment
python3 -m venv venv

# Install dependencies
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# Initialize database
export FLASK_APP=app.py
./venv/bin/flask db upgrade

# Install as systemd service (see Service Installation section below)
sudo ./install.sh
```

### Service Installation (Systemd)

For production use, install NetScan as a systemd service that starts automatically on boot:

For production use, install NetScan as a systemd service that starts automatically on boot:

```bash
# After completing the production installation above
sudo ./install.sh

# The install script will:
# 1. Install system dependencies (python3-venv, nmap if not present)
# 2. Copy files to /opt/netscan if needed
# 3. Create virtual environment
# 4. Install Python dependencies
# 5. Run database migrations
# 6. Create and start systemd service

# Check service status
sudo systemctl status netscan --no-pager

# View service logs
sudo journalctl -u netscan -f
```

#### Systemd Service Configuration

The install script creates `/etc/systemd/system/netscan.service`:

```ini
[Unit]
Description=NetScan Network Device Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pi
Group=pi
WorkingDirectory=/opt/netscan
Environment="PYTHONUNBUFFERED=1"
Environment="SECRET_KEY=<auto-generated>"
Environment="NETSCAN_PORT=2530"
Environment="PATH=/opt/netscan/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
ExecStart=/opt/netscan/venv/bin/python /opt/netscan/service.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

The service will start automatically on boot and restart if it crashes.

Access the web interface at: http://localhost:2530

**First Login**: Use the default credentials (admin/admin123) and you'll be prompted to change the password.

### Development Installation

For development and testing purposes:

```bash
# Clone the repository
git clone https://github.com/nobrega8/netscan.git
cd netscan

# Install system dependencies first (important!)
sudo apt update
sudo apt -y install python3-venv python3-dev build-essential nmap

# Create virtual environment (recommended even for development)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create environment configuration (optional but recommended)
cp .env.example .env
# Edit .env file to customize settings if needed

# Set up authentication (optional for development)
export SECRET_KEY="development-secret-key"
export FLASK_APP=app.py

# Initialize database
flask db upgrade

# Run in development mode
python3 app.py
```

Access the web interface at: http://localhost:2530

**Note**: For development on systems without the Prerequisites installed, you may encounter warnings about missing nmap or locale issues. Install the system dependencies as described in the Prerequisites section.

### Docker Installation (Recommended for Easy Setup)

Docker provides the easiest way to run NetScan with all dependencies pre-configured:

#### Quick Start with Docker Compose

```bash
# Clone the repository
git clone https://github.com/nobrega8/netscan.git
cd netscan

# Create environment file from template
cp .env.docker.example .env

# Edit the environment file (important: change default passwords!)
nano .env

# Start the application
docker compose up -d

# View logs
docker compose logs -f netscan
```

Access the web interface at: http://localhost:2530

#### Docker Environment Configuration

Edit the `.env` file to customize your installation:

```bash
# Required: Change these for security
SECRET_KEY=your-very-secure-secret-key-for-production
ADMIN_PASSWORD=your-secure-admin-password

# Optional: Customize settings
SCAN_INTERVAL_MINUTES=30
NETWORK_RANGE=auto
NETSCAN_DISABLE_STARTUP_SCAN=true
```

#### Network Scanning Considerations

For network scanning to work properly in Docker, you may need to use host networking:

**Option 1: Host Network (Recommended for full functionality)**
```bash
# Edit docker-compose.yml and uncomment:
# network_mode: host
# Comment out the networks section

docker compose up -d
```

**Option 2: Bridge Network (Default)**
- Uses bridge networking (included in docker-compose.yml)
- May have limited network discovery capabilities
- Suitable for basic functionality testing

#### Docker Management Commands

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# View logs
docker compose logs -f netscan

# Restart services
docker compose restart netscan

# Update to latest version
git pull origin main
docker compose build --no-cache
docker compose up -d

# Backup data
docker compose exec netscan cp /app/instance/netscan.db /app/instance/netscan.db.backup

# Clean up (removes data!)
docker compose down -v
```

#### Development with Docker

For development with auto-reload:

```bash
# Copy the development override file
cp docker-compose.override.yml.example docker-compose.override.yml

# Start in development mode
docker compose up
```

#### Docker Components

The Docker setup includes:

- **NetScan Application**: Main Flask application with network scanning
- **Redis**: Session storage and rate limiting backend
- **Persistent Volumes**: Database and upload storage
- **Health Checks**: Automatic container health monitoring

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
- `NETSCAN_DISABLE_STARTUP_SCAN`: Disable automatic scan on service startup (default: true)
- `NETSCAN_ENABLE_OS_DETECTION`: Enable OS detection (requires root/setcap, default: false)
- `REDIS_URL`: Redis connection for Flask-Limiter backend (optional, default: in-memory)

#### Rate Limiting Backend (Production Recommendation)

By default, Flask-Limiter uses an in-memory backend which may show warnings in production. For production deployments, especially with multiple workers, configure Redis:

```bash
# Install Redis (optional)
sudo apt -y install redis-server

# Configure Redis URL
export REDIS_URL=redis://localhost:6379/0
```

Add to your `.env` file:
```bash
REDIS_URL=redis://localhost:6379/0
```

**Note**: The in-memory backend works fine for single-instance deployments but Redis is recommended for production scalability.

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

# Optional: Redis backend for production rate limiting
REDIS_URL=redis://localhost:6379/0
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
# Navigate to installation directory
cd /opt/netscan  # for service installations
# cd netscan     # for development installations

# Pull latest changes
git pull --ff-only origin main

# Update dependencies
./venv/bin/pip install -r requirements.txt  # for service installations
# source venv/bin/activate && pip install -r requirements.txt  # for development

# Run database migrations
export FLASK_APP=app.py
./venv/bin/flask db upgrade  # for service installations
# flask db upgrade           # for development (with venv activated)

# Restart the service
sudo systemctl restart netscan  # for service installations
# (restart manually for development)
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

#### Prerequisites Issues

1. **"nmap program was not found in path"**: Install nmap
   ```bash
   sudo apt update
   sudo apt -y install nmap
   ```

2. **Python package compilation errors** (netifaces, psutil): Install build tools
   ```bash
   sudo apt -y install python3-dev build-essential
   ```

3. **PEP 668 / "externally-managed-environment" errors**: Use virtual environment
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Locale warnings**: Configure system locale
   ```bash
   sudo apt -y install locales
   sudo update-locale LANG=en_GB.UTF-8 LC_CTYPE=en_GB.UTF-8
   # Reboot or logout/login for changes to take effect
   ```

5. **Slow network scans**: Enable SYN scans without sudo
   ```bash
   sudo apt -y install libcap2-bin
   sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"
   ```

6. **Network timeout errors during pip install**: Try installing with timeout and retries
   ```bash
   pip install --timeout 300 --retries 3 -r requirements.txt
   ```

#### Flask-Limiter Warnings

If you see warnings about "in-memory" backend in production:

1. **Install Redis** (recommended for production):
   ```bash
   sudo apt -y install redis-server
   export REDIS_URL=redis://localhost:6379/0
   ```

2. **Ignore warning** (acceptable for single-instance deployments):
   - The in-memory backend works fine for most home/small office use cases

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

## Production Deployment

### First-Time Setup

When deploying NetScan for the first time:

1. **Initial Admin Setup**: After installation, visit `/first-login-password` to set the admin password
   - Default admin username: `admin` (configurable via `ADMIN_USERNAME` env var)  
   - Default admin password: `admin123` (configurable via `ADMIN_PASSWORD` env var)
   - **Important**: You must change the default password before first use

2. **Flask-Limiter Backend**: For production with multiple workers, configure Redis:
   ```bash
   # Install Redis
   sudo apt -y install redis-server
   
   # Set environment variable
   export REDIS_URL=redis://localhost:6379/0
   
   # Or add to .env file
   echo "REDIS_URL=redis://localhost:6379/0" >> .env
   ```
   
   **Note**: The default in-memory backend works fine for single-instance deployments.

3. **Enhanced nmap Performance** (optional): For faster scanning, enable SYN scans:
   ```bash
   # Install capabilities library
   sudo apt -y install libcap2-bin
   
   # Allow nmap to perform SYN scans without root
   sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"
   ```
   
   **Default behavior**: NetScan uses TCP connect scans (`-sT`) by default, which work without root privileges but are slower than SYN scans (`-sS`).

### Security Recommendations

- Change default admin credentials immediately after installation
- Use a strong `SECRET_KEY` in production (auto-generated by `install.sh`)
- Consider setting up HTTPS with a reverse proxy (nginx/apache)
- For multi-user environments, configure Redis for rate limiting backend

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

### System Requirements
- Python 3.6+
- nmap (system package)
- python3-venv (for PEP 668 compliance)
- Network access for scanning

### Optional Dependencies
- libcap2-bin (for SYN scans without sudo)
- locales (to prevent locale warnings)
- redis-server (for production rate limiting backend)

### Permissions
- Standard user privileges (no root required for basic operation)
- Optional: sudo access for installing setcap capabilities for faster scanning

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
