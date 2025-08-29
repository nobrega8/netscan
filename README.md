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

# Run the application
python3 app.py
```

Access the web interface at: http://localhost:5000

### Raspberry Pi Service Installation

```bash
# Install as system service
sudo ./install.sh

# Start the service
sudo systemctl start netscan

# Enable auto-start on boot
sudo systemctl enable netscan

# Check status
sudo systemctl status netscan
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

- `GET /api/devices` - JSON list of all devices
- `POST /scan` - Trigger manual network scan
- `POST /merge_devices` - Merge multiple devices

## Requirements

- Python 3.6+
- nmap (system package)
- Network access for scanning
- Root/sudo access for some network operations

## Database Schema

- **devices**: Core device information and status
- **people**: User/owner information  
- **scans**: Historical scan results and timeline data
- **ouis**: MAC address manufacturer lookup table

## License

MIT License