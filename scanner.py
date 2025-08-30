import nmap
import netifaces
import socket
import json
from datetime import datetime
from models import Device, Scan, OUI, db
import re
import threading
import time

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        
    def get_network_range(self):
        """Auto-detect network range or use configured range"""
        try:
            # Get default gateway interface
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            interface = default_gateway[1]
            
            # Get network info for this interface
            addrs = netifaces.ifaddresses(interface)
            ipv4_info = addrs[netifaces.AF_INET][0]
            
            ip = ipv4_info['addr']
            netmask = ipv4_info['netmask']
            
            # Calculate network range
            network = self._calculate_network(ip, netmask)
            return network
        except:
            # Fallback to common ranges
            return '192.168.1.0/24'
    
    def _calculate_network(self, ip, netmask):
        """Calculate network range from IP and netmask"""
        import ipaddress
        interface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
        return str(interface.network)
    
    def scan_network(self, network_range=None):
        """Scan the network for devices"""
        if not network_range:
            network_range = self.get_network_range()
        
        print(f"Scanning network: {network_range}")
        
        try:
            # Ping scan to find live hosts
            self.nm.scan(hosts=network_range, arguments='-sn')
            
            devices_found = []
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    device_info = self._get_device_info(host)
                    if device_info:
                        devices_found.append(device_info)
                        self._update_device(device_info)
            
            return devices_found
            
        except Exception as e:
            print(f"Error scanning network: {e}")
            return []
    
    def _get_device_info(self, ip):
        """Get detailed information about a device"""
        try:
            # Get hostname
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            # Get MAC address using ARP
            mac_address = self._get_mac_address(ip)
            if not mac_address:
                return None
            
            # Get open ports (quick scan of common ports)
            open_ports = self._scan_ports(ip)
            
            return {
                'ip_address': ip,
                'hostname': hostname,
                'mac_address': mac_address,
                'open_ports': open_ports,
                'is_online': True,
                'timestamp': datetime.utcnow()
            }
            
        except Exception as e:
            print(f"Error getting device info for {ip}: {e}")
            return None
    
    def _get_mac_address(self, ip):
        """Get MAC address for an IP using ARP table"""
        try:
            import subprocess
            import platform
            
            if platform.system().lower() == 'linux':
                # Use ARP command
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                                    return part.lower().replace('-', ':')
            
            # Fallback: trigger ARP entry and try again
            subprocess.run(['ping', '-c', '1', ip], capture_output=True)
            time.sleep(0.1)
            
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                                return part.lower().replace('-', ':')
                                
        except Exception as e:
            print(f"Error getting MAC for {ip}: {e}")
        
        return None
    
    def _scan_ports(self, ip, ports='22,23,25,53,80,110,443,993,995'):
        """Scan common ports on a device"""
        try:
            self.nm.scan(ip, ports, arguments='-sS')
            open_ports = []
            
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    ports_info = self.nm[ip][proto].keys()
                    for port in ports_info:
                        if self.nm[ip][proto][port]['state'] == 'open':
                            open_ports.append(port)
            
            return open_ports
            
        except Exception as e:
            print(f"Error scanning ports for {ip}: {e}")
            return []
    
    def _update_device(self, device_info):
        """Update or create device in database"""
        try:
            device = Device.query.filter_by(mac_address=device_info['mac_address']).first()
            
            if device:
                # Update existing device
                device.ip_address = device_info['ip_address']
                device.hostname = device_info['hostname']
                device.is_online = True
                device.last_seen = device_info['timestamp']
                device.open_ports = json.dumps(device_info['open_ports'])
            else:
                # Create new device
                device = Device(
                    ip_address=device_info['ip_address'],
                    hostname=device_info['hostname'],
                    mac_address=device_info['mac_address'],
                    is_online=True,
                    last_seen=device_info['timestamp'],
                    first_seen=device_info['timestamp'],
                    open_ports=json.dumps(device_info['open_ports'])
                )
                db.session.add(device)
            
            # Record scan
            scan = Scan(
                device_id=device.id if device.id else None,
                ip_address=device_info['ip_address'],
                is_online=True,
                open_ports=json.dumps(device_info['open_ports']),
                timestamp=device_info['timestamp']
            )
            
            if device.id:  # Only add scan if device exists
                db.session.add(scan)
            
            db.session.commit()
            
            # Update OUI information
            self._update_oui(device_info['mac_address'])
            
        except Exception as e:
            print(f"Error updating device: {e}")
            db.session.rollback()
    
    def _update_oui(self, mac_address):
        """Update OUI information for a MAC address"""
        try:
            oui_prefix = mac_address.replace(':', '').upper()[:6]
            
            # Check if we already have this OUI
            oui = OUI.query.filter_by(prefix=oui_prefix).first()
            if not oui:
                # Try to get manufacturer info (this would be enhanced with actual OUI lookup)
                manufacturer = self._lookup_oui(oui_prefix)
                if manufacturer:
                    oui = OUI(prefix=oui_prefix, manufacturer=manufacturer)
                    db.session.add(oui)
                    db.session.commit()
                    
        except Exception as e:
            print(f"Error updating OUI: {e}")
    
    def _lookup_oui(self, oui_prefix):
        """Lookup manufacturer from OUI prefix (simplified)"""
        # This is a simplified version - in a real implementation,
        # you'd download and parse the IEEE OUI database
        common_ouis = {
            '001122': 'Cisco Systems',
            '000C29': 'VMware',
            '001A2B': 'Apple',
            '000039': 'Toshiba',
            '00E04C': 'Realtek',
            '001B44': 'NETGEAR'
        }
        return common_ouis.get(oui_prefix)
    
    def mark_offline_devices(self):
        """Mark devices as offline if not seen in recent scan"""
        from datetime import timedelta
        
        cutoff_time = datetime.utcnow() - timedelta(minutes=60)  # 1 hour timeout
        
        devices = Device.query.filter(
            Device.last_seen < cutoff_time,
            Device.is_online == True
        ).all()
        
        for device in devices:
            device.is_online = False
        
        db.session.commit()