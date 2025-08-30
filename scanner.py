import nmap
import netifaces
import socket
import json
import subprocess
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
            
            # Also scan localhost for comprehensive information
            localhost_info = self.scan_localhost()
            if localhost_info and localhost_info not in devices_found:
                devices_found.append(localhost_info)
            
            # After scanning, mark devices not seen as offline
            self.mark_offline_devices()
            
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
    
    def scan_ports(self, ip, ports='22,23,25,53,80,110,143,443,993,995,21,139,445,3389,5900,8080,8443,3306,5432,1433,6379,27017'):
        """Scan common ports on a device (public method)"""
        try:
            # Try SYN scan first (requires root)
            try:
                self.nm.scan(ip, ports, arguments='-sS')
            except Exception:
                # Fallback to TCP connect scan (no root required)
                self.nm.scan(ip, ports, arguments='-sT')
                
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
            # Fallback to basic connectivity test
            return self._basic_port_check(ip, ports.split(','))
    
    def _basic_port_check(self, ip, port_list):
        """Basic port connectivity check using socket"""
        import socket
        open_ports = []
        
        for port_str in port_list:
            try:
                port = int(port_str.strip())
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                continue
                
        return open_ports

    def _scan_ports(self, ip, ports='22,23,25,53,80,110,143,443,993,995,21,139,445,3389,5900,8080,8443,3306,5432,1433,6379,27017', extended=False):
        """Legacy method for backward compatibility"""
        if extended:
            # Extended port list for localhost scanning
            extended_ports = '22,23,25,53,80,110,143,443,993,995,21,139,445,3389,5900,8080,8443,3306,5432,1433,6379,27017,5000,8000,9000,3000,5173,8081,8888,9090'
            return self.scan_ports(ip, extended_ports)
        return self.scan_ports(ip, ports)
    
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
                
                # Update additional fields if provided
                if 'os_info' in device_info:
                    device.os_info = device_info['os_info']
                if 'vendor' in device_info:
                    device.vendor = device_info['vendor']
                if 'device_type' in device_info:
                    device.device_type = device_info['device_type']
                if 'os_family' in device_info:
                    device.os_family = device_info['os_family']
                if 'services' in device_info:
                    device.services = device_info['services']
                if 'category' in device_info and not device.category:  # Only set if not already set
                    device.category = device_info['category']
            else:
                # Create new device
                device = Device(
                    ip_address=device_info['ip_address'],
                    hostname=device_info['hostname'],
                    mac_address=device_info['mac_address'],
                    is_online=True,
                    last_seen=device_info['timestamp'],
                    first_seen=device_info['timestamp'],
                    open_ports=json.dumps(device_info['open_ports']),
                    os_info=device_info.get('os_info'),
                    vendor=device_info.get('vendor'),
                    device_type=device_info.get('device_type'),
                    os_family=device_info.get('os_family'),
                    services=device_info.get('services'),
                    category=device_info.get('category')
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
    
    def get_device_details(self, ip):
        """Get comprehensive device information including OS detection"""
        try:
            device_info = {}
            
            # OS Detection using nmap
            try:
                self.nm.scan(ip, arguments='-O')
                if ip in self.nm.all_hosts():
                    host_info = self.nm[ip]
                    
                    # OS information
                    if 'osmatch' in host_info:
                        os_matches = host_info['osmatch']
                        if os_matches:
                            device_info['os_info'] = os_matches[0]['name']
                            device_info['os_accuracy'] = os_matches[0]['accuracy']
                    
                    # Vendor information
                    if 'vendor' in host_info:
                        vendors = list(host_info['vendor'].values())
                        if vendors:
                            device_info['vendor'] = vendors[0]
                    
                    # Device type
                    if 'osclass' in host_info:
                        osclass = host_info['osclass']
                        if osclass:
                            device_info['device_type'] = osclass[0].get('type', 'Unknown')
                            device_info['os_family'] = osclass[0].get('osfamily', 'Unknown')
            except Exception as e:
                print(f"OS detection failed for {ip}: {e}")
            
            # Try to get additional information through service detection
            try:
                # Service version detection
                self.nm.scan(ip, arguments='-sV')
                if ip in self.nm.all_hosts():
                    host_info = self.nm[ip]
                    services = {}
                    
                    for proto in host_info.all_protocols():
                        ports = host_info[proto].keys()
                        for port in ports:
                            port_info = host_info[proto][port]
                            if port_info['state'] == 'open':
                                service_name = port_info.get('name', 'unknown')
                                version = port_info.get('version', '')
                                product = port_info.get('product', '')
                                
                                services[port] = {
                                    'name': service_name,
                                    'product': product,
                                    'version': version
                                }
                    
                    device_info['services'] = services
            except Exception as e:
                print(f"Service detection failed for {ip}: {e}")
            
            # Try to get NetBIOS information (Windows)
            try:
                result = subprocess.run(['nmblookup', '-A', ip], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '<00>' in line and 'UNIQUE' in line:
                            device_info['netbios_name'] = line.split()[0].strip()
                        elif '<20>' in line and 'UNIQUE' in line:
                            device_info['workgroup'] = line.split()[0].strip()
            except Exception as e:
                print(f"NetBIOS lookup failed for {ip}: {e}")
            
            return device_info
            
        except Exception as e:
            print(f"Error getting device details for {ip}: {e}")
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
            # Record offline scan
            scan = Scan(
                device_id=device.id,
                ip_address=device.ip_address,
                is_online=False,
                timestamp=datetime.utcnow()
            )
            db.session.add(scan)
        
        db.session.commit()
    
    def scan_localhost(self):
        """Scan the localhost to gather information about the system itself"""
        import platform
        try:
            import psutil
            PSUTIL_AVAILABLE = True
        except ImportError:
            PSUTIL_AVAILABLE = False
        import socket
        import uuid
        import subprocess
        import os
        
        try:
            # Get local IP address
            local_ip = socket.gethostbyname(socket.gethostname())
            
            # Alternative method if above doesn't work
            if local_ip.startswith('127.'):
                # Connect to external host to get actual local IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect(('8.8.8.8', 80))
                    local_ip = s.getsockname()[0]
                except:
                    pass
                finally:
                    s.close()
            
            # Get MAC address of primary network interface
            mac_address = None
            try:
                # Get MAC address
                mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])
                mac_address = mac.lower()
            except:
                pass
            
            # Get hostname
            hostname = socket.gethostname()
            
            # Get OS information
            os_info = f"{platform.system()} {platform.release()}"
            
            # Get detailed system info
            try:
                if platform.system().lower() == 'linux':
                    # Try to get distribution info
                    result = subprocess.run(['lsb_release', '-ds'], capture_output=True, text=True)
                    if result.returncode == 0:
                        os_info = result.stdout.strip()
            except:
                pass
            
            # Scan open ports on localhost
            open_ports = self._scan_ports(local_ip, extended=True)
            
            # Get system services information
            services = []
            for port in open_ports[:10]:  # Limit to first 10 ports
                service_info = self._get_service_info(local_ip, port)
                if service_info:
                    services.append(service_info)
            
            # Get vendor information (simplified)
            vendor = "Unknown"
            device_type = "Server"
            
            # Try to determine if it's a known system type
            if 'raspberry' in hostname.lower() or 'pi' in hostname.lower():
                vendor = "Raspberry Pi Foundation"
                device_type = "Computer"
            elif platform.system().lower() == 'linux':
                device_type = "Computer"
            elif platform.system().lower() == 'windows':
                device_type = "Computer"
            elif platform.system().lower() == 'darwin':
                vendor = "Apple"
                device_type = "Computer"
            
            # Create or update localhost device
            device_info = {
                'ip_address': local_ip,
                'hostname': hostname,
                'mac_address': mac_address,
                'open_ports': open_ports,
                'is_online': True,
                'os_info': os_info,
                'vendor': vendor,
                'device_type': device_type,
                'os_family': platform.system(),
                'services': json.dumps(services) if services else None,
                'category': 'Server',  # Default category for localhost
                'timestamp': datetime.utcnow()
            }
            
            # Update device in database
            if mac_address:
                self._update_device(device_info)
                return device_info
            
        except Exception as e:
            print(f"Error scanning localhost: {e}")
            
        return None
        print(f"Marked {len(devices)} devices as offline")