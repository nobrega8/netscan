from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import enum
import json

db = SQLAlchemy()

class UserRole(enum.Enum):
    ADMIN = "ADMIN"
    EDITOR = "EDITOR"
    VIEWER = "VIEWER"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    last_login_at = db.Column(db.DateTime)
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role):
        """Check if user has specific role"""
        if isinstance(role, str):
            role = UserRole(role.upper())  # Ensure role is uppercase
        return self.role == role
    
    def can_edit(self):
        """Check if user can edit/modify data"""
        return self.role in [UserRole.ADMIN, UserRole.EDITOR]
    
    def can_admin(self):
        """Check if user has admin privileges"""
        return self.role == UserRole.ADMIN
    
    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until:
            return datetime.utcnow() < self.locked_until
        return False
    
    def __repr__(self):
        return f'<User {self.username}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    brand = db.Column(db.String(100))
    model = db.Column(db.String(100))
    icon = db.Column(db.String(50), default='device')
    image_path = db.Column(db.String(255))  # Path to uploaded device image
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    open_ports = db.Column(db.Text)  # JSON string of open ports
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'))
    merged_devices = db.Column(db.Text)  # JSON string of merged MAC addresses
    
    # Additional device information
    os_info = db.Column(db.String(255))  # Operating system information
    vendor = db.Column(db.String(100))   # Hardware vendor
    device_type = db.Column(db.String(50))  # Device type (router, computer, etc.)
    os_family = db.Column(db.String(50))    # OS family (Windows, Linux, etc.)
    netbios_name = db.Column(db.String(100))  # NetBIOS name
    workgroup = db.Column(db.String(100))     # Windows workgroup
    services = db.Column(db.Text)  # JSON string of detected services
    category = db.Column(db.String(50))       # Device category (Phone, Computer, etc.)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        """Convert Device object to dictionary for JSON serialization"""
        
        try:
            # Parse JSON strings safely
            open_ports = []
            services = []
            merged_devices = []
            
            try:
                if self.open_ports:
                    open_ports = json.loads(self.open_ports)
            except (json.JSONDecodeError, TypeError):
                open_ports = []
                
            try:
                if self.services:
                    services = json.loads(self.services)
            except (json.JSONDecodeError, TypeError):
                services = []
                
            try:
                if self.merged_devices:
                    merged_devices = json.loads(self.merged_devices)
            except (json.JSONDecodeError, TypeError):
                merged_devices = []
            
            # Handle owner relationship - get the person data separately to avoid relationship issues
            owner = None
            if self.person_id:
                try:
                    # Get person by ID to avoid SQLAlchemy relationship loading issues
                    person = db.session.get(Person, self.person_id)
                    if person:
                        owner = {
                            'id': person.id,
                            'name': str(person.name) if person.name else '',
                            'email': str(person.email) if person.email else ''
                        }
                except Exception as e:
                    print(f"Error loading owner for device {self.id}: {e}")
                    # If there's any issue with loading the owner, just skip it
                    owner = None
            
            result = {
                'id': int(self.id) if self.id is not None else 0,
                'hostname': str(self.hostname) if self.hostname else '',
                'ip_address': str(self.ip_address) if self.ip_address else '',
                'mac_address': str(self.mac_address) if self.mac_address else '',
                'brand': str(self.brand) if self.brand else '',
                'model': str(self.model) if self.model else '',
                'icon': str(self.icon) if self.icon else 'device',
                'image_path': str(self.image_path) if self.image_path else '',
                'is_online': bool(self.is_online),
                'last_seen': self.last_seen.isoformat() if self.last_seen else None,
                'first_seen': self.first_seen.isoformat() if self.first_seen else None,
                'open_ports': open_ports,
                'person_id': int(self.person_id) if self.person_id is not None else None,
                'merged_devices': merged_devices,
                'os_info': str(self.os_info) if self.os_info else '',
                'vendor': str(self.vendor) if self.vendor else '',
                'device_type': str(self.device_type) if self.device_type else '',
                'os_family': str(self.os_family) if self.os_family else '',
                'netbios_name': str(self.netbios_name) if self.netbios_name else '',
                'workgroup': str(self.workgroup) if self.workgroup else '',
                'services': services,
                'category': str(self.category) if self.category else '',
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'updated_at': self.updated_at.isoformat() if self.updated_at else None,
                'owner': owner
            }
            
            # Verify the result can be JSON serialized
            try:
                json.dumps(result)
            except Exception as e:
                print(f"JSON serialization failed for device {self.id}: {e}")
                # Return a minimal safe version
                return {
                    'id': int(self.id) if self.id is not None else 0,
                    'hostname': str(self.hostname) if self.hostname else 'Unknown',
                    'ip_address': str(self.ip_address) if self.ip_address else '',
                    'mac_address': str(self.mac_address) if self.mac_address else '',
                    'is_online': bool(self.is_online),
                    'last_seen': self.last_seen.isoformat() if self.last_seen else None,
                    'first_seen': self.first_seen.isoformat() if self.first_seen else None,
                    'open_ports': [],
                    'person_id': None,
                    'merged_devices': [],
                    'owner': None
                }
            
            return result
            
        except Exception as e:
            print(f"Unexpected error in to_dict for device {self.id if hasattr(self, 'id') else 'unknown'}: {e}")
            import traceback
            traceback.print_exc()
            # Return absolute minimal data
            return {
                'id': 0,
                'hostname': 'Error',
                'ip_address': '',
                'mac_address': '',
                'is_online': False,
                'last_seen': None,
                'first_seen': None,
                'open_ports': [],
                'person_id': None,
                'merged_devices': [],
                'owner': None
            }

class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100))
    image_path = db.Column(db.String(255))  # Path to uploaded profile photo
    devices = db.relationship('Device', backref='owner', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    ip_address = db.Column(db.String(45))
    is_online = db.Column(db.Boolean, default=False)
    response_time = db.Column(db.Float)
    open_ports = db.Column(db.Text)  # JSON string
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class OUI(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prefix = db.Column(db.String(8), unique=True, nullable=False)  # First 6 chars of MAC
    manufacturer = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)