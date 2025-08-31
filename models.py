from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import enum

db = SQLAlchemy()

class UserRole(enum.Enum):
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"

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
            role = UserRole(role)
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