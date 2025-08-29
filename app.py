from flask import Flask, render_template, request, jsonify, redirect, url_for
from models import db, Device, Person, Scan, OUI
from scanner import NetworkScanner
from config import Config
import json
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
scanner = NetworkScanner()

# Template filter for JSON parsing
@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        try:
            return json.loads(value)
        except:
            return []
    return []

# Create tables on startup
with app.app_context():
    db.create_all()

@app.route('/')
def dashboard():
    devices = Device.query.all()
    online_devices = Device.query.filter_by(is_online=True).count()
    total_devices = Device.query.count()
    people = Person.query.count()
    
    return render_template('dashboard.html', 
                         devices=devices,
                         online_devices=online_devices,
                         total_devices=total_devices,
                         people=people)

@app.route('/devices')
def devices():
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template('devices.html', devices=devices)

@app.route('/device/<int:device_id>')
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    scans = Scan.query.filter_by(device_id=device_id).order_by(Scan.timestamp.desc()).limit(50).all()
    return render_template('device_detail.html', device=device, scans=scans)

@app.route('/device/<int:device_id>/edit', methods=['GET', 'POST'])
def edit_device(device_id):
    device = Device.query.get_or_404(device_id)
    
    if request.method == 'POST':
        device.hostname = request.form.get('hostname')
        device.brand = request.form.get('brand')
        device.model = request.form.get('model')
        device.icon = request.form.get('icon', 'device')
        
        person_id = request.form.get('person_id')
        if person_id:
            device.person_id = int(person_id)
        else:
            device.person_id = None
            
        db.session.commit()
        return redirect(url_for('device_detail', device_id=device.id))
    
    people = Person.query.all()
    return render_template('edit_device.html', device=device, people=people)

@app.route('/people')
def people():
    people = Person.query.all()
    return render_template('people.html', people=people)

@app.route('/netspeed')
def netspeed():
    return render_template('netspeed.html')

@app.route('/person/<int:person_id>')
def person_detail(person_id):
    person = Person.query.get_or_404(person_id)
    devices = Device.query.filter_by(person_id=person_id).all()
    
    # Get timeline data
    timeline = []
    for device in devices:
        recent_scans = Scan.query.filter_by(device_id=device.id).order_by(Scan.timestamp.desc()).limit(100).all()
        for scan in recent_scans:
            timeline.append({
                'device': device,
                'scan': scan,
                'timestamp': scan.timestamp
            })
    
    timeline.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('person_detail.html', person=person, devices=devices, timeline=timeline)

@app.route('/person/new', methods=['GET', 'POST'])
def new_person():
    if request.method == 'POST':
        person = Person(
            name=request.form.get('name'),
            email=request.form.get('email')
        )
        db.session.add(person)
        db.session.commit()
        return redirect(url_for('people'))
    
    return render_template('new_person.html')

@app.route('/scan', methods=['POST'])
def manual_scan():
    try:
        devices = scanner.scan_network()
        scanner.mark_offline_devices()
        return jsonify({'success': True, 'devices_found': len(devices)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/devices')
def api_devices():
    devices = Device.query.all()
    return jsonify([{
        'id': d.id,
        'hostname': d.hostname,
        'ip_address': d.ip_address,
        'mac_address': d.mac_address,
        'brand': d.brand,
        'model': d.model,
        'is_online': d.is_online,
        'last_seen': d.last_seen.isoformat() if d.last_seen else None,
        'owner': d.owner.name if d.owner else None
    } for d in devices])

@app.route('/merge_devices', methods=['POST'])
def merge_devices():
    """Merge multiple devices (MAC addresses) into one"""
    data = request.get_json()
    primary_device_id = data.get('primary_device_id')
    device_ids_to_merge = data.get('device_ids', [])
    
    try:
        primary_device = Device.query.get(primary_device_id)
        if not primary_device:
            return jsonify({'success': False, 'error': 'Primary device not found'})
        
        merged_macs = json.loads(primary_device.merged_devices or '[]')
        
        for device_id in device_ids_to_merge:
            device_to_merge = Device.query.get(device_id)
            if device_to_merge and device_to_merge.id != primary_device.id:
                # Add MAC to merged list
                merged_macs.append(device_to_merge.mac_address)
                
                # Transfer scans to primary device
                scans = Scan.query.filter_by(device_id=device_to_merge.id).all()
                for scan in scans:
                    scan.device_id = primary_device.id
                
                # Delete the merged device
                db.session.delete(device_to_merge)
        
        primary_device.merged_devices = json.dumps(merged_macs)
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=2530)