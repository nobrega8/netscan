"""
Enhanced task system for NetScan
Provides asynchronous scanning capabilities
"""

import threading
import time
import json
from datetime import datetime, timedelta, UTC
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Callable, Dict, Any
import uuid

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class Task:
    id: str
    name: str
    status: TaskStatus
    progress: int = 0
    message: str = ""
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: datetime = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(UTC)

class TaskManager:
    """Simple task manager for background operations"""
    
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.workers: Dict[str, threading.Thread] = {}
        self.max_workers = 3
        self.active_workers = 0
        self.lock = threading.Lock()
        
        # Event listeners for real-time updates
        self.progress_callbacks: Dict[str, Callable] = {}
    
    def create_task(self, name: str, func: Callable, *args, **kwargs) -> str:
        """Create a new task"""
        task_id = str(uuid.uuid4())
        
        task = Task(
            id=task_id,
            name=name,
            status=TaskStatus.PENDING
        )
        
        with self.lock:
            self.tasks[task_id] = task
        
        # Create worker thread
        worker = threading.Thread(
            target=self._run_task,
            args=(task_id, func, args, kwargs),
            daemon=True
        )
        
        with self.lock:
            self.workers[task_id] = worker
        
        # Start worker if we have capacity
        self._try_start_worker(task_id)
        
        return task_id
    
    def _try_start_worker(self, task_id: str):
        """Try to start a worker if we have capacity"""
        with self.lock:
            if self.active_workers < self.max_workers:
                worker = self.workers.get(task_id)
                if worker and not worker.is_alive():
                    worker.start()
                    self.active_workers += 1
    
    def _run_task(self, task_id: str, func: Callable, args: tuple, kwargs: dict):
        """Execute a task"""
        try:
            with self.lock:
                task = self.tasks[task_id]
                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now(UTC)
                task.message = "Starting task..."
            
            self._notify_progress(task_id, 0, "Starting task...")
            
            # Add progress callback to kwargs if the function supports it
            if 'progress_callback' in func.__code__.co_varnames:
                kwargs['progress_callback'] = lambda progress, message: self._update_progress(task_id, progress, message)
            
            # Execute the task
            result = func(*args, **kwargs)
            
            with self.lock:
                task = self.tasks[task_id]
                task.status = TaskStatus.COMPLETED
                task.progress = 100
                task.message = "Task completed successfully"
                task.result = result
                task.completed_at = datetime.now(UTC)
            
            self._notify_progress(task_id, 100, "Task completed successfully")
            
        except Exception as e:
            with self.lock:
                task = self.tasks[task_id]
                task.status = TaskStatus.FAILED
                task.error = str(e)
                task.message = f"Task failed: {str(e)}"
                task.completed_at = datetime.now(UTC)
            
            self._notify_progress(task_id, task.progress, f"Task failed: {str(e)}")
        
        finally:
            with self.lock:
                self.active_workers -= 1
                if task_id in self.workers:
                    del self.workers[task_id]
            
            # Try to start next pending task
            self._start_next_pending_task()
    
    def _start_next_pending_task(self):
        """Start the next pending task if we have capacity"""
        with self.lock:
            if self.active_workers >= self.max_workers:
                return
            
            # Find next pending task
            for task_id, task in self.tasks.items():
                if task.status == TaskStatus.PENDING and task_id in self.workers:
                    self._try_start_worker(task_id)
                    break
    
    def _update_progress(self, task_id: str, progress: int, message: str):
        """Update task progress"""
        with self.lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.progress = progress
                task.message = message
        
        self._notify_progress(task_id, progress, message)
    
    def _notify_progress(self, task_id: str, progress: int, message: str):
        """Notify progress callbacks"""
        callback = self.progress_callbacks.get(task_id)
        if callback:
            try:
                callback(task_id, progress, message)
            except Exception as e:
                print(f"Error in progress callback: {e}")
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        return self.tasks.get(task_id)
    
    def get_all_tasks(self) -> Dict[str, Task]:
        """Get all tasks"""
        return self.tasks.copy()
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a task"""
        with self.lock:
            task = self.tasks.get(task_id)
            if task and task.status in [TaskStatus.PENDING, TaskStatus.RUNNING]:
                task.status = TaskStatus.CANCELLED
                task.message = "Task cancelled"
                task.completed_at = datetime.now(UTC)
                
                # Remove worker if it hasn't started
                if task_id in self.workers:
                    worker = self.workers[task_id]
                    if not worker.is_alive():
                        del self.workers[task_id]
                
                return True
        
        return False
    
    def cleanup_completed_tasks(self, max_age_hours: int = 24):
        """Clean up old completed tasks"""
        cutoff_time = datetime.now(UTC) - timedelta(hours=max_age_hours)
        
        with self.lock:
            to_remove = []
            for task_id, task in self.tasks.items():
                if (task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED] 
                    and task.completed_at and task.completed_at < cutoff_time):
                    to_remove.append(task_id)
            
            for task_id in to_remove:
                del self.tasks[task_id]
                if task_id in self.progress_callbacks:
                    del self.progress_callbacks[task_id]
    
    def set_progress_callback(self, task_id: str, callback: Callable):
        """Set a progress callback for a task"""
        self.progress_callbacks[task_id] = callback
    
    def get_task_summary(self) -> Dict[str, int]:
        """Get summary of task statuses"""
        summary = {status.value: 0 for status in TaskStatus}
        
        with self.lock:
            for task in self.tasks.values():
                summary[task.status.value] += 1
        
        return summary

# Global task manager instance
task_manager = TaskManager()

# Scanning tasks
class ScanTasks:
    """Collection of scanning tasks"""
    
    @staticmethod
    def network_scan(network_range=None, progress_callback=None):
        """Enhanced network scan task"""
        from scanner import EnhancedNetworkScanner
        
        # Get app instance from the module where it's defined
        import app as app_module
        
        # Run within Flask application context
        with app_module.app.app_context():
            scanner = EnhancedNetworkScanner()
            return scanner.enhanced_scan_network(network_range, progress_callback)
    
    @staticmethod
    def device_port_scan(device_id, progress_callback=None):
        """Port scan for specific device"""
        from models import Device, db
        from scanner import EnhancedNetworkScanner
        
        # Get app instance from the module where it's defined
        import app as app_module
        
        # Run within Flask application context
        with app_module.app.app_context():
            device = db.session.get(Device, device_id)
            if not device or not device.ip_address:
                raise ValueError("Device not found or has no IP address")
            
            scanner = EnhancedNetworkScanner()
            
            if progress_callback:
                progress_callback(25, f"Scanning ports for {device.hostname or device.ip_address}")
            
            # Enhanced port scan
            enhanced_info = scanner._detect_services_and_os(device.ip_address)
            
            if progress_callback:
                progress_callback(75, "Updating device information...")
            
            # Update device
            device.open_ports = json.dumps(enhanced_info.get('open_ports', []))
            device.services = json.dumps(enhanced_info.get('services', []))
            device.os_info = enhanced_info.get('os_info') or device.os_info
            device.device_type = enhanced_info.get('device_type') or device.device_type
            device.last_seen = datetime.now(UTC)
            
            db.session.commit()
            
            if progress_callback:
                progress_callback(100, "Port scan completed")
            
            return {
                'device_id': device_id,
                'open_ports': enhanced_info.get('open_ports', []),
                'services': enhanced_info.get('services', [])
            }
    
    @staticmethod
    def oui_database_update(progress_callback=None):
        """Update OUI database from IEEE"""
        import requests
        from models import OUI, db
        
        try:
            if progress_callback:
                progress_callback(10, "Downloading OUI database...")
            
            # Download OUI database
            url = "https://standards-oui.ieee.org/oui/oui.txt"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            if progress_callback:
                progress_callback(50, "Parsing OUI data...")
            
            # Parse OUI data
            oui_data = []
            lines = response.text.split('\n')
            
            for i, line in enumerate(lines):
                if '(hex)' in line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        oui_prefix = parts[0].strip().replace('-', '').upper()
                        manufacturer = parts[2].strip()
                        
                        oui_data.append({
                            'prefix': oui_prefix,
                            'manufacturer': manufacturer
                        })
                
                # Update progress every 1000 lines
                if i % 1000 == 0 and progress_callback:
                    progress = 50 + (i / len(lines)) * 40
                    progress_callback(int(progress), f"Processing OUI data... ({i}/{len(lines)})")
            
            if progress_callback:
                progress_callback(90, "Updating database...")
            
            # Update database
            # Clear existing OUI data
            OUI.query.delete()
            
            # Insert new data in batches
            batch_size = 1000
            for i in range(0, len(oui_data), batch_size):
                batch = oui_data[i:i + batch_size]
                for oui_info in batch:
                    oui = OUI(
                        prefix=oui_info['prefix'],
                        manufacturer=oui_info['manufacturer']
                    )
                    db.session.add(oui)
                
                db.session.commit()
                
                if progress_callback:
                    progress = 90 + ((i + batch_size) / len(oui_data)) * 10
                    progress_callback(int(progress), f"Inserting OUI data... ({i + batch_size}/{len(oui_data)})")
            
            if progress_callback:
                progress_callback(100, f"OUI database updated with {len(oui_data)} entries")
            
            return {'updated_count': len(oui_data)}
            
        except Exception as e:
            raise Exception(f"Failed to update OUI database: {str(e)}")

# Convenience functions
def start_network_scan(network_range=None) -> str:
    """Start an asynchronous network scan"""
    return task_manager.create_task(
        "Network Scan",
        ScanTasks.network_scan,
        network_range
    )

def start_device_port_scan(device_id: int) -> str:
    """Start an asynchronous device port scan"""
    return task_manager.create_task(
        f"Port Scan (Device {device_id})",
        ScanTasks.device_port_scan,
        device_id
    )

def start_oui_update() -> str:
    """Start an asynchronous OUI database update"""
    return task_manager.create_task(
        "OUI Database Update",
        ScanTasks.oui_database_update
    )

def get_scan_progress(task_id: str) -> Optional[Dict]:
    """Get scan progress"""
    task = task_manager.get_task(task_id)
    if task:
        return {
            'id': task.id,
            'name': task.name,
            'status': task.status.value,
            'progress': task.progress,
            'message': task.message,
            'result': task.result,
            'error': task.error
        }
    return None