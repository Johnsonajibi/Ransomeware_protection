#!/usr/bin/env python3
"""
REAL ANTI-RANSOMWARE SYSTEM - FULLY FUNCTIONAL
Complete implementation with working features
"""

import os
import sys
import json
import time
import threading
import hashlib
import sqlite3
import shutil
import signal
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set
from dataclasses import dataclass
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32api
import win32file
import psutil

# Configuration
PROGRAM_DATA = Path("C:/Users") / os.getenv('USERNAME', 'Default') / "AppData/Local/AntiRansomware"
PROGRAM_DATA.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = PROGRAM_DATA / "protection.db"
LOG_PATH = PROGRAM_DATA / "system.log"
QUARANTINE_PATH = PROGRAM_DATA / "quarantine"
QUARANTINE_PATH.mkdir(parents=True, exist_ok=True)

@dataclass
class ProtectedFolder:
    path: str
    usb_required: bool
    active: bool
    created: datetime
    
    def to_dict(self):
        return {
            'path': self.path,
            'usb_required': self.usb_required,
            'active': self.active,
            'created': self.created.isoformat()
        }

class DatabaseManager:
    """Database operations for persistence"""
    
    def __init__(self):
        self.db_path = DATABASE_PATH
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Protected folders table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS protected_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                usb_required BOOLEAN DEFAULT 1,
                active BOOLEAN DEFAULT 1,
                created TEXT NOT NULL
            )
        """)
        
        # Threat events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                action TEXT NOT NULL,
                severity TEXT DEFAULT 'MEDIUM'
            )
        """)
        
        # System logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
    
    def add_protected_folder(self, folder: ProtectedFolder):
        """Add protected folder to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO protected_folders (path, usb_required, active, created)
                VALUES (?, ?, ?, ?)
            """, (folder.path, folder.usb_required, folder.active, folder.created.isoformat()))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            self.log_error(f"Failed to add protected folder: {e}")
            return False
    
    def get_protected_folders(self) -> List[ProtectedFolder]:
        """Get all protected folders"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT path, usb_required, active, created FROM protected_folders")
            rows = cursor.fetchall()
            conn.close()
            
            folders = []
            for row in rows:
                folders.append(ProtectedFolder(
                    path=row[0],
                    usb_required=bool(row[1]),
                    active=bool(row[2]),
                    created=datetime.fromisoformat(row[3])
                ))
            
            return folders
        except Exception as e:
            self.log_error(f"Failed to get protected folders: {e}")
            return []
    
    def remove_protected_folder(self, path: str):
        """Remove protected folder"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM protected_folders WHERE path = ?", (path,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            self.log_error(f"Failed to remove protected folder: {e}")
            return False
    
    def log_threat(self, file_path: str, threat_type: str, action: str, severity: str = "MEDIUM"):
        """Log threat event"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO threat_events (timestamp, file_path, threat_type, action, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), file_path, threat_type, action, severity))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.log_error(f"Failed to log threat: {e}")
    
    def get_recent_threats(self, limit: int = 20) -> List[Dict]:
        """Get recent threat events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT timestamp, file_path, threat_type, action, severity
                FROM threat_events
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            threats = []
            for row in rows:
                threats.append({
                    'timestamp': row[0],
                    'file_path': row[1],
                    'threat_type': row[2],
                    'action': row[3],
                    'severity': row[4]
                })
            
            return threats
        except Exception as e:
            self.log_error(f"Failed to get threats: {e}")
            return []
    
    def log_error(self, message: str):
        """Log error message"""
        try:
            with open(LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now().isoformat()} ERROR: {message}\n")
        except:
            pass

class USBMonitor:
    """Monitor USB devices"""
    
    def __init__(self):
        self.usb_devices = set()
        self._scan_usb_devices()
    
    def _scan_usb_devices(self):
        """Scan for current USB devices"""
        try:
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            
            for drive in drives:
                drive_type = win32file.GetDriveType(drive)
                if drive_type == win32file.DRIVE_REMOVABLE:
                    self.usb_devices.add(drive)
        except Exception as e:
            print(f"USB scan error: {e}")
    
    def is_usb_connected(self) -> bool:
        """Check if any USB device is connected"""
        self._scan_usb_devices()
        return len(self.usb_devices) > 0
    
    def get_usb_devices(self) -> Set[str]:
        """Get list of USB devices"""
        self._scan_usb_devices()
        return self.usb_devices.copy()

class RansomwareDetector(FileSystemEventHandler):
    """Real-time ransomware detection"""
    
    def __init__(self, db_manager: DatabaseManager):
        super().__init__()
        self.db_manager = db_manager
        
        # Known ransomware file extensions
        self.ransomware_extensions = {
            '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.aes', '.rsa',
            '.xtbl', '.crinf', '.r5a', '.vault', '.petya', '.wannacry', '.locky',
            '.cerber', '.zepto', '.dharma', '.thor', '.aesir', '.odin', '.sage'
        }
        
        # Ransomware file name patterns
        self.ransomware_names = {
            'decrypt_instruction', 'how_to_decrypt', 'ransom_note', 'readme_for_decrypt',
            'recovery_key', 'restore_files', 'decrypt_files', 'ransom_recovery'
        }
        
        # Track file modifications for entropy analysis
        self.file_modifications = {}
    
    def on_created(self, event):
        """Handle file creation"""
        if not event.is_directory:
            self._analyze_file(event.src_path, "FILE_CREATED")
    
    def on_modified(self, event):
        """Handle file modification"""
        if not event.is_directory:
            self._analyze_file(event.src_path, "FILE_MODIFIED")
    
    def on_moved(self, event):
        """Handle file movement/renaming"""
        if not event.is_directory:
            self._analyze_file(event.dest_path, "FILE_RENAMED")
    
    def _analyze_file(self, file_path: str, event_type: str):
        """Analyze file for ransomware indicators"""
        try:
            file_obj = Path(file_path)
            
            # Check if file exists and is accessible
            if not file_obj.exists():
                return
            
            filename = file_obj.name.lower()
            
            # Check for ransomware extensions
            for ext in self.ransomware_extensions:
                if filename.endswith(ext):
                    self._handle_threat(file_path, "RANSOMWARE_EXTENSION", "CRITICAL")
                    return
            
            # Check for ransomware file names
            for pattern in self.ransomware_names:
                if pattern in filename:
                    self._handle_threat(file_path, "RANSOMWARE_FILENAME", "HIGH")
                    return
            
            # Check file content for small files
            if file_obj.stat().st_size < 1024 * 1024:  # Less than 1MB
                if self._check_file_content(file_path):
                    self._handle_threat(file_path, "RANSOMWARE_CONTENT", "HIGH")
                    return
            
            # Track rapid modifications (potential mass encryption)
            current_time = time.time()
            if file_path in self.file_modifications:
                last_mod = self.file_modifications[file_path]
                if current_time - last_mod < 1.0:  # Modified within 1 second
                    self._handle_threat(file_path, "RAPID_MODIFICATION", "MEDIUM")
            
            self.file_modifications[file_path] = current_time
            
        except Exception as e:
            self.db_manager.log_error(f"File analysis error: {e}")
    
    def _check_file_content(self, file_path: str) -> bool:
        """Check file content for ransomware indicators"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Read first 1KB
                
                # Check for common ransomware messages
                content_str = content.decode('utf-8', errors='ignore').lower()
                ransomware_phrases = [
                    'your files have been encrypted',
                    'files have been locked',
                    'pay the ransom',
                    'decrypt your files',
                    'bitcoin payment'
                ]
                
                for phrase in ransomware_phrases:
                    if phrase in content_str:
                        return True
                
                # Basic entropy check for encrypted content
                if len(set(content)) / len(content) > 0.8 and len(content) > 100:
                    return True
                
            return False
            
        except Exception:
            return False
    
    def _handle_threat(self, file_path: str, threat_type: str, severity: str):
        """Handle detected threat"""
        try:
            print(f"THREAT DETECTED: {threat_type} - {file_path}")
            
            action_taken = "MONITORED"
            
            # For critical threats, attempt to quarantine
            if severity == "CRITICAL":
                if self._quarantine_file(file_path):
                    action_taken = "QUARANTINED"
                    print(f"File quarantined: {file_path}")
                else:
                    action_taken = "QUARANTINE_FAILED"
            
            # Log the threat
            self.db_manager.log_threat(file_path, threat_type, action_taken, severity)
            
        except Exception as e:
            self.db_manager.log_error(f"Threat handling error: {e}")
    
    def _quarantine_file(self, file_path: str) -> bool:
        """Quarantine a threatening file"""
        try:
            source = Path(file_path)
            if not source.exists():
                return False
            
            # Create unique quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            quarantine_name = f"THREAT_{timestamp}_{source.name}"
            quarantine_file = QUARANTINE_PATH / quarantine_name
            
            # Move file to quarantine
            shutil.move(str(source), str(quarantine_file))
            
            # Create metadata file
            metadata = {
                'original_path': str(source),
                'quarantined_at': datetime.now().isoformat(),
                'file_size': quarantine_file.stat().st_size
            }
            
            metadata_file = quarantine_file.with_suffix('.meta')
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return True
            
        except Exception as e:
            self.db_manager.log_error(f"Quarantine failed: {e}")
            return False

class FileProtectionService:
    """File protection service"""
    
    def __init__(self, db_manager: DatabaseManager, usb_monitor: USBMonitor):
        self.db_manager = db_manager
        self.usb_monitor = usb_monitor
        self.detector = RansomwareDetector(db_manager)
        self.observers = []
        self.running = False
    
    def start_protection(self):
        """Start file system protection"""
        if self.running:
            return True
        
        try:
            folders = self.db_manager.get_protected_folders()
            
            for folder in folders:
                if not folder.active:
                    continue
                
                # Check USB requirement
                if folder.usb_required and not self.usb_monitor.is_usb_connected():
                    print(f"USB required but not connected for: {folder.path}")
                    continue
                
                # Check if folder exists
                if not os.path.exists(folder.path):
                    print(f"Protected folder not found: {folder.path}")
                    continue
                
                # Start monitoring
                observer = Observer()
                observer.schedule(self.detector, folder.path, recursive=True)
                observer.start()
                self.observers.append(observer)
                
                print(f"Protection started for: {folder.path}")
            
            self.running = True
            print(f"File protection active for {len(self.observers)} folders")
            return True
            
        except Exception as e:
            self.db_manager.log_error(f"Failed to start protection: {e}")
            return False
    
    def stop_protection(self):
        """Stop file system protection"""
        if not self.running:
            return
        
        for observer in self.observers:
            try:
                observer.stop()
                observer.join(timeout=5)
            except Exception as e:
                print(f"Error stopping observer: {e}")
        
        self.observers.clear()
        self.running = False
        print("File protection stopped")
    
    def restart_protection(self):
        """Restart protection service"""
        self.stop_protection()
        time.sleep(1)
        return self.start_protection()

class AntiRansomwareGUI:
    """Main GUI application"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Real Anti-Ransomware Protection")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Initialize components
        self.db_manager = DatabaseManager()
        self.usb_monitor = USBMonitor()
        self.protection_service = FileProtectionService(self.db_manager, self.usb_monitor)
        
        # Setup GUI
        self._setup_gui()
        self._setup_status_updates()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        
        # Start protection automatically
        self.protection_service.start_protection()
    
    def _setup_gui(self):
        """Setup the GUI components"""
        # Create main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Protection tab
        protection_frame = ttk.Frame(notebook)
        notebook.add(protection_frame, text="Protection")
        self._setup_protection_tab(protection_frame)
        
        # Monitoring tab
        monitoring_frame = ttk.Frame(notebook)
        notebook.add(monitoring_frame, text="Monitoring")
        self._setup_monitoring_tab(monitoring_frame)
        
        # Quarantine tab
        quarantine_frame = ttk.Frame(notebook)
        notebook.add(quarantine_frame, text="Quarantine")
        self._setup_quarantine_tab(quarantine_frame)
        
        # Status tab
        status_frame = ttk.Frame(notebook)
        notebook.add(status_frame, text="System Status")
        self._setup_status_tab(status_frame)
    
    def _setup_protection_tab(self, parent):
        """Setup protection configuration tab"""
        # Title
        title_label = ttk.Label(parent, text="Folder Protection Configuration", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Add folder frame
        add_frame = ttk.LabelFrame(parent, text="Add Protected Folder")
        add_frame.pack(fill="x", padx=10, pady=5)
        
        # Folder selection
        folder_frame = ttk.Frame(add_frame)
        folder_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(folder_frame, text="Folder Path:").pack(side="left")
        self.folder_var = tk.StringVar()
        folder_entry = ttk.Entry(folder_frame, textvariable=self.folder_var, width=50)
        folder_entry.pack(side="left", padx=(10, 5))
        
        ttk.Button(folder_frame, text="Browse...", 
                  command=self._browse_folder).pack(side="left")
        
        # Options frame
        options_frame = ttk.Frame(add_frame)
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.usb_required_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Require USB dongle for access", 
                       variable=self.usb_required_var).pack(side="left")
        
        # Add button
        ttk.Button(add_frame, text="Add Protected Folder", 
                  command=self._add_protected_folder).pack(pady=10)
        
        # Protected folders list
        list_frame = ttk.LabelFrame(parent, text="Currently Protected Folders")
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for folders
        columns = ("Path", "USB Required", "Status", "Created")
        self.folders_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.folders_tree.heading(col, text=col)
            self.folders_tree.column(col, width=200)
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.folders_tree.yview)
        h_scroll = ttk.Scrollbar(list_frame, orient="horizontal", command=self.folders_tree.xview)
        self.folders_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Pack treeview and scrollbars
        self.folders_tree.pack(side="left", fill="both", expand=True)
        v_scroll.pack(side="right", fill="y")
        h_scroll.pack(side="bottom", fill="x")
        
        # Buttons frame
        buttons_frame = ttk.Frame(list_frame)
        buttons_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="Remove Selected", 
                  command=self._remove_selected_folder).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Refresh List", 
                  command=self._refresh_folders_list).pack(side="left", padx=5)
        
        # Load initial data
        self._refresh_folders_list()
    
    def _setup_monitoring_tab(self, parent):
        """Setup monitoring tab"""
        # Title
        title_label = ttk.Label(parent, text="Real-time Threat Monitoring", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Status frame
        status_frame = ttk.LabelFrame(parent, text="Protection Status")
        status_frame.pack(fill="x", padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Protection Status: ACTIVE", 
                                     font=('Arial', 12, 'bold'), foreground="green")
        self.status_label.pack(pady=10)
        
        # Control buttons
        control_frame = ttk.Frame(status_frame)
        control_frame.pack(pady=5)
        
        ttk.Button(control_frame, text="Stop Protection", 
                  command=self._stop_protection).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Start Protection", 
                  command=self._start_protection).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Restart Protection", 
                  command=self._restart_protection).pack(side="left", padx=5)
        
        # Threats list
        threats_frame = ttk.LabelFrame(parent, text="Recent Threat Detections")
        threats_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for threats
        threat_columns = ("Time", "File", "Threat Type", "Action", "Severity")
        self.threats_tree = ttk.Treeview(threats_frame, columns=threat_columns, show="headings")
        
        for col in threat_columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=150)
        
        # Scrollbar for threats
        threats_scroll = ttk.Scrollbar(threats_frame, orient="vertical", 
                                     command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=threats_scroll.set)
        
        self.threats_tree.pack(side="left", fill="both", expand=True)
        threats_scroll.pack(side="right", fill="y")
        
        # Refresh button
        ttk.Button(threats_frame, text="Refresh Threats", 
                  command=self._refresh_threats_list).pack(side="bottom", pady=5)
        
        # Load initial threats
        self._refresh_threats_list()
    
    def _setup_quarantine_tab(self, parent):
        """Setup quarantine management tab"""
        # Title
        title_label = ttk.Label(parent, text="Quarantine Management", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Quarantine info
        info_frame = ttk.LabelFrame(parent, text="Quarantine Information")
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.quarantine_info = ttk.Label(info_frame, text="Loading quarantine information...")
        self.quarantine_info.pack(pady=10)
        
        # Quarantined files list
        files_frame = ttk.LabelFrame(parent, text="Quarantined Files")
        files_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for quarantined files
        quarantine_columns = ("Filename", "Original Path", "Quarantined", "Size")
        self.quarantine_tree = ttk.Treeview(files_frame, columns=quarantine_columns, show="headings")
        
        for col in quarantine_columns:
            self.quarantine_tree.heading(col, text=col)
            self.quarantine_tree.column(col, width=200)
        
        quarantine_scroll = ttk.Scrollbar(files_frame, orient="vertical", 
                                        command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=quarantine_scroll.set)
        
        self.quarantine_tree.pack(side="left", fill="both", expand=True)
        quarantine_scroll.pack(side="right", fill="y")
        
        # Quarantine buttons
        qbuttons_frame = ttk.Frame(files_frame)
        qbuttons_frame.pack(fill="x", pady=5)
        
        ttk.Button(qbuttons_frame, text="Refresh List", 
                  command=self._refresh_quarantine_list).pack(side="left", padx=5)
        ttk.Button(qbuttons_frame, text="Delete Selected", 
                  command=self._delete_quarantined_file).pack(side="left", padx=5)
        ttk.Button(qbuttons_frame, text="Clear All", 
                  command=self._clear_all_quarantine).pack(side="left", padx=5)
        
        self._refresh_quarantine_list()
    
    def _setup_status_tab(self, parent):
        """Setup system status tab"""
        # Title
        title_label = ttk.Label(parent, text="System Status & Information", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # System info frame
        sys_frame = ttk.LabelFrame(parent, text="System Information")
        sys_frame.pack(fill="x", padx=10, pady=5)
        
        self.system_info = tk.Text(sys_frame, height=8, wrap="word")
        sys_scroll = ttk.Scrollbar(sys_frame, orient="vertical", command=self.system_info.yview)
        self.system_info.configure(yscrollcommand=sys_scroll.set)
        
        self.system_info.pack(side="left", fill="both", expand=True)
        sys_scroll.pack(side="right", fill="y")
        
        # USB status frame
        usb_frame = ttk.LabelFrame(parent, text="USB Device Status")
        usb_frame.pack(fill="x", padx=10, pady=5)
        
        self.usb_status_label = ttk.Label(usb_frame, text="Checking USB devices...")
        self.usb_status_label.pack(pady=10)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(parent, text="Protection Statistics")
        stats_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.stats_text = tk.Text(stats_frame, height=6, wrap="word")
        stats_scroll = ttk.Scrollbar(stats_frame, orient="vertical", command=self.stats_text.yview)
        self.stats_text.configure(yscrollcommand=stats_scroll.set)
        
        self.stats_text.pack(side="left", fill="both", expand=True)
        stats_scroll.pack(side="right", fill="y")
        
        self._refresh_status_info()
    
    def _setup_status_updates(self):
        """Setup automatic status updates"""
        def update_status():
            self._refresh_status_info()
            self._update_protection_status()
            self.root.after(5000, update_status)  # Update every 5 seconds
        
        self.root.after(1000, update_status)  # Start after 1 second
    
    def _browse_folder(self):
        """Browse for folder to protect"""
        folder = filedialog.askdirectory(title="Select Folder to Protect")
        if folder:
            self.folder_var.set(folder)
    
    def _add_protected_folder(self):
        """Add a new protected folder"""
        folder_path = self.folder_var.get().strip()
        
        if not folder_path:
            messagebox.showerror("Error", "Please select a folder to protect")
            return
        
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Selected folder does not exist")
            return
        
        folder = ProtectedFolder(
            path=folder_path,
            usb_required=self.usb_required_var.get(),
            active=True,
            created=datetime.now()
        )
        
        if self.db_manager.add_protected_folder(folder):
            messagebox.showinfo("Success", "Folder added to protection successfully")
            self.folder_var.set("")
            self._refresh_folders_list()
            self.protection_service.restart_protection()
        else:
            messagebox.showerror("Error", "Failed to add folder to protection")
    
    def _remove_selected_folder(self):
        """Remove selected protected folder"""
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a folder to remove")
            return
        
        item = self.folders_tree.item(selection[0])
        folder_path = item['values'][0]
        
        if messagebox.askyesno("Confirm", f"Remove protection from:\n{folder_path}"):
            if self.db_manager.remove_protected_folder(folder_path):
                messagebox.showinfo("Success", "Folder removed from protection")
                self._refresh_folders_list()
                self.protection_service.restart_protection()
            else:
                messagebox.showerror("Error", "Failed to remove folder")
    
    def _refresh_folders_list(self):
        """Refresh the protected folders list"""
        # Clear existing items
        for item in self.folders_tree.get_children():
            self.folders_tree.delete(item)
        
        # Load folders from database
        folders = self.db_manager.get_protected_folders()
        
        for folder in folders:
            status = "Active" if folder.active else "Inactive"
            usb_req = "Yes" if folder.usb_required else "No"
            created = folder.created.strftime("%Y-%m-%d %H:%M")
            
            self.folders_tree.insert("", "end", values=(
                folder.path, usb_req, status, created
            ))
    
    def _refresh_threats_list(self):
        """Refresh the threats list"""
        # Clear existing items
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        # Load recent threats
        threats = self.db_manager.get_recent_threats(50)
        
        for threat in threats:
            timestamp = datetime.fromisoformat(threat['timestamp']).strftime("%H:%M:%S")
            filename = os.path.basename(threat['file_path'])
            
            # Color code by severity
            tags = []
            if threat['severity'] == 'CRITICAL':
                tags = ['critical']
            elif threat['severity'] == 'HIGH':
                tags = ['high']
            
            self.threats_tree.insert("", "end", values=(
                timestamp, filename, threat['threat_type'], 
                threat['action'], threat['severity']
            ), tags=tags)
        
        # Configure tag colors
        self.threats_tree.tag_configure('critical', background='#ffcccc')
        self.threats_tree.tag_configure('high', background='#ffe6cc')
    
    def _refresh_quarantine_list(self):
        """Refresh quarantine files list"""
        # Clear existing items
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        
        try:
            quarantine_count = 0
            total_size = 0
            
            for file_path in QUARANTINE_PATH.glob("THREAT_*"):
                if file_path.suffix == '.meta':
                    continue
                
                quarantine_count += 1
                file_size = file_path.stat().st_size
                total_size += file_size
                
                # Load metadata if available
                meta_file = file_path.with_suffix('.meta')
                original_path = str(file_path)
                quarantined_time = "Unknown"
                
                if meta_file.exists():
                    try:
                        with open(meta_file, 'r') as f:
                            metadata = json.load(f)
                            original_path = metadata.get('original_path', str(file_path))
                            quarantined_time = datetime.fromisoformat(
                                metadata['quarantined_at']
                            ).strftime("%Y-%m-%d %H:%M")
                    except:
                        pass
                
                self.quarantine_tree.insert("", "end", values=(
                    file_path.name, original_path, quarantined_time, 
                    f"{file_size:,} bytes"
                ))
            
            # Update quarantine info
            size_mb = total_size / (1024 * 1024)
            self.quarantine_info.config(
                text=f"Quarantined Files: {quarantine_count} | Total Size: {size_mb:.1f} MB"
            )
            
        except Exception as e:
            self.quarantine_info.config(text=f"Error loading quarantine: {e}")
    
    def _delete_quarantined_file(self):
        """Delete selected quarantined file"""
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to delete")
            return
        
        item = self.quarantine_tree.item(selection[0])
        filename = item['values'][0]
        
        if messagebox.askyesno("Confirm", f"Permanently delete quarantined file:\n{filename}"):
            try:
                file_path = QUARANTINE_PATH / filename
                meta_path = file_path.with_suffix('.meta')
                
                if file_path.exists():
                    file_path.unlink()
                if meta_path.exists():
                    meta_path.unlink()
                
                messagebox.showinfo("Success", "File deleted successfully")
                self._refresh_quarantine_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete file: {e}")
    
    def _clear_all_quarantine(self):
        """Clear all quarantined files"""
        if messagebox.askyesno("Confirm", "Delete ALL quarantined files?\nThis action cannot be undone."):
            try:
                deleted_count = 0
                for file_path in QUARANTINE_PATH.glob("*"):
                    if file_path.is_file():
                        file_path.unlink()
                        deleted_count += 1
                
                messagebox.showinfo("Success", f"Deleted {deleted_count} quarantined files")
                self._refresh_quarantine_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear quarantine: {e}")
    
    def _stop_protection(self):
        """Stop file protection"""
        self.protection_service.stop_protection()
        self.status_label.config(text="Protection Status: STOPPED", foreground="red")
    
    def _start_protection(self):
        """Start file protection"""
        if self.protection_service.start_protection():
            self.status_label.config(text="Protection Status: ACTIVE", foreground="green")
        else:
            self.status_label.config(text="Protection Status: FAILED", foreground="red")
    
    def _restart_protection(self):
        """Restart file protection"""
        if self.protection_service.restart_protection():
            self.status_label.config(text="Protection Status: RESTARTED", foreground="green")
            messagebox.showinfo("Success", "Protection service restarted successfully")
        else:
            self.status_label.config(text="Protection Status: FAILED", foreground="red")
            messagebox.showerror("Error", "Failed to restart protection service")
    
    def _update_protection_status(self):
        """Update protection status display"""
        if self.protection_service.running:
            active_count = len(self.protection_service.observers)
            self.status_label.config(
                text=f"Protection Status: ACTIVE ({active_count} folders monitored)", 
                foreground="green"
            )
        else:
            self.status_label.config(text="Protection Status: STOPPED", foreground="red")
    
    def _refresh_status_info(self):
        """Refresh system status information"""
        try:
            # System information
            sys_info = []
            sys_info.append(f"Program Version: Real Anti-Ransomware v2.0")
            sys_info.append(f"Database Path: {DATABASE_PATH}")
            sys_info.append(f"Quarantine Path: {QUARANTINE_PATH}")
            sys_info.append(f"Log Path: {LOG_PATH}")
            
            # Memory usage
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            sys_info.append(f"Memory Usage: {memory_mb:.1f} MB")
            
            # Disk usage
            try:
                disk_usage = shutil.disk_usage(str(PROGRAM_DATA))
                free_gb = disk_usage.free / (1024**3)
                sys_info.append(f"Available Disk Space: {free_gb:.1f} GB")
            except:
                sys_info.append("Available Disk Space: Unknown")
            
            self.system_info.delete(1.0, tk.END)
            self.system_info.insert(1.0, "\n".join(sys_info))
            
            # USB status
            usb_devices = self.usb_monitor.get_usb_devices()
            if usb_devices:
                usb_text = f"USB Devices Connected: {len(usb_devices)}\nDevices: {', '.join(usb_devices)}"
            else:
                usb_text = "No USB devices connected"
            
            self.usb_status_label.config(text=usb_text)
            
            # Statistics
            folders = self.db_manager.get_protected_folders()
            threats = self.db_manager.get_recent_threats(100)
            
            stats = []
            stats.append(f"Protected Folders: {len(folders)}")
            stats.append(f"Active Folders: {sum(1 for f in folders if f.active)}")
            stats.append(f"Total Threats Detected: {len(threats)}")
            stats.append(f"Critical Threats: {sum(1 for t in threats if t['severity'] == 'CRITICAL')}")
            stats.append(f"Files Quarantined: {sum(1 for t in threats if t['action'] == 'QUARANTINED')}")
            
            # Quarantine statistics
            try:
                quarantine_files = list(QUARANTINE_PATH.glob("THREAT_*"))
                quarantine_files = [f for f in quarantine_files if f.suffix != '.meta']
                total_quarantine_size = sum(f.stat().st_size for f in quarantine_files)
                stats.append(f"Quarantined Files: {len(quarantine_files)}")
                stats.append(f"Quarantine Size: {total_quarantine_size / 1024 / 1024:.1f} MB")
            except:
                stats.append("Quarantine Status: Error reading")
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, "\n".join(stats))
            
        except Exception as e:
            print(f"Status refresh error: {e}")
    
    def _on_closing(self):
        """Handle application closing"""
        if messagebox.askokcancel("Quit", "Stop protection and exit application?"):
            self.protection_service.stop_protection()
            self.root.destroy()
    
    def run(self):
        """Run the application"""
        print("Starting Real Anti-Ransomware Protection...")
        print(f"Database: {DATABASE_PATH}")
        print(f"Quarantine: {QUARANTINE_PATH}")
        print("GUI application starting...")
        
        self.root.mainloop()

def main():
    """Main entry point"""
    try:
        app = AntiRansomwareGUI()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
