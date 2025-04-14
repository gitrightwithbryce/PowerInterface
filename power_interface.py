#!/usr/bin/env python3
"""
PowerInterface - RSPS Network Analysis Tool
A GUI application for monitoring, capturing, and manipulating 
network packets for RuneScape Private Servers.
"""

import sys
import os
import time
import threading
import socket
import psutil
import pandas as pd
import numpy as np
from datetime import datetime
from hexdump import hexdump
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QComboBox, 
                            QTableWidget, QTableWidgetItem, QTabWidget, 
                            QTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem, 
                            QHeaderView, QMessageBox, QStatusBar, QGroupBox,
                            QCheckBox, QFileDialog, QLineEdit, QFrame)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QColor, QIcon

# Add after imports, before the is_admin() function
def setup_environment():
    """Setup necessary environment variables for Qt in WSL"""
    if not os.environ.get('DISPLAY'):
        os.environ['DISPLAY'] = ':0'
    
    # Get the real user when running with sudo
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')
    real_user = os.environ.get('SUDO_USER', os.getenv('USER'))
    
    if not os.environ.get('XDG_RUNTIME_DIR'):
        # Use the real user's runtime directory
        runtime_dir = f"/run/user/{sudo_uid if sudo_uid else os.getuid()}"
        os.environ['XDG_RUNTIME_DIR'] = runtime_dir
        
        # Create and set permissions for runtime directory if it doesn't exist
        if not os.path.exists(runtime_dir):
            os.makedirs(runtime_dir, mode=0o700, exist_ok=True)
            if sudo_uid and sudo_gid:
                os.chown(runtime_dir, int(sudo_uid), int(sudo_gid))
            
    if not os.environ.get('WAYLAND_DISPLAY'):
        os.environ['QT_QPA_PLATFORM'] = 'xcb'  # Force X11 backend

# Add this call right after the imports
setup_environment()

# Check if running with admin/root privileges
def is_admin():
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix-like
            # Check both effective UID and if running with sudo
            is_root = os.geteuid() == 0
            is_sudo = 'SUDO_UID' in os.environ
            return is_root or is_sudo
    except Exception as e:
        print(f"Error checking admin privileges: {e}")
        return False

# Only show warning if actually running without privileges
if not is_admin():
    print("WARNING: This application requires administrative privileges for packet capture.")
    print("Please restart with elevated permissions (sudo).")
    # Don't exit, but warn the user
    print("Continuing without elevated permissions may limit packet capture functionality.")

# Import Scapy with suppressed warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import sniff, IP, TCP, UDP, raw, wrpcap, rdpcap, send, Raw
except ImportError:
    print("ERROR: Could not import Scapy. Please ensure it's installed correctly.")
    sys.exit(1)

class PacketCaptureThread(QThread):
    """Thread for capturing packets without blocking the GUI"""
    packet_captured = pyqtSignal(object)
    
    def __init__(self, process_pid, filter_str=None):
        super().__init__()
        self.process_pid = process_pid
        self.filter_str = filter_str
        self.running = False
        self.interfaces = []
        self.connections = []
        self.socket = None
        self.update_process_connections()
        
    def update_process_connections(self):
        """Get all network connections for the selected process"""
        if not self.process_pid:
            return
            
        try:
            process = psutil.Process(self.process_pid)
            self.connections = process.net_connections()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.connections = []
            
    def get_filter_string(self):
        """Generate BPF filter string based on process connections"""
        filters = []
        
        for conn in self.connections:
            if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                local_ip, local_port = conn.laddr
                remote_ip, remote_port = conn.raddr
                
                # Create filter for this connection (both directions)
                conn_filter = f"(host {local_ip} and host {remote_ip} and port {local_port} and port {remote_port})"
                filters.append(conn_filter)
                
        return " or ".join(filters) if filters else "tcp or udp"
        
    def run(self):
        """Main packet capture loop"""
        self.running = True
        self.update_process_connections()
        
        try:
            # Use custom filter if provided, otherwise generate from connections
            filter_str = self.filter_str if self.filter_str else self.get_filter_string()
            
            def packet_callback(packet):
                if not self.running:
                    return True  # Return True to stop sniffing
                if IP in packet and (TCP in packet or UDP in packet):
                    self.packet_captured.emit(packet)
                return False  # Continue sniffing
            
            # Start packet capture with error handling
            try:
                # Use stop_filter instead of checking self.running in callback
                sniff(filter=filter_str, 
                      prn=packet_callback,
                      store=0,
                      stop_filter=lambda _: not self.running,
                      timeout=0.1)  # Add small timeout to make stop more responsive
            except Exception as e:
                print(f"Packet capture error: {e}")
                # Try without filter if filter fails
                if "Cannot compile filter" in str(e):
                    print("Attempting capture without filter...")
                    sniff(prn=packet_callback, 
                          store=0,
                          stop_filter=lambda _: not self.running,
                          timeout=0.1)
                    
        except Exception as e:
            print(f"Capture thread error: {e}")
        finally:
            self.running = False
            
    def stop(self):
        """Stop the packet capture thread"""
        self.running = False
        # Give the thread a moment to stop gracefully
        self.wait(1000)  # Wait up to 1 second
        if self.isRunning():
            print("Forcing thread termination...")
            self.terminate()  # Force termination if still running
            self.wait()  # Wait for termination to complete

class PacketManager:
    """Manages packet operations like storing, filtering and manipulation"""
    
    def __init__(self):
        self.packets = []
        self.filtered_packets = []
        self.current_filter = None
        
    def add_packet(self, packet):
        """Add a new packet to storage"""
        packet_time = datetime.now()
        packet_data = {
            'time': packet_time,
            'packet': packet,
            'src': packet[IP].src if IP in packet else "",
            'dst': packet[IP].dst if IP in packet else "",
            'protocol': self._get_protocol(packet),
            'length': len(packet),
            'info': self._get_packet_info(packet),
            'modified': False
        }
        self.packets.append(packet_data)
        self._apply_filter()
        return len(self.packets) - 1
        
    def _get_protocol(self, packet):
        """Determine the protocol of the packet"""
        if TCP in packet:
            return f"TCP {packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            return f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
        elif IP in packet:
            return f"IP {packet[IP].proto}"
        else:
            return "Unknown"
    
    def _get_packet_info(self, packet):
        """Extract useful info from the packet"""
        info = ""
        if TCP in packet:
            flags = []
            if packet[TCP].flags & 0x01: flags.append("F")  # FIN
            if packet[TCP].flags & 0x02: flags.append("S")  # SYN
            if packet[TCP].flags & 0x04: flags.append("R")  # RST
            if packet[TCP].flags & 0x08: flags.append("P")  # PSH
            if packet[TCP].flags & 0x10: flags.append("A")  # ACK
            if packet[TCP].flags & 0x20: flags.append("U")  # URG
            
            flag_str = "".join(flags)
            info = f"Seq={packet[TCP].seq} Ack={packet[TCP].ack} Win={packet[TCP].window} [{flag_str}]"
            
            # Check for payload data
            if Raw in packet:
                data_len = len(packet[Raw])
                info += f" Len={data_len}"
                
        elif UDP in packet:
            info = f"Len={len(packet[UDP])}"
            if Raw in packet:
                data_len = len(packet[Raw])
                info += f" Data={data_len}"
                
        return info
        
    def set_filter(self, filter_func):
        """Set a new filter function"""
        self.current_filter = filter_func
        self._apply_filter()
        
    def _apply_filter(self):
        """Apply current filter to packets"""
        if self.current_filter:
            self.filtered_packets = [p for p in self.packets if self.current_filter(p)]
        else:
            self.filtered_packets = self.packets[:]
        
    def get_displayed_packets(self):
        """Get the current filtered/displayed packets"""
        return self.filtered_packets
        
    def get_packet(self, index):
        """Get packet by index"""
        if 0 <= index < len(self.packets):
            return self.packets[index]
        return None
        
    def modify_packet(self, index, modified_packet):
        """Replace a packet with a modified version"""
        if 0 <= index < len(self.packets):
            self.packets[index]['packet'] = modified_packet
            self.packets[index]['modified'] = True
            self.packets[index]['length'] = len(modified_packet)
            self.packets[index]['info'] = self._get_packet_info(modified_packet)
            return True
        return False
        
    def save_packets(self, filename):
        """Save captured packets to a pcap file"""
        try:
            wrpcap(filename, [p['packet'] for p in self.filtered_packets])
            return True
        except Exception as e:
            print(f"Error saving packets: {e}")
            return False
            
    def clear(self):
        """Clear all stored packets"""
        self.packets = []
        self.filtered_packets = []

class ProcessSelector(QWidget):
    """Widget for selecting a running process"""
    
    process_selected = pyqtSignal(int)
    
    def __init__(self):
        super().__init__()
        self.processes = []
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Process selection
        select_layout = QHBoxLayout()
        select_layout.addWidget(QLabel("Select RSPS Process:"))
        
        self.process_combo = QComboBox()
        self.process_combo.setMinimumWidth(300)
        self.process_combo.setMaximumWidth(500)  # Add maximum width
        select_layout.addWidget(self.process_combo)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_processes)
        select_layout.addWidget(refresh_btn)
        
        select_layout.addStretch(1)
        layout.addLayout(select_layout)
        
        # Process details
        details_group = QGroupBox("Process Details")
        details_layout = QVBoxLayout()
        
        self.details_label = QLabel("No process selected")
        self.details_label.setWordWrap(True)  # Allow text wrapping
        self.details_label.setMinimumHeight(100)  # Set minimum height
        self.details_label.setMaximumHeight(150)  # Set maximum height
        details_layout.addWidget(self.details_label)
        
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        self.setLayout(layout)
        
        # Set fixed size for the widget
        self.setMinimumHeight(200)
        self.setMaximumHeight(250)
        
        # Connect signals
        self.process_combo.currentIndexChanged.connect(self.on_process_selected)
        
        # Initialize process list
        self.refresh_processes()
        
    def refresh_processes(self):
        """Update the list of running processes"""
        self.process_combo.clear()
        self.processes = []
        
        # Check if running in WSL
        is_wsl = 'microsoft-standard' in os.uname().release.lower() if hasattr(os, 'uname') else False
        
        if is_wsl:
            try:
                # Use powershell to get Windows processes
                import subprocess
                ps_command = """powershell.exe -Command "Get-Process | Where-Object {$_.MainWindowTitle -ne '' -or $_.ProcessName -match 'java|roat|client'} | Select-Object ProcessName,Id,Path | ConvertTo-Json" """
                result = subprocess.run(ps_command, capture_output=True, text=True, shell=True)
                
                if result.returncode == 0 and result.stdout.strip():
                    import json
                    win_processes = json.loads(result.stdout)
                    # Handle single process case
                    if isinstance(win_processes, dict):
                        win_processes = [win_processes]
                    
                    for proc in win_processes:
                        proc_name = proc.get('ProcessName', '').lower()
                        proc_id = proc.get('Id')
                        proc_path = proc.get('Path', '')
                        
                        # Check if it's likely a game client
                        if any(name in proc_name for name in ['java', 'roat', 'client', 'chrome', 'firefox', 'electron']):
                            proc_info = {
                                'pid': proc_id,
                                'name': proc_name,
                                'username': 'Windows',
                                'cmdline': proc_path,
                                'exe_path': proc_path,
                                'cwd': os.path.dirname(proc_path) if proc_path else ''
                            }
                            
                            self.processes.append(proc_info)
                            display_name = f"{proc_name}"
                            if proc_path:
                                display_name += f" ({os.path.basename(proc_path)})"
                            display_name += f" [PID: {proc_id}] (Windows)"
                            display_name = "🎮 " + display_name
                            self.process_combo.addItem(display_name, proc_id)
                            
            except Exception as e:
                print(f"Error getting Windows processes: {e}")
            
        # Get WSL processes (for completeness)
        rsps_patterns = [
            'java',
            'javaw',
            'roat',
            'roatpkz',
            'node',
            'rsps',
            'runescape',
            'client',
            'loader',
            'play'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower() if proc_info['name'] else ''
                cmdline = ' '.join(proc_info['cmdline']).lower() if proc_info['cmdline'] else ''
                
                # Check if process matches RSPS patterns
                is_rsps = False
                for pattern in rsps_patterns:
                    if pattern in proc_name or pattern in cmdline:
                        is_rsps = True
                        break
                
                if is_rsps:
                    try:
                        exe_path = proc.exe()
                        cwd = proc.cwd()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe_path = ''
                        cwd = ''
                    
                    proc_info = {
                        'pid': proc.pid,
                        'name': proc_name,
                        'username': proc_info['username'],
                        'cmdline': cmdline,
                        'exe_path': exe_path,
                        'cwd': cwd
                    }
                    
                    self.processes.append(proc_info)
                    display_name = f"{proc_name}"
                    if exe_path:
                        display_name += f" ({os.path.basename(exe_path)})"
                    display_name += f" [PID: {proc.pid}] (WSL)"
                    display_name = "🎮 " + display_name
                    self.process_combo.addItem(display_name, proc.pid)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
    def on_process_selected(self, index):
        """Handle process selection"""
        if index >= 0 and index < len(self.processes):
            selected_pid = self.processes[index]['pid']
            
            # Update details display
            proc_info = self.processes[index]
            details = f"<b>Name:</b> {proc_info['name']}<br>"
            details += f"<b>PID:</b> {proc_info['pid']}<br>"
            details += f"<b>User:</b> {proc_info['username']}<br>"
            
            # Truncate command line if too long
            cmd = proc_info['cmdline']
            if len(cmd) > 100:
                cmd = cmd[:97] + "..."
            details += f"<b>Command:</b> {cmd}<br><br>"
            
            # Add network connections
            try:
                process = psutil.Process(selected_pid)
                connections = process.net_connections()
                
                if connections:
                    details += "<b>Network Connections:</b><br>"
                    for conn in connections:
                        if conn.laddr and hasattr(conn, 'raddr') and conn.raddr:
                            details += f"• {conn.laddr.ip}:{conn.laddr.port} → {conn.raddr.ip}:{conn.raddr.port} [{conn.status}]<br>"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                details += "Could not retrieve network connections (access denied)"
                
            self.details_label.setText(details)
            
            # Emit signal
            self.process_selected.emit(selected_pid)
        else:
            self.details_label.setText("No process selected")
            self.process_selected.emit(-1)

class PacketTableWidget(QTableWidget):
    """Custom table widget for displaying packets"""
    
    packet_selected = pyqtSignal(int)
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the table UI"""
        # Set up columns
        columns = ["#", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
        self.setColumnCount(len(columns))
        self.setHorizontalHeaderLabels(columns)
        
        # Set properties
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        
        # Resize columns
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Number
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Source
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Destination
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(6, QHeaderView.Stretch)           # Info
        
        # Connect signals
        self.itemSelectionChanged.connect(self.on_selection_change)
        
    def add_packet(self, index, packet_data):
        """Add a packet to the table"""
        row = self.rowCount()
        self.insertRow(row)
        
        # Format time
        time_str = packet_data['time'].strftime('%H:%M:%S.%f')[:-3]
        
        # Set values
        self.setItem(row, 0, QTableWidgetItem(str(index + 1)))
        self.setItem(row, 1, QTableWidgetItem(time_str))
        self.setItem(row, 2, QTableWidgetItem(packet_data['src']))
        self.setItem(row, 3, QTableWidgetItem(packet_data['dst']))
        self.setItem(row, 4, QTableWidgetItem(packet_data['protocol']))
        self.setItem(row, 5, QTableWidgetItem(str(packet_data['length'])))
        self.setItem(row, 6, QTableWidgetItem(packet_data['info']))
        
        # Mark modified packets
        if packet_data.get('modified', False):
            for col in range(7):
                self.item(row, col).setBackground(QColor(255, 255, 200))  # Light yellow
        
        # Store packet index
        self.setItem(row, 0, QTableWidgetItem(str(index + 1)))
        self.item(row, 0).setData(Qt.UserRole, index)
        
        # Scroll to new row
        self.scrollToBottom()
        
    def clear_packets(self):
        """Clear all packets from the table"""
        self.setRowCount(0)
        
    def on_selection_change(self):
        """Handle selection change in the table"""
        selected_items = self.selectedItems()
        if selected_items:
            selected_row = selected_items[0].row()
            packet_index = self.item(selected_row, 0).data(Qt.UserRole)
            self.packet_selected.emit(packet_index)

class PacketDetailsWidget(QWidget):
    """Widget for displaying packet details"""
    
    def __init__(self):
        super().__init__()
        self.current_packet = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Packet structure tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Layer", "Value"])
        self.tree.setAlternatingRowColors(True)
        layout.addWidget(self.tree)
        
        # Hex view of packet
        hex_group = QGroupBox("Hex View")
        hex_layout = QVBoxLayout()
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Courier New", 10))
        hex_layout.addWidget(self.hex_view)
        hex_group.setLayout(hex_layout)
        layout.addWidget(hex_group)
        
        self.setLayout(layout)
        
    def display_packet(self, packet_data):
        """Display packet details"""
        if not packet_data or 'packet' not in packet_data:
            self.clear()
            return
            
        self.current_packet = packet_data
        packet = packet_data['packet']
        
        # Clear previous data
        self.tree.clear()
        self.hex_view.clear()
        
        # Populate tree with packet layers
        self._add_packet_to_tree(packet)
        
        # Show hex dump
        if Raw in packet:
            raw_data = bytes(packet[Raw])
            hex_dump = hexdump(raw_data, result='return')
            self.hex_view.setText(hex_dump)
        else:
            self.hex_view.setText("No payload data")
            
    def _add_packet_to_tree(self, packet, parent=None):
        """Recursively add packet layers to tree"""
        if parent is None:
            # Root item
            item = QTreeWidgetItem(self.tree)
            item.setText(0, packet.name)
            parent = item
        
        # Add fields for this layer
        for field_name in packet.fields_desc:
            field_value = getattr(packet, field_name.name)
            
            child = QTreeWidgetItem(parent)
            child.setText(0, field_name.name)
            
            # Format the value
            if isinstance(field_value, int):
                value_str = f"{field_value} (0x{field_value:x})"
            elif isinstance(field_value, bytes):
                value_str = field_value.hex()
            else:
                value_str = str(field_value)
                
            child.setText(1, value_str)
        
        # Add payload
        if packet.payload:
            payload_item = QTreeWidgetItem(parent)
            payload_item.setText(0, packet.payload.name)
            
            # Recursively add payload layers
            self._add_packet_to_tree(packet.payload, payload_item)
            
    def clear(self):
        """Clear all packet details"""
        self.tree.clear()
        self.hex_view.clear()
        self.current_packet = None

class PacketEditorWidget(QWidget):
    """Widget for editing packet data"""
    
    packet_modified = pyqtSignal(int, object)
    packet_resent = pyqtSignal(object)
    
    def __init__(self):
        super().__init__()
        self.current_packet = None
        self.current_index = -1
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Hex editor
        hex_group = QGroupBox("Edit Packet Payload (Hex)")
        hex_layout = QVBoxLayout()
        self.hex_editor = QTextEdit()
        self.hex_editor.setFont(QFont("Courier New", 10))
        self.hex_editor.setPlaceholderText("Select a packet to edit its payload")
        hex_layout.addWidget(self.hex_editor)
        hex_group.setLayout(hex_layout)
        layout.addWidget(hex_group)
        
        # Actions
        actions_layout = QHBoxLayout()
        
        # Apply changes button
        self.apply_btn = QPushButton("Apply Changes")
        self.apply_btn.clicked.connect(self.apply_changes)
        self.apply_btn.setEnabled(False)
        actions_layout.addWidget(self.apply_btn)
        
        # Resend button
        self.resend_btn = QPushButton("Resend Packet")
        self.resend_btn.clicked.connect(self.resend_packet)
        self.resend_btn.setEnabled(False)
        actions_layout.addWidget(self.resend_btn)
        
        # Reset button
        self.reset_btn = QPushButton("Reset")
        self.reset_btn.clicked.connect(self.reset_changes)
        self.reset_btn.setEnabled(False)
        actions_layout.addWidget(self.reset_btn)
        
        layout.addLayout(actions_layout)
        
        # Validation messages
        self.validation_label = QLabel("")
        self.validation_label.setStyleSheet("color: red;")
        layout.addWidget(self.validation_label)
        
        self.setLayout(layout)
        
    def set_packet(self, packet_index, packet_data):
        """Set the packet to edit"""
        self.current_packet = packet_data
        self.current_index = packet_index
        
        self.hex_editor.clear()
        self.validation_label.clear()
        
        if packet_data and Raw in packet_data['packet']:
            raw_data = bytes(packet_data['packet'][Raw])
            hex_dump = hexdump(raw_data, result='return')
            self.hex_editor.setText(hex_dump)
            
            self.apply_btn.setEnabled(True)
            self.reset_btn.setEnabled(True)
            self.resend_btn.setEnabled(True)
        else:
            self.hex_editor.setPlaceholderText("Selected packet has no payload to edit")
            self.apply_btn.setEnabled(False)
            self.reset_btn.setEnabled(False)
            self.resend_btn.setEnabled(False)
            
    def apply_changes(self):
        """Apply the changes to the packet"""
        if not self.current_packet:
            return
            
        try:
            # Parse the hex dump back to bytes
            hex_text = self.hex_editor.toPlainText()
            
            # Parse the hex text
            bytes_data = self._parse_hex_dump(hex_text)
            
            if not bytes_data:
                self.validation_label.setText("Error: Invalid hex format")
                return
                
            # Create a modified packet
            packet = self.current_packet['packet'].copy()
            
            if Raw in packet:
                packet[Raw].load = bytes_data
            else:
                # No payload layer, add one
                packet = packet / Raw(load=bytes_data)
                
            # Emit the modified packet
            self.packet_modified.emit(self.current_index, packet)
            self.validation_label.setText("Packet modified successfully")
            self.validation_label.setStyleSheet("color: green;")
            
        except Exception as e:
            self.validation_label.setText(f"Error: {str(e)}")
            self.validation_label.setStyleSheet("color: red;")
            
    def _parse_hex_dump(self, hex_text):
        """Parse hexdump text back to bytes"""
        # Remove line numbers and ascii representation
        lines = hex_text.strip().split('\n')
        hex_values = []
        
        for line in lines:
            parts = line.split()
            if len(parts) > 1:
                # Skip first part (address)
                for i in range(1, min(9, len(parts))):  # Up to 8 hex pairs per line
                    if len(parts[i]) == 2 and all(c in '0123456789abcdefABCDEF' for c in parts[i]):
                        hex_values.append(parts[i])
        
        if not hex_values:
            return None
            
        try:
            return bytes.fromhex(''.join(hex_values))
        except ValueError:
            return None
            
    def reset_changes(self):
        """Reset changes to the original packet"""
        if self.current_packet and Raw in self.current_packet['packet']:
            raw_data = bytes(self.current_packet['packet'][Raw])
            hex_dump = hexdump(raw_data, result='return')
            self.hex_editor.setText(hex_dump)
            self.validation_label.clear()
            
    def resend_packet(self):
        """Resend the current packet"""
        if not self.current_packet:
            return
            
        try:
            # Get the modified packet if changes were made
            if self.hex_editor.document().isModified():
                self.apply_changes()
                
            # Send the packet
            packet = self.current_packet['packet']
            send(packet, verbose=0)
            
            self.validation_label.setText("Packet sent successfully")
            self.validation_label.setStyleSheet("color: green;")
            
            # Emit signal
            self.packet_resent.emit(packet)
        except Exception as e:
            self.validation_label.setText(f"Error sending packet: {str(e)}")
            self.validation_label.setStyleSheet("color: red;")
            
    def clear(self):
        """Clear editor state"""
        self.current_packet = None
        self.current_index = -1
        self.hex_editor.clear()
        self.validation_label.clear()
        self.apply_btn.setEnabled(False)
        self.reset_btn.setEnabled(False)
        self.resend_btn.setEnabled(False)

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        # Check for admin/root privileges
        if not is_admin():
            QMessageBox.warning(
                self, 
                "Insufficient Permissions",
                "This application requires administrative privileges for packet capture.\n"
                "Please restart with elevated permissions."
            )
        
        self.packet_manager = PacketManager()
        self.capture_thread = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI"""
        self.setWindowTitle("PowerInterface - RSPS Network Analysis Tool")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget
        central_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Process selection
        self.process_selector = ProcessSelector()
        self.process_selector.process_selected.connect(self.on_process_selected)
        main_layout.addWidget(self.process_selector)
        
        # Main splitter (packet list and details)
        splitter = QSplitter(Qt.Vertical)
        
        # Packet capture controls
        capture_group = QGroupBox("Packet Capture")
        capture_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setEnabled(False)
        capture_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        capture_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton("Clear Packets")
        self.clear_btn.clicked.connect(self.clear_packets)
        capture_layout.addWidget(self.clear_btn)
        
        save_btn = QPushButton("Save Packets")
        save_btn.clicked.connect(self.save_packets)
        capture_layout.addWidget(save_btn)
        
        # Filter controls
        capture_layout.addWidget(QLabel("Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter filter expression (e.g. tcp.port == 43594)")
        capture_layout.addWidget(self.filter_input)
        
        apply_filter_btn = QPushButton("Apply")
        apply_filter_btn.clicked.connect(self.apply_filter)
        capture_layout.addWidget(apply_filter_btn)
        
        capture_group.setLayout(capture_layout)
        main_layout.addWidget(capture_group)
        
        # Packet list
        self.packet_table = PacketTableWidget()
        self.packet_table.packet_selected.connect(self.on_packet_selected)
        
        # Tabs for details and editor
        tab_widget = QTabWidget()
        
        # Packet details tab
        self.packet_details = PacketDetailsWidget()
        tab_widget.addTab(self.packet_details, "Packet Details")
        
        # Packet editor tab
        self.packet_editor = PacketEditorWidget()
        self.packet_editor.packet_modified.connect(self.on_packet_modified)
        tab_widget.addTab(self.packet_editor, "Packet Editor")
        
        # Add to splitter
        splitter.addWidget(self.packet_table)
        splitter.addWidget(tab_widget)
        splitter.setSizes([400, 400])
        
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Set layout
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        
        # Timer for status updates
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(1000)  # 1 second interval
        
    def on_process_selected(self, pid):
        """Handle process selection"""
        if pid > 0:
            self.status_bar.showMessage(f"Selected process PID: {pid}")
            self.start_btn.setEnabled(True)
        else:
            self.status_bar.showMessage("No process selected")
            self.start_btn.setEnabled(False)
            
    def start_capture(self):
        """Start packet capture"""
        if self.capture_thread and self.capture_thread.isRunning():
            return
            
        selected_pid = -1
        for proc in self.process_selector.processes:
            if self.process_selector.process_combo.currentData() == proc['pid']:
                selected_pid = proc['pid']
                break
                
        if selected_pid <= 0:
            QMessageBox.warning(self, "Error", "No valid process selected")
            return
            
        # Create and start capture thread
        self.capture_thread = PacketCaptureThread(selected_pid)
        self.capture_thread.packet_captured.connect(self.on_packet_captured)
        self.capture_thread.start()
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.showMessage("Capturing packets...")
        
    def stop_capture(self):
        """Stop packet capture"""
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait()
            
        # Update UI
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.showMessage("Capture stopped")
        
    def on_packet_captured(self, packet):
        """Handle captured packet"""
        # Add to packet manager
        packet_index = self.packet_manager.add_packet(packet)
        
        # Update UI
        packets = self.packet_manager.get_displayed_packets()
        if packet in [p['packet'] for p in packets]:
            self.packet_table.add_packet(packet_index, packets[-1])
            
    def on_packet_selected(self, packet_index):
        """Handle packet selection in the table"""
        packet_data = self.packet_manager.get_packet(packet_index)
        if packet_data:
            self.packet_details.display_packet(packet_data)
            self.packet_editor.set_packet(packet_index, packet_data)
            
    def on_packet_modified(self, packet_index, modified_packet):
        """Handle packet modification"""
        if self.packet_manager.modify_packet(packet_index, modified_packet):
            # Refresh the packet table
            self.refresh_packet_table()
            
            # Update packet details
            packet_data = self.packet_manager.get_packet(packet_index)
            self.packet_details.display_packet(packet_data)
            
    def refresh_packet_table(self):
        """Refresh the packet table with current data"""
        self.packet_table.clear_packets()
        packets = self.packet_manager.get_displayed_packets()
        
        for i, packet_data in enumerate(packets):
            original_index = self.packet_manager.packets.index(packet_data)
            self.packet_table.add_packet(original_index, packet_data)
            
    def clear_packets(self):
        """Clear all captured packets"""
        self.packet_manager.clear()
        self.packet_table.clear_packets()
        self.packet_details.clear()
        self.packet_editor.clear()
        self.status_bar.showMessage("Packets cleared")
        
    def save_packets(self):
        """Save captured packets to a file"""
        if not self.packet_manager.packets:
            QMessageBox.information(self, "Information", "No packets to save")
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Packets", "", "PCAP Files (*.pcap);;All Files (*)"
        )
        
        if filename:
            if self.packet_manager.save_packets(filename):
                self.status_bar.showMessage(f"Packets saved to {filename}")
            else:
                QMessageBox.warning(self, "Error", "Failed to save packets")
                
    def apply_filter(self):
        """Apply filter to packet display"""
        filter_text = self.filter_input.text().strip()
        
        if not filter_text:
            # Clear filter
            self.packet_manager.set_filter(None)
        else:
            # Create filter function
            def filter_func(packet_data):
                if filter_text.lower() in str(packet_data).lower():
                    return True
                    
                # More specific filters
                if filter_text.startswith("ip."):
                    _, addr = filter_text.split(".", 1)
                    return addr in packet_data['src'] or addr in packet_data['dst']
                    
                if filter_text.startswith("tcp.port"):
                    try:
                        port = int(filter_text.split("==")[1].strip())
                        protocol = packet_data['protocol']
                        return f"TCP {port}" in protocol or f"→ {port}" in protocol
                    except:
                        pass
                        
                if filter_text.startswith("udp.port"):
                    try:
                        port = int(filter_text.split("==")[1].strip())
                        protocol = packet_data['protocol']
                        return f"UDP {port}" in protocol or f"→ {port}" in protocol
                    except:
                        pass
                        
                return False
                
            self.packet_manager.set_filter(filter_func)
            
        # Refresh the table
        self.refresh_packet_table()
        
    def update_status(self):
        """Update status bar with current stats"""
        if self.capture_thread and self.capture_thread.isRunning():
            packet_count = len(self.packet_manager.packets)
            displayed_count = len(self.packet_manager.filtered_packets)
            
            if self.packet_manager.current_filter:
                self.status_bar.showMessage(f"Capturing: {packet_count} packets captured, {displayed_count} displayed")
            else:
                self.status_bar.showMessage(f"Capturing: {packet_count} packets captured")
                
    def closeEvent(self, event):
        """Handle window close event"""
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for a consistent look
    window = MainWindow()
    window.show()
    sys.exit(app.exec_()) 