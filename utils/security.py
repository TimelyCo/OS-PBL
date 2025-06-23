import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import hashlib
import socket
import subprocess
import platform
import psutil
import threading
import time
from datetime import datetime

trusted_hashes = {
    'hash.py': '987e382c5208a6321babcd61f3e607648c7ffa2ae67192ee5aa483b610bbf861',
    'main.py': 'd234cd2a63512cd718414f6c07fec62b1b752f3b1555ee34f46b9414a38f8c31',
    'file_ops.py': 'f0f0cfabf2d3779afe4faa4cf3a9af44f8d24d6107b85a1cbae8e0bef7be36ed',
    'file_ops_gui.py': 'f2a2a62570552182cac4e541816e0e3fcde299b0c84a193602f509046b3b754e',
    'network_utils.py': '3975514480e48f426babc25c1e997dab56e7e7cb1a5b4d5727999ddb87b2e60a',
    'process_mgmt.py': 'f4527eb56e89242406b30d5229b2338a1b7930b9dd6ab183463c958689626543',
    '__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'command_parser.py': 'b22783922559ae4c7c44e58a4d1a25da6adc64d990a02bed2d0d4e2fd3936506',
    'security.py': 'ca5ecda94726cbd53009673a7548b58193406cc5a80b8fef3750f06c00e61fa5',
}

# Suspicious process patterns (common malware/suspicious names)
suspicious_patterns = ['keylog', 'trojan', 'virus', 'malware', 'backdoor', 'rootkit', 'spyware', 'adware']

# Global variables for monitoring
monitoring_active = False
monitor_thread = None

# ----- Utility Functions -----
def compute_file_hash(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None

def check_network_connection(host, port):
    try:
        ip = socket.gethostbyname(host)
        socket.create_connection((host, int(port)), timeout=5)
        return f"✅ Connected to {host}:{port} ({ip})"
    except Exception as e:
        return f"❌ Connection failed to {host}:{port} → {e}"

def list_processes():
    processes = []
    system = platform.system()
    if system == "Windows":
        out = subprocess.check_output("tasklist /fo csv /nh", shell=True).decode()
        for line in out.splitlines():
            try:
                name = line.split(',')[0].strip('"')
                processes.append(name)
            except IndexError:
                continue
    else:
        out = subprocess.check_output(["ps", "-e", "-o", "comm"]).decode()
        for line in out.splitlines()[1:]:
            processes.append(line.strip())
    return processes

def find_trusted_processes(trusted_list):
    result = []
    running = list_processes()
    for proc in running:
        if proc.lower() in trusted_list:
            result.append(proc)
    return result

# ----- NEW FEATURE: Real-time System Security Monitoring -----
def get_system_security_metrics():
    """Collect real-time system security metrics"""
    try:
        # CPU and Memory usage
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        # Network connections
        connections = psutil.net_connections()
        active_connections = len([conn for conn in connections if conn.status == 'ESTABLISHED'])
        
        # Running processes count
        process_count = len(psutil.pids())
        
        # Check for suspicious processes
        suspicious_procs = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                for pattern in suspicious_patterns:
                    if pattern in proc_name:
                        suspicious_procs.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Check for high CPU processes (potential security concern)
        high_cpu_procs = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                if proc.info['cpu_percent'] > 50:  # More than 50% CPU
                    high_cpu_procs.append(f"{proc.info['name']} ({proc.info['cpu_percent']:.1f}%)")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Network interface stats
        net_io = psutil.net_io_counters()
        
        return {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'active_connections': active_connections,
            'process_count': process_count,
            'suspicious_processes': suspicious_procs,
            'high_cpu_processes': high_cpu_procs[:5],  # Top 5
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv
        }
    except Exception as e:
        return {'error': str(e)}

def update_security_dashboard():
    """Update the real-time security dashboard"""
    global monitoring_active
    
    while monitoring_active:
        try:
            metrics = get_system_security_metrics()
            
            if 'error' not in metrics:
                # Update dashboard in main thread
                root.after(0, lambda: update_dashboard_display(metrics))
            
            time.sleep(2)  # Update every 2 seconds
        except Exception as e:
            print(f"Monitor error: {e}")
            break

def update_dashboard_display(metrics):
    """Update the dashboard display with new metrics"""
    dashboard_text.delete(1.0, tk.END)
    
    # Create formatted dashboard
    dashboard_content = f"""🔴 REAL-TIME SECURITY MONITORING DASHBOARD 🔴
Last Update: {metrics['timestamp']}

📊 SYSTEM PERFORMANCE:
├─ CPU Usage: {metrics['cpu_percent']:.1f}% {'⚠️ HIGH' if metrics['cpu_percent'] > 80 else '✅ Normal'}
├─ Memory Usage: {metrics['memory_percent']:.1f}% {'⚠️ HIGH' if metrics['memory_percent'] > 85 else '✅ Normal'}
├─ Active Network Connections: {metrics['active_connections']} {'⚠️ HIGH' if metrics['active_connections'] > 50 else '✅ Normal'}
└─ Running Processes: {metrics['process_count']}

🔍 SECURITY ALERTS:
"""
    
    if metrics['suspicious_processes']:
        dashboard_content += "🚨 SUSPICIOUS PROCESSES DETECTED:\n"
        for proc in metrics['suspicious_processes']:
            dashboard_content += f"   ⚠️ {proc}\n"
    else:
        dashboard_content += "✅ No suspicious processes detected\n"
    
    if metrics['high_cpu_processes']:
        dashboard_content += "\n🔥 HIGH CPU USAGE PROCESSES:\n"
        for proc in metrics['high_cpu_processes']:
            dashboard_content += f"   📈 {proc}\n"
    else:
        dashboard_content += "\n✅ No high CPU usage detected\n"
    
    dashboard_content += f"""
🌐 NETWORK ACTIVITY:
├─ Data Sent: {metrics['bytes_sent'] / (1024*1024):.2f} MB
└─ Data Received: {metrics['bytes_recv'] / (1024*1024):.2f} MB

🔒 SECURITY STATUS: {'🟢 SECURE' if not metrics['suspicious_processes'] and metrics['cpu_percent'] < 80 else '🟡 MONITOR' if not metrics['suspicious_processes'] else '🔴 ALERT'}
"""
    
    dashboard_text.insert(tk.END, dashboard_content)

def toggle_monitoring():
    """Toggle real-time monitoring on/off"""
    global monitoring_active, monitor_thread
    
    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=update_security_dashboard, daemon=True)
        monitor_thread.start()
        monitor_btn.config(text="⏹ Stop Monitoring", bg="#ff6b6b")
        status_label.config(text="🔴 LIVE MONITORING ACTIVE", fg="red")
    else:
        monitoring_active = False
        monitor_btn.config(text="▶️ Start Real-time Monitoring", bg="#51cf66")
        status_label.config(text="⚪ Monitoring Stopped", fg="gray")

# ----- Original GUI Actions -----
def handle_file_check():
    path = file_entry.get()
    hash_val = compute_file_hash(path)
    if hash_val:
        output_text.insert(tk.END, f"✅ File exists.\nSHA-256: {hash_val}\n\n")
    else:
        output_text.insert(tk.END, f"❌ File not found at: {path}\n\n")

def handle_file_integrity_check():
    path = file_entry.get()
    filename = path.split("\\")[-1]  # Extract file name from full path
    current_hash = compute_file_hash(path)

    if current_hash is None:
        output_text.insert(tk.END, f"❌ File not found: {path}\n\n")
        return

    trusted_hash = trusted_hashes.get(filename)
    if trusted_hash:
        if current_hash == trusted_hash:
            output_text.insert(tk.END, f"✅ File '{filename}' is trusted. Hash matches.\n\n")
        else:
            output_text.insert(tk.END, f"⚠️ WARNING: File '{filename}' may be corrupted. Hash mismatch!\n\n")
    else:
        output_text.insert(tk.END, f"ℹ️ No trusted hash available for '{filename}'. Cannot verify.\n\n")

def handle_network_check():
    host = host_entry.get()
    port = port_entry.get()
    result = check_network_connection(host, port)
    output_text.insert(tk.END, result + "\n\n")

def handle_process_check():
    user_input = proc_entry.get()
    trusted_list = [p.strip().lower() for p in user_input.split(",")]
    matches = find_trusted_processes(trusted_list)
    if matches:
        output_text.insert(tk.END, "✅ Trusted running processes:\n" + "\n".join(" - " + m for m in matches) + "\n\n")
    else:
        output_text.insert(tk.END, "❌ No trusted processes found running.\n\n")

def on_closing():
    """Handle application closing"""
    global monitoring_active
    monitoring_active = False
    root.destroy()

# ----- Enhanced GUI Layout -----
root = tk.Tk()
root.title("🔒 Advanced System Security Checker")
root.geometry("900x800")
root.protocol("WM_DELETE_WINDOW", on_closing)

# Create notebook for tabs
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True, padx=10, pady=10)

# Tab 1: Original Security Tools
tools_frame = ttk.Frame(notebook)
notebook.add(tools_frame, text="🔧 Security Tools")

tk.Label(tools_frame, text="🔹 File Path", font=("Arial", 10, "bold")).pack(pady=5)
file_entry = tk.Entry(tools_frame, width=80)
file_entry.pack()

frame1 = tk.Frame(tools_frame)
frame1.pack(pady=5)
tk.Button(frame1, text="Check File", command=handle_file_check, bg="#e3f2fd").pack(side=tk.LEFT, padx=5)
tk.Button(frame1, text="Check File Integrity", command=handle_file_integrity_check, bg="#f3e5f5").pack(side=tk.LEFT, padx=5)

tk.Label(tools_frame, text="🔹 Network Host and Port", font=("Arial", 10, "bold")).pack(pady=(20,5))
frame2 = tk.Frame(tools_frame)
frame2.pack()
host_entry = tk.Entry(frame2, width=40)
host_entry.pack(side=tk.LEFT, padx=5)
port_entry = tk.Entry(frame2, width=20)
port_entry.pack(side=tk.LEFT, padx=5)

tk.Button(tools_frame, text="Check Network", command=handle_network_check, bg="#e8f5e8").pack(pady=5)

tk.Label(tools_frame, text="🔹 Trusted Processes (comma-separated)", font=("Arial", 10, "bold")).pack(pady=(20,5))
proc_entry = tk.Entry(tools_frame, width=80)
proc_entry.pack()

tk.Button(tools_frame, text="Check Trusted Processes", command=handle_process_check, bg="#fff3e0").pack(pady=5)

tk.Label(tools_frame, text="🖥 Output", font=("Arial", 10, "bold")).pack(pady=(20,5))
output_text = scrolledtext.ScrolledText(tools_frame, width=80, height=15, wrap=tk.WORD)
output_text.pack(padx=10, pady=10)

# Tab 2: Real-time Security Dashboard
dashboard_frame = ttk.Frame(notebook)
notebook.add(dashboard_frame, text="📊 Live Dashboard")

# Control panel
control_frame = tk.Frame(dashboard_frame)
control_frame.pack(pady=10)

monitor_btn = tk.Button(control_frame, text="▶️ Start Real-time Monitoring", 
                       command=toggle_monitoring, font=("Arial", 12, "bold"),
                       bg="#51cf66", fg="white", padx=20, pady=10)
monitor_btn.pack(side=tk.LEFT, padx=10)

status_label = tk.Label(control_frame, text="⚪ Monitoring Stopped", 
                       font=("Arial", 11, "bold"), fg="gray")
status_label.pack(side=tk.LEFT, padx=20)

# Dashboard display
tk.Label(dashboard_frame, text="🔒 Security Dashboard", font=("Arial", 14, "bold")).pack(pady=10)
dashboard_text = scrolledtext.ScrolledText(dashboard_frame, width=100, height=25, 
                                         wrap=tk.WORD, font=("Courier", 10))
dashboard_text.pack(padx=10, pady=10, fill='both', expand=True)

# Initial dashboard content
dashboard_text.insert(tk.END, """🔴 REAL-TIME SECURITY MONITORING DASHBOARD 🔴

Click "Start Real-time Monitoring" to begin live system surveillance.

This dashboard will show:
📊 CPU and Memory usage
🌐 Network activity
🔍 Suspicious process detection
⚡ High resource usage alerts
🔒 Overall security status

Features:
• Real-time updates every 2 seconds
• Automatic threat detection
• Performance monitoring
• Network connection tracking
• Process anomaly detection
""")

# Exit button
tk.Button(root, text="Exit Application", command=on_closing, 
          bg="#ff4757", fg="white", font=("Arial", 10, "bold")).pack(pady=10)

# Start the GUI
root.mainloop()