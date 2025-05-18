#!/usr/bin/env python3
import os
import hashlib
import socket
import subprocess
import platform

# Predefined trusted processes
trusted_processes = ["System", "explorer.exe", "python.exe","chrome.exe"]  # Add more as needed

# --------- File Check ---------
def compute_file_hash(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None

file_path = "C:\\Users\\hp\\Desktop\\OS-PBL\\modules\\file_ops.py"  
file_hash = compute_file_hash(file_path)
if file_hash:
    print(f"File exists. SHA-256: {file_hash}")
else:
    print(f"File not found: {file_path}")

# --------- Network Check ---------
host = "example.com"
port = 80
try:
    ip = socket.gethostbyname(host)
    socket.create_connection((host, port), timeout=5)
    print(f"Network connection to {host}:{port} ({ip}) is allowed.")
except Exception as e:
    print(f"Network connection to {host}:{port} failed: {e}")

# --------- Process Check ---------
# --------- Process Check ---------
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

# --------- Display Only Trusted Processes ---------
trusted_processes = ["system", "explorer.exe", "python.exe","chrome.exe"]  # Lowercase for comparison

print("\nTrusted running processes:")
for proc in list_processes():
    if proc.lower() in trusted_processes:
        print(proc)

